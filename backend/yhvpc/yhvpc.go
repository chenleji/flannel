// Copyright 2015 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// +build !windows

package yhvpc

import (
	"encoding/json"
	"fmt"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
	"net"
	"sync"
	"syscall"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
)

const (
	BackendType       = "yh-vpc"
	defaultBridgeName = "cni0"
)

func init() {
	backend.Register(BackendType, New)
}

type YhVpcBackend struct {
	subnetMgr subnet.Manager
	extIface  *backend.ExternalInterface
}

func New(sm subnet.Manager, extIface *backend.ExternalInterface) (backend.Backend, error) {
	backend := &YhVpcBackend{
		subnetMgr: sm,
		extIface:  extIface,
	}

	return backend, nil
}

func newSubnetAttrs(publicIP net.IP, iface string, mac net.HardwareAddr) (*subnet.LeaseAttrs, error) {
	data, err := json.Marshal(&phyIfLeaseAttrs{iface, hardwareAddr(mac)})
	if err != nil {
		return nil, err
	}

	return &subnet.LeaseAttrs{
		PublicIP:    ip.FromIP(publicIP),
		BackendType: BackendType,
		BackendData: json.RawMessage(data),
	}, nil
}

func (be *YhVpcBackend) RegisterNetwork(ctx context.Context, wg sync.WaitGroup, config *subnet.Config) (backend.Network, error) {
	subnetAttrs, err := newSubnetAttrs(be.extIface.ExtAddr, be.extIface.Iface.Name, be.extIface.Iface.HardwareAddr)
	if err != nil {
		return nil, err
	}

	lease, err := be.subnetMgr.AcquireLease(ctx, subnetAttrs)
	switch err {
	case nil:
	case context.Canceled, context.DeadlineExceeded:
		return nil, err
	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)
	}

	// create bridge cni0 if necessary
	br, err := ensureBridge(defaultBridgeName, be.extIface.Iface.MTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create bridge %q: %v", defaultBridgeName, err)
	}

	// add physical Interface into CNI bridge
	err = addExtIface2Bridge(br, be.extIface.Iface.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to add physical interface(%s) to CNI bridge. %v", be.extIface.Iface.Name, err)
	}

	return newNetwork(be.subnetMgr, be.extIface, ip.IP4Net{}, lease)
}

// So we can make it JSON (un)marshalable
type hardwareAddr net.HardwareAddr

func (hw hardwareAddr) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", net.HardwareAddr(hw))), nil
}

func (hw *hardwareAddr) UnmarshalJSON(bytes []byte) error {
	if len(bytes) < 2 || bytes[0] != '"' || bytes[len(bytes)-1] != '"' {
		return fmt.Errorf("error parsing hardware addr")
	}

	bytes = bytes[1 : len(bytes)-1]

	mac, err := net.ParseMAC(string(bytes))
	if err != nil {
		return err
	}

	*hw = hardwareAddr(mac)
	return nil
}

func ensureBridge(brName string, mtu int) (*netlink.Bridge, error) {
	br := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name: brName,
			MTU:  mtu,
			// Let kernel use default txqueuelen; leaving it unset
			// means 0, and a zero-length TX queue messes up FIFO
			// traffic shapers which use TX queue length as the
			// default packet limit
			TxQLen: -1,
		},
	}

	if mtu == 0 {
	}

	if err := netlink.LinkAdd(br); err != nil {
		if err != syscall.EEXIST {
			return nil, fmt.Errorf("could not add %q: %v", brName, err)
		}

		// it's ok if the device already exists as long as config is similar
		br, err = bridgeByName(brName)
		if err != nil {
			return nil, err
		}
	}

	if err := netlink.LinkSetUp(br); err != nil {
		return nil, err
	}

	return br, nil
}

func bridgeByName(name string) (*netlink.Bridge, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("could not lookup %q: %v", name, err)
	}
	br, ok := l.(*netlink.Bridge)
	if !ok {
		return nil, fmt.Errorf("%q already exists but is not a bridge", name)
	}
	return br, nil
}

func setBridgeIP(br *netlink.Bridge, ip4Net *ip.IP4Net) (string, error) {
	link, err := netlink.LinkByName(br.Name)
	if err != nil {
		return "", fmt.Errorf("failed to lookup %q: %v", br.Name, err)
	}

	addrs, err := netlink.AddrList(link, syscall.AF_INET)
	if err != nil && err != syscall.ENOENT {
		return "", fmt.Errorf("could not get list of IP addresses: %v", err)
	}
	if len(addrs) > 0 {
		bridgeIPStr := ip4Net.String()
		for _, a := range addrs {
			if a.IPNet.String() == bridgeIPStr {
				// Bridge IP already set, nothing to do
				return bridgeIPStr, nil
			}
		}
	}

	addr := &netlink.Addr{IPNet: ip4Net.ToIPNet(), Label: ""}
	if err = netlink.AddrAdd(link, addr); err != nil {
		return "", fmt.Errorf("failed to add IP addr to %q: %v", br.Name, err)
	}

	return ip4Net.String(), nil
}

func addExtIface2Bridge(br *netlink.Bridge, ifName string) error {
	// check interface was attached to CNI bridge
	intf, err := netlink.LinkByName(ifName)
	if intf.Attrs().MasterIndex == br.Attrs().Index {
		return nil
	}

	// add interface to the CNI bridge
	if err = netlink.LinkSetMaster(intf, br); err != nil {
		return fmt.Errorf("failed to connect %q to bridge %v: %v", ifName, br.Attrs().Name, err)
	}

	// set links Promisc on
	if err = netlink.SetPromiscOn(intf); err != nil {
		return fmt.Errorf("failed to set promisc on interface:%s", ifName)
	}

	// set up links physical interface
	if err = netlink.LinkSetUp(intf); err != nil {
		return fmt.Errorf("failed to set %q up: %v", ifName, err)
	}

	return nil
}
