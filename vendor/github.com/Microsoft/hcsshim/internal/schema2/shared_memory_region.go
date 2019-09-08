/*
 * HCS API
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: 2.1
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package hcsschema

type SharedMemoryRegion struct {

	SectionName string `json:"SectionName,omitempty"`

	StartOffset int32 `json:"StartOffset,omitempty"`

	Length int32 `json:"Length,omitempty"`

	AllowGuestWrite bool `json:"AllowGuestWrite,omitempty"`

	HiddenFromGuest bool `json:"HiddenFromGuest,omitempty"`
}
