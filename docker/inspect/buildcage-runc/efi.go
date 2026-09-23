package main

// RHEL's update-ca-trust writes an EFI signature database for firmware to
// /etc/pki/ca-trust/extracted/edk2/cacerts.bin, where the certificate lands as
// a bare DER. The file is EFI_SIGNATURE_LISTs back to back, little-endian (UEFI
// specification, "Signature Database"):
//
//	list: type(16, GUID) | list size(4) | header size(4) | signature size(4)
//	      header(header size) | signature(signature size)*
//	signature: owner(16, GUID) | data
//
// p11-kit writes one certificate per list, but a list may hold several of the
// same length, so the certificate is cut as a single signature. Nothing spans
// the file, so there is no count or digest to update.

import (
	"bytes"
	"encoding/binary"
	"slices"
)

// EFI_CERT_X509_GUID (a5c059a1-94e4-4aa7-87b5-ab155c2bf072) in its stored byte
// order: the first three fields are little-endian.
var efiCertX509 = []byte{0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72}

const (
	efiListHeaderSize = 16 + 4 + 4 + 4
	efiOwnerSize      = 16
)

// signatureListsWithout drops every X.509 signature whose data is exactly one
// of ders, and any list left empty by that, and reports whether it dropped any.
// The file has no magic, so content that does not parse as signature lists to
// its last byte is not touched and is left for the caller to report.
func signatureListsWithout(content []byte, ders [][]byte) ([]byte, bool) {
	out := make([]byte, 0, len(content))
	removed := false
	for rest := content; len(rest) > 0; {
		if len(rest) < efiListHeaderSize {
			return nil, false
		}
		// uint64 so that a corrupt size cannot wrap the checks.
		listSize := uint64(binary.LittleEndian.Uint32(rest[16:]))
		headerSize := uint64(binary.LittleEndian.Uint32(rest[20:]))
		signatureSize := uint64(binary.LittleEndian.Uint32(rest[24:]))
		start := efiListHeaderSize + headerSize
		if listSize > uint64(len(rest)) || listSize < start || signatureSize < efiOwnerSize ||
			(listSize-start)%signatureSize != 0 {
			return nil, false
		}
		list := rest[:listSize]
		rest = rest[listSize:]

		x509 := bytes.Equal(list[:16], efiCertX509)
		kept := slices.Clone(list[:start])
		cut := false
		for at := start; at < listSize; at += signatureSize {
			signature := list[at : at+signatureSize]
			if x509 && slices.ContainsFunc(ders, func(der []byte) bool { return bytes.Equal(signature[efiOwnerSize:], der) }) {
				cut = true
				continue
			}
			kept = append(kept, signature...)
		}
		if !cut {
			out = append(out, list...)
			continue
		}
		removed = true
		if uint64(len(kept)) == start {
			continue
		}
		binary.LittleEndian.PutUint32(kept[16:], uint32(len(kept)))
		out = append(out, kept...)
	}
	return out, removed
}
