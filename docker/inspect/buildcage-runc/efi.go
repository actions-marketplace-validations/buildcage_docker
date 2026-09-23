package main

// An EFI signature database is what p11-kit's edk2-cacerts extract writes, and
// so what RHEL's update-ca-trust leaves at
// /etc/pki/ca-trust/extracted/edk2/cacerts.bin for firmware to load. A rebuild
// copies the certificate in there as a bare DER, which no PEM removal reaches.
//
// The file is EFI_SIGNATURE_LISTs back to back, little-endian, with nothing
// around them (UEFI specification, "Signature Database"):
//
//	list: type(16, a GUID) | list size(4) | header size(4) | signature size(4)
//	      header(header size) | signature(signature size)*
//	signature: owner(16, a GUID) | data
//
// A list holds signatures of one type and one size. p11-kit writes each
// certificate as a list of its own, but the format lets one list carry several
// certificates of the same length, so the certificate is cut out as the one
// signature that is it rather than as a whole list. Nothing spans the file:
// there is no count to update and no digest to reseal, and every byte that
// stays is copied over as it was.

import (
	"bytes"
	"encoding/binary"
	"slices"
)

// EFI_CERT_X509_GUID, a5c059a1-94e4-4aa7-87b5-ab155c2bf072, laid out the way a
// GUID is stored: its first three fields little-endian.
var efiCertX509 = []byte{0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72}

const (
	efiListHeaderSize = 16 + 4 + 4 + 4
	efiOwnerSize      = 16
)

// signatureListsWithout returns content with every signature that is the
// certificate taken out, and reports whether it removed anything. A list the
// removal leaves with no signatures goes as a whole.
//
// Only an X.509 signature whose data is the certificate byte for byte is cut.
// A copy anywhere else, and content that does not parse as signature lists to
// its last byte, is left for the caller to report: the file carries no magic,
// so the parse is what says it is a signature database at all.
func signatureListsWithout(content []byte, ders [][]byte) ([]byte, bool) {
	out := make([]byte, 0, len(content))
	removed := false
	for rest := content; len(rest) > 0; {
		if len(rest) < efiListHeaderSize {
			return nil, false
		}
		// Widened so that no size a corrupt file gives can wrap the checks.
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
