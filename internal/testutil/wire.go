// Package testutil provides checked numeric encoding for local wire fixtures.
// It is imported only by tests, not by the runtime transport.
package testutil

// Uint16 converts a fixture length or port without silent truncation.
// Unsupported fixture values fail immediately instead of producing bad bytes.
func Uint16(value int) uint16 {
	if value < 0 || value > 65535 {
		panic("wire fixture value exceeds uint16")
	}
	return uint16(value)
}

// Uint8 converts a fixture length without silent truncation.
// Unsupported fixture values fail immediately instead of producing bad bytes.
func Uint8(value int) uint8 {
	if value < 0 || value > 255 {
		panic("wire fixture value exceeds uint8")
	}
	return uint8(value)
}
