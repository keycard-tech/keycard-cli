package internal

import (
	"encoding/hex"
	"strings"
)

// ParseHex strips 0x/0X prefix and decodes a hex string.
func ParseHex(s string) ([]byte, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	return hex.DecodeString(s)
}
