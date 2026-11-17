package internal

import (
	"bytes"
	"strings"
	"testing"

	"github.com/keycard-tech/keycard-go/v4/globalplatform"
)

func TestGPKeyOptionsWithoutKey(t *testing.T) {
	options, err := GPKeyOptions("")
	if err != nil {
		t.Fatalf("GPKeyOptions(\"\") returned %v", err)
	}

	if options != nil {
		t.Fatalf("GPKeyOptions(\"\") = %d options, want none", len(options))
	}
}

func TestGPKeyOptionsHex(t *testing.T) {
	options, err := GPKeyOptions("0xc212e073ff8b4bbfaff4de8ab655221f")
	if err != nil {
		t.Fatalf("GPKeyOptions returned %v", err)
	}

	if len(options) != 1 {
		t.Fatalf("GPKeyOptions returned %d options, want 1", len(options))
	}

	if _, err := GPKeyOptions("zz"); err == nil || !strings.Contains(err.Error(), "gp-mac-key") {
		t.Fatalf("GPKeyOptions with invalid hex returned %v, want an error naming the flag", err)
	}
}

func TestGPKeySetsOrder(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 16)

	keySets, err := gpKeySets(key)
	if err != nil {
		t.Fatalf("gpKeySets returned %v", err)
	}

	if len(keySets) != 2 {
		t.Fatalf("gpKeySets returned %d key sets, want 2", len(keySets))
	}

	if keySets[0].Protocol() != globalplatform.SCPVersion03 {
		t.Fatalf("first key set is SCP%02d, want SCP03", keySets[0].Protocol())
	}

	if keySets[1].Protocol() != globalplatform.SCPVersion02 {
		t.Fatalf("second key set is SCP%02d, want SCP02", keySets[1].Protocol())
	}

	for _, keySet := range keySets {
		if keySet.Version() != 0 {
			t.Fatalf("key set version = %d, want 0", keySet.Version())
		}
		if !bytes.Equal(keySet.Enc(), key) || !bytes.Equal(keySet.Mac(), key) {
			t.Fatalf("key set holds enc=%x mac=%x, want both %x", keySet.Enc(), keySet.Mac(), key)
		}
		if keySet.Dek() != nil {
			t.Fatalf("key set dek = %x, want none", keySet.Dek())
		}
	}
}

func TestGPKeySetsAES256(t *testing.T) {
	keySets, err := gpKeySets(bytes.Repeat([]byte{0x01}, 32))
	if err != nil {
		t.Fatalf("gpKeySets returned %v", err)
	}

	if len(keySets) != 1 || keySets[0].Protocol() != globalplatform.SCPVersion03 {
		t.Fatalf("gpKeySets returned %d key sets, want only SCP03", len(keySets))
	}
}

func TestGPKeySetsUnusableKey(t *testing.T) {
	if _, err := gpKeySets(bytes.Repeat([]byte{0x01}, 8)); err == nil {
		t.Fatal("gpKeySets accepted an 8 byte key")
	} else if !strings.Contains(err.Error(), "scp02") || !strings.Contains(err.Error(), "scp03") {
		t.Fatalf("gpKeySets error %q does not report both protocols", err)
	}
}
