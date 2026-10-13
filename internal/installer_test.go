package internal

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/keycard-tech/keycard-go/v4/apdu"
	"github.com/keycard-tech/keycard-go/v4/globalplatform"
)

func TestMathPackageAID(t *testing.T) {
	want := []byte{0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x02}

	if len(MathPackageAID) != len(want) {
		t.Fatalf("MathPackageAID = %x, want %x", MathPackageAID, want)
	}
	for i := range want {
		if MathPackageAID[i] != want[i] {
			t.Fatalf("MathPackageAID = %x, want %x", MathPackageAID, want)
		}
	}

	if got := mathPackageAIDString(); got != "A0000008040002" {
		t.Fatalf("mathPackageAIDString() = %q", got)
	}
}

func TestWithMathHint(t *testing.T) {
	loadErr := apdu.NewErrBadResponse(globalplatform.SwReferencedDataNotFound, "unexpected status word")

	if got := withMathHint(nil, false); got != nil {
		t.Fatalf("withMathHint(nil, false) = %v, want nil", got)
	}

	hinted := withMathHint(loadErr, false)
	if hinted == nil {
		t.Fatal("withMathHint(err, false) = nil, want error with hint")
	}
	if !errors.Is(hinted, loadErr) {
		t.Fatal("hint must wrap the original error")
	}
	for _, want := range []string{"keycard-math-soft", "A0000008040002", "--load-math", "bad response"} {
		if !strings.Contains(hinted.Error(), want) {
			t.Errorf("hint %q must contain %q", hinted.Error(), want)
		}
	}

	// When we loaded the math package ourselves the hint would be misleading.
	if got := withMathHint(loadErr, true); got != loadErr {
		t.Fatalf("withMathHint(err, true) = %v, want the untouched error", got)
	}
}

func TestSwOf(t *testing.T) {
	want := uint16(globalplatform.SwFileNotFound)

	sw, ok := swOf(apdu.NewErrBadResponse(want, "not found"))
	if !ok || sw != want {
		t.Fatalf("swOf() = %#x, %v; want %#x, true", sw, ok, want)
	}

	// The status word must also be found behind wrapping, as used by
	// loadMathPackage/deleteMathPackage.
	sw, ok = swOf(fmt.Errorf("deleting math package: %w", apdu.NewErrBadResponse(want, "not found")))
	if !ok || sw != want {
		t.Fatalf("swOf(wrapped) = %#x, %v; want %#x, true", sw, ok, want)
	}

	if _, ok := swOf(errors.New("no reader found")); ok {
		t.Fatal("swOf() must report false for errors without a status word")
	}
}
