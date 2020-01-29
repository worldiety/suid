package suid

import (
	"fmt"
	"testing"
)

func TestParse(t *testing.T) {
	suid := New()
	fmt.Println(suid.String(), "=>", len(suid.String()))
	fmt.Println(suid.HexString(), "=>", len(suid.HexString()))

	if Must(Parse(suid.String())) != suid {
		t.Fatalf("cannot parse string")
	}

	if Must(Parse(suid.HexString())) != suid {
		t.Fatalf("cannot parse string")
	}

	if Must(Parse(string(suid[:]))) != suid {
		t.Fatalf("cannot parse string")
	}
}
