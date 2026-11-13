package webhook

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestVerify(t *testing.T) {
	secret := []byte("whsec")
	body := []byte(`{"order_id":7}`)
	now := time.Unix(1_731_500_000, 0)
	good := Sign(secret, body, now)

	cases := []struct {
		name    string
		header  string
		body    []byte
		at      time.Time
		secrets [][]byte
		ok      bool
	}{
		{"valid", good, body, now, [][]byte{secret}, true},
		{"previous secret still accepted", good, body, now, [][]byte{[]byte("new"), secret}, true},
		{"changed body", good, []byte(`{"order_id":8}`), now, [][]byte{secret}, false},
		{"wrong secret", good, body, now, [][]byte{[]byte("other")}, false},
		{"too old", good, body, now.Add(Tolerance + time.Second), [][]byte{secret}, false},
		{"from the future", good, body, now.Add(-Tolerance - time.Second), [][]byte{secret}, false},
		{"empty header", "", body, now, [][]byte{secret}, false},
		{"no signature", "t=1731500000", body, now, [][]byte{secret}, false},
		{"short signature", "t=1731500000,v1=abcd", body, now, [][]byte{secret}, false},
		{"empty secret", good, body, now, [][]byte{nil}, false},
		{"swapped timestamp", strings.Replace(good, "t=1731500000", "t=1731500001", 1), body, now, [][]byte{secret}, false},
	}
	for _, c := range cases {
		err := Verify(c.header, c.body, c.at, c.secrets...)
		if c.ok != (err == nil) {
			t.Errorf("%s: err = %v", c.name, err)
		}
		if err != nil && !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: unexpected error type %v", c.name, err)
		}
	}
}

func FuzzVerify(f *testing.F) {
	secret := []byte("whsec")
	now := time.Unix(1_731_500_000, 0)
	f.Add(Sign(secret, []byte("{}"), now), []byte("{}"))
	f.Add("t=,v1=", []byte{})
	f.Fuzz(func(t *testing.T, header string, body []byte) {
		if Verify(header, body, now, secret) == nil && header != Sign(secret, body, now) {
			// Equivalent headers, such as extra fields, may verify, but only with a
			// correct MAC over this body.
			if !strings.Contains(header, Sign(secret, body, now)[len("t=1731500000,"):]) {
				t.Fatalf("forged header accepted: %q", header)
			}
		}
	})
}
