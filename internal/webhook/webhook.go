// Package webhook verifies signed payment notifications. The provider signs each
// request with a shared secret, which this service reads from goraz.
//
// The header looks like: Payment-Signature: t=1731500000,v1=<hex HMAC-SHA256>
// where the MAC covers "<t>." followed by the raw body. A timestamp limits replays.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Tolerance is how far a signature's timestamp may be from now.
const Tolerance = 5 * time.Minute

// ErrBadSignature is returned for any signature that doesn't verify.
var ErrBadSignature = errors.New("webhook: invalid signature")

// Sign returns a header value for body, as the provider would compute it.
func Sign(secret, body []byte, at time.Time) string {
	ts := strconv.FormatInt(at.Unix(), 10)
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac(secret, ts, body))
}

func mac(secret []byte, ts string, body []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(ts))
	m.Write([]byte("."))
	m.Write(body)
	return m.Sum(nil)
}

// Verify checks header against body. Secrets are accepted as a list, so a rotation
// can keep the previous secret valid until the provider switches.
func Verify(header string, body []byte, now time.Time, secrets ...[]byte) error {
	var ts string
	var sigs [][]byte
	for part := range strings.SplitSeq(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return ErrBadSignature
		}
		switch k {
		case "t":
			ts = v
		case "v1":
			b, err := hex.DecodeString(v)
			if err != nil || len(b) != sha256.Size {
				return ErrBadSignature
			}
			sigs = append(sigs, b)
		}
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || len(sigs) == 0 {
		return ErrBadSignature
	}
	if d := now.Sub(time.Unix(sec, 0)); d > Tolerance || d < -Tolerance {
		return ErrBadSignature
	}
	for _, s := range secrets {
		if len(s) == 0 {
			continue
		}
		want := mac(s, ts, body)
		for _, got := range sigs {
			if hmac.Equal(got, want) {
				return nil
			}
		}
	}
	return ErrBadSignature
}
