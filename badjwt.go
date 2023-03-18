// Package badjwt is a deliberately flawed JWT implementation.
//
// Do not copy this code. It is insecure.
package badjwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Header identifies the algorithm used to generate the signature.
const Header = `{"alg": "HS256", "typ": "JWT"}`

// A Payload is a set of claims.
type Payload map[string]any

// Sign signs a payload with the given HS256 key.
func Sign(p Payload, key []byte) (string, error) {
	if len(key) < 32 {
		return "", fmt.Errorf("key is too short") // RFC 7518, 3.2
	}

	jp, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("failed to encode payload: %w", err)
	}

	msg := fmt.Sprintf(
		"%s.%s",
		base64.RawURLEncoding.EncodeToString([]byte(Header)),
		base64.RawURLEncoding.EncodeToString(jp),
	)

	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	sig := h.Sum(nil)

	return fmt.Sprintf("%s.%s", msg, base64.RawURLEncoding.EncodeToString(sig)), nil
}

// Verify verifies a token using the given HS256 key.
func Verify(token string, key []byte) (Payload, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("key is too short") // RFC 7518, 3.2
	}

	fields := strings.Split(token, ".")
	if n := len(fields); n != 3 {
		return nil, fmt.Errorf("wrong number of fields")
	}

	sig, err := base64.RawURLEncoding.DecodeString(fields[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	h := hmac.New(sha256.New, key)
	h.Write([]byte(fmt.Sprintf("%s.%s", fields[0], fields[1])))

	if !hmac.Equal(sig, h.Sum(nil)) {
		return nil, fmt.Errorf("incorrect key")
	}

	jp, err := base64.RawURLEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var p Payload
	if err := json.Unmarshal(jp, &p); err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	return p, nil
}
