package badjwt

import (
	"bytes"
	"encoding/json"
	"testing"

	"golang.org/x/exp/maps"
)

var (
	testPayload = Payload{"sub": "1234567890", "name": "John Doe", "admin": true}
	testToken   = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoiMTIzNDU2Nzg5MCJ9.FWmP5uoxCW1-CNAIhe8ZooVcg7YeyEGBFAZFlf5MIhc"
	testKey     = []byte("my secret key that nobody knows!")
)

func TestSign(t *testing.T) {
	got, err := Sign(testPayload, testKey)
	if err != nil {
		t.Errorf("Sign() error: %v", err)
	}
	if got != testToken {
		t.Errorf("Sign(): got %s, want %s", got, testToken)
	}
}

func TestVerify(t *testing.T) {
	got, err := Verify(testToken, testKey)
	if err != nil {
		t.Errorf("Verify() error: %v", err)
	}
	if !maps.Equal(got, testPayload) {
		t.Errorf("Verify(): got %#v, want %#v", got, testPayload)
	}
}

func FuzzVerifyWithWrongKey(f *testing.F) {
	f.Fuzz(func(t *testing.T, j, k1, k2 []byte) {
		if bytes.Equal(k1, k2) {
			t.Skip()
		}

		var p Payload
		if err := json.Unmarshal(j, &p); err != nil {
			t.Skip()
		}

		t1, err := Sign(p, k1)
		if err != nil {
			t.Skip()
		}

		_, err = Verify(t1, k2)
		if err == nil {
			t.Errorf("token signed with k1 verifies with k2 != k1")
		}
	})
}
