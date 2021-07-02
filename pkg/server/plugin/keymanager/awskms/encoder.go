package awskms

import (
	"encoding/hex"
	"errors"
	"fmt"
)

func newEncoder() *encoder {
	return &encoder{
		allowedCharset: getAllowedAliasCharset(),
		escapeChar:     "_",
	}
}

type encoder struct {
	allowedCharset map[rune]struct{}
	escapeChar     string
}

// encodeKeyID encodes characters not supported by KMS to be used as alias name.
// The encoding is done using the characater asciihex value and "_" as escape
// character.
func (e *encoder) encode(keyID string) string {
	var encodedKeyID string

	for _, r := range keyID {
		_, allowed := e.allowedCharset[r]
		if !allowed {
			encodedKeyID += fmt.Sprintf("%s%02x", e.escapeChar, r)
		} else {
			encodedKeyID += string(r)
		}
	}

	return encodedKeyID
}

// decodeKeyID decodes keys encoded using encodeKeyID.
func (e *encoder) decode(keyID string) (string, error) {
	var decodedKeyID string
	for idx := 0; idx < len(keyID); idx++ {
		if string(keyID[idx]) == e.escapeChar {
			if len(keyID) < idx+3 {
				return "", errors.New("unable to decode: missing values after escape character")
			}

			decodedChar, err := hex.DecodeString(keyID[idx+1 : idx+3])
			if err != nil {
				return "", fmt.Errorf("unable to decode: %w", err)
			}
			decodedKeyID += string(decodedChar)

			// move to the next char
			idx += 2
		} else {
			decodedKeyID += string(keyID[idx])
		}
	}

	return decodedKeyID, nil
}

// getAllowedAliasCharset returns a map with the allowed characters for alias name.
// Allowed pattern is: alias/^[a-zA-Z0-9/_-]+$
func getAllowedAliasCharset() map[rune]struct{} {
	allowedKMSChars := make(map[rune]struct{})

	for v := '0'; v <= '9'; v++ {
		allowedKMSChars[v] = struct{}{}
	}

	for v := 'A'; v <= 'Z'; v++ {
		allowedKMSChars[v] = struct{}{}
	}

	for v := 'a'; v <= 'z'; v++ {
		allowedKMSChars[v] = struct{}{}
	}

	allowedKMSChars['/'] = struct{}{}
	allowedKMSChars['_'] = struct{}{}
	allowedKMSChars['-'] = struct{}{}

	return allowedKMSChars
}
