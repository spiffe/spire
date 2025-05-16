package util

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// GetSHA256Digest calculates the sha256 digest of a file specified by path. If the size of the file exceeds the provided
// limit, the hash will not be calculated and an error will be returned instead.
func GetSHA256Digest(path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("SHA256 digest: %w", err)
	}
	defer f.Close()

	if limit > 0 {
		fi, err := f.Stat()
		if err != nil {
			return "", fmt.Errorf("SHA256 digest: %w", err)
		}
		if fi.Size() > limit {
			return "", fmt.Errorf("SHA256 digest: workload %s exceeds size limit (%d > %d)", path, fi.Size(), limit)
		}
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("SHA256 digest: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
