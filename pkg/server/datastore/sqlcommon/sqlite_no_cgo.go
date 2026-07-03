//go:build !cgo

package sqlcommon

func IsSQLiteConstraintViolation(err error) bool {
	return false
}
