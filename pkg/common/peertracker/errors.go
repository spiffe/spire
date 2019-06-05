package peertracker

import "errors"

var (
	ErrInvalidConnection    = errors.New("invalid connection")
	ErrUnsupportedPlatform  = errors.New("unsupported platform")
	ErrUnsupportedTransport = errors.New("unsupported transport")
)
