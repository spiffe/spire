package peertracker

import "errors"

var (
	ErrInvalidConnection    = errors.New("invalid connection")
	ErrNoLongerWatched      = errors.New("caller is no longer being watched")
	ErrUnsupportedPlatform  = errors.New("unsupported platform")
	ErrUnsupportedTransport = errors.New("unsupported transport")
)
