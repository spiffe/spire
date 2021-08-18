package peertracker

import "errors"

var (
	ErrInvalidConnection    = errors.New("invalid connection")
	ErrorNoLongerWatched    = errors.New("caller is no longer being watched")
	ErrUnsupportedPlatform  = errors.New("unsupported platform")
	ErrUnsupportedTransport = errors.New("unsupported transport")
)
