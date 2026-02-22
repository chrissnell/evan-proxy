package auth

import "errors"

var (
	ErrUnknownUser   = errors.New("unknown user")
	ErrWrongPassword = errors.New("wrong password")
)
