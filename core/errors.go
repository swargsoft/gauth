// Package core provides the gauth engine implementation.
// This file defines error types and error handling utilities.
//
// ERROR CODE CONTRACT (STABLE - DO NOT CHANGE EXISTING CODES):
// These error codes are part of the public API contract. The msgly
// frontend depends on these exact strings for error handling. Adding
// new codes is allowed; changing existing codes is NOT.
package core

import "fmt"

type ErrorCode string

const (
	ErrCodeBadRequest     ErrorCode = "ERR_BAD_REQUEST"
	ErrCodeInvalidAPIKey  ErrorCode = "ERR_INVALID_API_KEY"
	ErrCodeInvalidState   ErrorCode = "ERR_INVALID_STATE"
	ErrCodeStateExpired   ErrorCode = "ERR_STATE_EXPIRED"
	ErrCodeStateReplayed  ErrorCode = "ERR_STATE_REPLAYED"
	ErrCodeTokenExchange  ErrorCode = "ERR_TOKEN_EXCHANGE_FAILED"
	ErrCodeNoRefreshToken ErrorCode = "ERR_NO_REFRESH_TOKEN"
	ErrCodeReauthRequired ErrorCode = "ERR_GOOGLE_AUTH_REQUIRED"
	ErrCodeNotFound       ErrorCode = "ERR_NOT_FOUND"
	ErrCodeRateLimited    ErrorCode = "ERR_RATE_LIMITED"
	ErrCodeInternal       ErrorCode = "ERR_INTERNAL"
)

// Error is gauth's operational error type. HTTPStatus determines the
// response code; Code is a stable machine-readable string.
type Error struct {
	Code        ErrorCode `json:"code"`
	Message     string    `json:"message"`
	HTTPStatus  int       `json:"-"`
	NeedsReauth bool      `json:"needsReauth,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func NewError(code ErrorCode, status int, message string) *Error {
	return &Error{Code: code, Message: message, HTTPStatus: status}
}

// ReauthRequired marks an error as needing the frontend to send the
// user back through the connect flow (auth-url) — the controller layer
// renders this as { message, needsReauth: true } instead of the usual
// { error: { code, message } } shape, matching the original API
// contract.
func ReauthRequired(message string) *Error {
	return &Error{Code: ErrCodeReauthRequired, Message: message, HTTPStatus: 401, NeedsReauth: true}
}
