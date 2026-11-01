package cfn

import "errors"

// UnauthorizedError is a hook's refusal because the caller may not do that step: the front door that
// set the hook checked the caller first (an in-cluster front door's custom-resource Invoke and REST v1
// hooks act with its own authority, so it checks the caller before each one). Teardown treats it as a
// failure — the resource stays and the stack is DELETE_FAILED — never as the best-effort skip a failing
// Function or API delete gets, so a delete the caller is not allowed never reports DELETE_COMPLETE.
type UnauthorizedError struct{ Reason string }

func (e *UnauthorizedError) Error() string { return e.Reason }

// Unauthorized returns an UnauthorizedError with the given reason.
func Unauthorized(reason string) error { return &UnauthorizedError{Reason: reason} }

// IsUnauthorized reports whether err is (or wraps) an UnauthorizedError.
func IsUnauthorized(err error) bool {
	var ue *UnauthorizedError
	return errors.As(err, &ue)
}
