package notify

// smtpEnvelopeError is the SMTP protocol error carrying a formatted envelope
// message. It wraps an inner error for IsPermanent classification.
type smtpEnvelopeError struct {
	msg   string
	inner error
}

func (e *smtpEnvelopeError) Error() string { return e.msg }
func (e *smtpEnvelopeError) Unwrap() error { return e.inner }

// NewSMTPEnvelopeError builds the envelope error from a rendered message and
// an optional inner error.
func NewSMTPEnvelopeError(msg string, inner ...error) *smtpEnvelopeError {
	e := &smtpEnvelopeError{msg: msg}
	if len(inner) > 0 {
		e.inner = inner[0]
	}
	return e
}
