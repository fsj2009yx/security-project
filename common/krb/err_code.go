package krb

import (
	"errors"
	"fmt"
)

// Status codes for Kerberos operations
const (
	KRBOK                 int32 = 0
	ErrMagicMismatch      int32 = -1001
	ErrVersionUnsupported int32 = -1002
	ErrMsgTypeInvalid     int32 = -1003
	ErrPayloadTooLarge    int32 = -1004
	ErrReplayTimestamp    int32 = -1005
	ErrReplaySeq          int32 = -1006
	ErrBufTooSmall        int32 = -1007
	ErrSocketSend         int32 = -1008
	ErrSocketRecv         int32 = -1009
	ErrClientNotFound     int32 = -2001
	ErrTicketExpired      int32 = -2002
	ErrTicketInvalid      int32 = -2003
	ErrAuthMismatch       int32 = -2004
	ErrADMismatch         int32 = -2005
	ErrKeyDerive          int32 = -2006
	ErrSessionNotFound    int32 = -2007
	ErrDESKeyLen          int32 = -3001
	ErrDESPadding         int32 = -3002
	ErrDESDecryptFail     int32 = -3003
	ErrRSAKeyInvalid      int32 = -3004
	ErrRSASignFail        int32 = -3005
	ErrRSAVerifyFail      int32 = -3006
	ErrSHA256Fail         int32 = -3008
	ErrCertExpired        int32 = -4001
	ErrCertSigInvalid     int32 = -4002
	ErrCertIDMismatch     int32 = -4003
	ErrCertLoadFail       int32 = -4004
)

type codeError struct {
	code int32
}

func (e codeError) Error() string {
	return fmt.Sprintf("krb code %d", e.code)
}

func errorFromCode(code int32) error {
	if code == KRBOK {
		return nil
	}
	return codeError{code: code}
}

func ErrorFromCode(code int32) error {
	return errorFromCode(code)
}

func CodeFromError(err error) int32 {
	if err == nil {
		return KRBOK
	}
	if ce, ok := errors.AsType[codeError](err); ok {
		return ce.code
	}
	return ErrTicketInvalid
}
