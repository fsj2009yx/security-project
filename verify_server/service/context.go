package service

import (
	"io"
)

type LocalPTYSession struct {
	PTY io.ReadWriteCloser
}

type SessionContext struct {
	IDClient string
	ADc      uint32
	KeyCV    [8]byte
	ExpireAt uint32
}

type VState struct {
	SeqNum   uint32
	IDV      string
	Kv       [8]byte
	Sessions map[string]SessionContext
}
