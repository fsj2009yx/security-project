package service

import (
	"context"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

type LocalPTYSession struct {
	PTY  io.ReadWriteCloser
	File *os.File
	Cmd  *exec.Cmd
	mu   sync.Mutex
}

type SessionContext struct {
	IDClient     string
	ADc          uint32
	KeyCV        [8]byte
	ExpireAt     uint32
	PtySessionID uint32
	LastIO       time.Time
	TotalFrames  uint64
	PTY          *LocalPTYSession
	Ctx          context.Context
	Cancel       context.CancelFunc
	Closed       bool
}

type VState struct {
	SeqNum   uint32
	IDV      string
	Kv       [8]byte
	Sessions map[string]*SessionContext
	mu       sync.RWMutex
}
