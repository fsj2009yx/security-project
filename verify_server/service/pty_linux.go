//go:build !windows
// +build !windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/creack/pty"

	"security-project/common/krb"
)

func startPTYSession(term string, cols, rows uint16) (*LocalPTYSession, int32) {
	shell := "/bin/sh"
	if term == "" {
		term = "xterm-256color"
	}
	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(), "TERM="+term)
	ws := &pty.Winsize{Cols: cols, Rows: rows}
	f, err := pty.StartWithSize(cmd, ws)
	if err != nil {
		return nil, krb.ErrSessionNotFound
	}
	return &LocalPTYSession{PTY: f, File: f, Cmd: cmd}, krb.KRBOK
}

func (p *LocalPTYSession) Resize(cols, rows uint16) error {
	if p == nil {
		return fmt.Errorf("pty not started")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.File == nil {
		return fmt.Errorf("pty not started")
	}
	return pty.Setsize(p.File, &pty.Winsize{Cols: cols, Rows: rows})
}

func (p *LocalPTYSession) Signal(sig uint8) error {
	if p == nil {
		return fmt.Errorf("pty process not started")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Cmd == nil || p.Cmd.Process == nil {
		return fmt.Errorf("pty process not started")
	}
	var s syscall.Signal
	switch sig {
	case 1:
		s = syscall.SIGINT
	case 2:
		s = syscall.SIGTERM
	case 3:
		s = syscall.SIGKILL
	default:
		s = syscall.SIGTERM
	}
	return p.Cmd.Process.Signal(s)
}

func (p *LocalPTYSession) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var err error
	if p.PTY != nil {
		err = p.PTY.Close()
		p.PTY = nil
	}
	if p.Cmd != nil && p.Cmd.Process != nil {
		_ = p.Cmd.Process.Kill()
		_, _ = p.Cmd.Process.Wait()
	}
	p.File = nil
	return err
}

func (p *LocalPTYSession) ReadAll(dst chan<- []byte, stop <-chan struct{}) {
	if p == nil || p.PTY == nil {
		close(dst)
		return
	}
	defer close(dst)
	buf := make([]byte, 4096)
	for {
		select {
		case <-stop:
			return
		default:
		}
		n, err := p.PTY.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			select {
			case dst <- chunk:
			case <-stop:
				return
			}
		}
		if err != nil {
			return
		}
	}
}
