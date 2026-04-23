//go:build windows

package service

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"

	"security-project/common/krb"
)

func startPTYSession(term string, cols, rows uint16) (*LocalPTYSession, int32) {
	cmd := exec.Command("cmd.exe")
	cmd.Env = append(os.Environ(), "TERM="+term)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, krb.ErrSessionNotFound
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, krb.ErrSessionNotFound
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, krb.ErrSessionNotFound
	}
	_ = stdin
	_ = stderr
	if err := cmd.Start(); err != nil {
		return nil, krb.ErrSessionNotFound
	}
	return &LocalPTYSession{PTY: &windowsPTY{r: stdout, w: stdin}, Cmd: cmd}, krb.KRBOK
}

type windowsPTY struct {
	r io.ReadCloser
	w io.WriteCloser
}

func (p *windowsPTY) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *windowsPTY) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *windowsPTY) Close() error {
	_ = p.w.Close()
	return p.r.Close()
}

func (p *LocalPTYSession) Resize(cols, rows uint16) error {
	return fmt.Errorf("resize unsupported on windows fallback")
}

func (p *LocalPTYSession) Signal(sig uint8) error {
	if p == nil || p.Cmd == nil || p.Cmd.Process == nil {
		return fmt.Errorf("pty process not started")
	}
	var s syscall.Signal
	switch sig {
	case 1:
		s = syscall.CTRL_C_EVENT
	case 2:
		s = syscall.CTRL_BREAK_EVENT
	case 3:
		s = syscall.Signal(1)
	default:
		s = syscall.CTRL_BREAK_EVENT
	}
	return p.Cmd.Process.Signal(s)
}

func (p *LocalPTYSession) Close() error {
	if p == nil {
		return nil
	}
	if p.PTY != nil {
		_ = p.PTY.Close()
	}
	if p.Cmd != nil && p.Cmd.Process != nil {
		_ = p.Cmd.Process.Kill()
		_, _ = p.Cmd.Process.Wait()
	}
	return nil
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
