//go:build !windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/creack/pty"
)

func startPTYSession(term string, cols, rows uint16) (*LocalPTYSession, error) {
	shell := "/bin/sh"
	if term == "" {
		term = "xterm-256color"
	}
	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(), "TERM="+term)
	ws := &pty.Winsize{Cols: cols, Rows: rows}
	f, err := pty.StartWithSize(cmd, ws)
	if err != nil {
		return nil, err
	}
	return &LocalPTYSession{PTY: f, File: f, Cmd: cmd}, nil
}

// Resize 用来调整PTY窗口大小的函数。它接受列数和行数作为参数，
// 并使用pty库的Setsize函数来设置PTY的窗口大小。如果PTY会话尚未启动或文件句柄无效，它将返回一个错误。
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

// Signal 用于向PTY会话发送信号的函数。它接受一个uint8类型的sig参数，表示要发送的信号类型。
// 根据sig的值，它将转换为相应的syscall.Signal类型，并使用Cmd.Process.Signal方法将信号发送到PTY会话的进程。
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

// Close 用于关闭PTY会话的函数。它首先检查PTY会话是否存在，如果不存在则直接返回nil。
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

// ReadAll 用于从PTY会话中读取数据的函数。它接受一个chan<- []byte类型的dst参数，用于将读取到的数据发送到外部，
// 以及一个<-chan struct{}类型的stop参数，用于接收停止信号。
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
