package krb

import "encoding/binary"

// Cursor 是一个简单的结构体，用于在字节切片中进行顺序读取。
// 它包含一个字节切片 data 和一个整数 off，表示当前读取位置的偏移量。
type Cursor struct {
	data []byte
	off  int
}

func NewCursor(data []byte) *Cursor {
	return &Cursor{data: data}
}

func (c *Cursor) Remaining() int {
	if c == nil {
		return 0
	}
	return len(c.data) - c.off
}

// ReadBytes 从 Cursor 中读取 n 个字节，并返回一个新的字节切片。它会更新 Cursor 的偏移量 off。
func (c *Cursor) ReadBytes(n int) ([]byte, error) {
	if c == nil || n < 0 || c.off+n > len(c.data) {
		return nil, errorFromCode(ErrTicketInvalid)
	}
	out := append([]byte(nil), c.data[c.off:c.off+n]...)
	c.off += n
	return out, nil
}

func (c *Cursor) ReadUint16() (uint16, error) {
	b, err := c.ReadBytes(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (c *Cursor) ReadUint32() (uint32, error) {
	b, err := c.ReadBytes(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func (c *Cursor) ReadKString() (KString, error) {
	ln, err := c.ReadUint16()
	if err != nil {
		return KString{}, err
	}
	b, err := c.ReadBytes(int(ln))
	if err != nil {
		return KString{}, err
	}
	return KString{Len: ln, Data: b}, nil
}
