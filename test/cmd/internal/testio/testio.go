package testio

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"security-project/common/krb"
	"strings"
)

func ReadJSON(dst any) (bool, error) {
	if StdinIsTerminal() {
		return false, nil
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return false, err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return false, nil
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return false, err
	}
	return true, nil
}

func StdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func PromptLine(reader *bufio.Reader, prompt string) (string, error) {
	fmt.Print(prompt)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func WriteJSON(v any) error {
	enc, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(enc, '\n'))
	return err
}

func Failf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func HexToBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	s = strings.Join(strings.Fields(s), "")
	if s == "" {
		return nil, nil
	}
	return hex.DecodeString(s)
}

func BytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}

func Key8FromHex(s string) ([8]byte, error) {
	var key [8]byte
	raw, err := HexToBytes(s)
	if err != nil {
		return key, err
	}
	if len(raw) != 8 {
		return key, fmt.Errorf("expected 8 bytes, got %d", len(raw))
	}
	copy(key[:], raw)
	return key, nil
}

func Key8ToHex(key [8]byte) string {
	return hex.EncodeToString(key[:])
}

type KRBHeaderJSON struct {
	Magic     string `json:"magic"`
	Version   uint8  `json:"version"`
	MsgType   uint8  `json:"msg_type"`
	MsgName   string `json:"msg_name"`
	TotalLen  uint32 `json:"total_len"`
	SeqNum    uint32 `json:"seq_num"`
	Timestamp uint32 `json:"timestamp"`
	Addition  uint32 `json:"addition"`
}

func ParseKRBPacketHex(packetHex string) (krb.ProtocolHeader, []byte, []byte, error) {
	raw, err := HexToBytes(packetHex)
	if err != nil {
		return krb.ProtocolHeader{}, nil, nil, err
	}
	if len(raw) < 20 {
		return krb.ProtocolHeader{}, nil, nil, fmt.Errorf("packet too short: expected at least 20 bytes, got %d", len(raw))
	}
	h, err := krb.UnpackHeader(raw[:20])
	if err != nil {
		return krb.ProtocolHeader{}, nil, nil, err
	}
	wantLen := 20 + int(h.TotalLen)
	if len(raw) != wantLen {
		return krb.ProtocolHeader{}, nil, nil, fmt.Errorf("packet length mismatch: header payload length=%d, packet bytes=%d", h.TotalLen, len(raw))
	}
	return h, raw[20:], raw, nil
}

func KRBHeaderToJSON(h krb.ProtocolHeader) KRBHeaderJSON {
	return KRBHeaderJSON{
		Magic:     fmt.Sprintf("0x%04X", h.Magic),
		Version:   h.Version,
		MsgType:   h.MsgType,
		MsgName:   KRBMsgTypeName(h.MsgType),
		TotalLen:  h.TotalLen,
		SeqNum:    h.SeqNum,
		Timestamp: h.Timestamp,
		Addition:  h.Addition,
	}
}

func KRBMsgTypeName(msgType uint8) string {
	switch msgType {
	case krb.MsgASReq:
		return "AS_REQ"
	case krb.MsgASRep:
		return "AS_REP"
	case krb.MsgTGSReq:
		return "TGS_REQ"
	case krb.MsgTGSRep:
		return "TGS_REP"
	case krb.MsgAPReq:
		return "AP_REQ"
	case krb.MsgAPRep:
		return "AP_REP"
	case krb.MsgApp:
		return "APP"
	case krb.MsgErr:
		return "ERR"
	default:
		return "UNKNOWN"
	}
}
