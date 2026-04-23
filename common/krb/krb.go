package krb

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	MagicNumber uint16 = 0x4B45
	Version1    uint8  = 0x01

	MsgASReq  uint8 = 0x01
	MsgASRep  uint8 = 0x02
	MsgTGSReq uint8 = 0x03
	MsgTGSRep uint8 = 0x04
	MsgAPReq  uint8 = 0x05
	MsgAPRep  uint8 = 0x06
	MsgApp    uint8 = 0x07
	MsgErr    uint8 = 0xff

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

type KString struct {
	Len  uint16
	Data []byte
}

type KerHeader struct {
	Magic     uint16
	Version   uint8
	MsgType   uint8
	TotalLen  uint32
	SeqNum    uint32
	Timestamp uint32
	Addition  uint32
}

type ASReqPayload struct {
	IDClient KString
	IDTGS    KString
	TS1      uint32
}

type ASRepPayloadWire struct {
	CipherLen uint32
	EncPart   []byte
}

type ASRepPlain struct {
	KeyCTGS   [8]byte
	IDTGS     KString
	TS2       uint32
	Lifetime  uint32
	TicketLen uint32
	TicketTGS []byte
}

type TicketTGSPlain struct {
	KeyCTGS  [8]byte
	IDClient KString
	ADc      uint32
	IDTGS    KString
	TS2      uint32
	Lifetime uint32
}

type AuthenticatorCTGSPlain struct {
	IDClient KString
	ADc      uint32
	TS3      uint32
}

type TGSReqPayload struct {
	IDV        KString
	TicketLen  uint32
	TicketTGS  []byte
	AuthLen    uint32
	AuthCipher []byte
}

type TGSRepPayloadWire struct {
	CipherLen uint32
	EncPart   []byte
}

type TGSRepPlain struct {
	KeyCV      [8]byte
	IDV        KString
	TS4        uint32
	Lifetime   uint32
	TicketVLen uint32
	TicketV    []byte
}

type TicketVPlain struct {
	KeyCV    [8]byte
	IDClient KString
	ADc      uint32
	IDV      KString
	TS4      uint32
	Lifetime uint32
}

type APReqPayload struct {
	TicketVLen uint32
	TicketV    []byte
	AuthLen    uint32
	AuthCipher []byte
}

type AuthenticatorCVPlain struct {
	IDClient KString
	ADc      uint32
	TS5      uint32
}

type APRepPayloadWire struct {
	CipherLen uint32
	EncPart   []byte
}

type APRepPlain struct {
	TS5Plus1 uint32
}

type APPReqPayload struct {
	IDClient  KString
	CipherLen uint16
	Cipher    []byte
	RSASignC  [256]byte
}

type APPReqPlain struct {
	PtyOp        uint8
	PtySessionID uint32
	PayloadLen   uint32
	Payload      []byte
}

type APPRepPayload struct {
	CipherLen uint16
	Cipher    []byte
	RSASignV  [256]byte
}

type APPRepPlain struct {
	PtyEvent     uint8
	PtySessionID uint32
	ExitCode     int32
	PayloadLen   uint32
	Payload      []byte
}

type ASClientSecret struct {
	IDClient string
	Kc       [8]byte
	ADc      uint32
}

type ASState struct {
	SeqNum  uint32
	Clients map[string]ASClientSecret
	Ktgs    [8]byte
	IDTGS   string
}

type ServiceSecret struct {
	IDV string
	Kv  [8]byte
}

type TGSState struct {
	SeqNum   uint32
	Ktgs     [8]byte
	IDTGS    string
	Services map[string]ServiceSecret
}

type Certificate struct {
	ID        string `json:"id"`
	Issuer    string `json:"issuer"`
	PublicKey struct {
		N string `json:"n"`
		E string `json:"e"`
	} `json:"public_key"`
	Expire string `json:"expire"`
	Sign   string `json:"sign"`
}

type certBody struct {
	ID        string `json:"id"`
	Issuer    string `json:"issuer"`
	PublicKey struct {
		N string `json:"n"`
		E string `json:"e"`
	} `json:"public_key"`
	Expire string `json:"expire"`
}

type RSAKeyJSON struct {
	N string `json:"n"`
	E string `json:"e"`
	D string `json:"d,omitempty"`
}

type ReplayWindow struct {
	mu    sync.Mutex
	seen  map[uint32]struct{}
	order []uint32
	max   int
}

func NewReplayWindow(max int) *ReplayWindow {
	if max <= 0 {
		max = 1024
	}
	return &ReplayWindow{seen: make(map[uint32]struct{}, max), order: make([]uint32, 0, max), max: max}
}

func (r *ReplayWindow) Check(ts, seq uint32) int32 {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := uint32(time.Now().Unix())
	diff := int64(ts) - int64(now)
	if diff < 0 {
		diff = -diff
	}
	if diff > 5 {
		return ErrReplayTimestamp
	}
	if _, ok := r.seen[seq]; ok {
		return ErrReplaySeq
	}
	r.seen[seq] = struct{}{}
	r.order = append(r.order, seq)
	if len(r.order) > r.max {
		old := r.order[0]
		r.order = r.order[1:]
		delete(r.seen, old)
	}
	return KRBOK
}

func EncodeKString(s string) []byte {
	out := make([]byte, 2+len(s))
	binary.BigEndian.PutUint16(out[:2], uint16(len(s)))
	copy(out[2:], s)
	return out
}

func DecodeKString(raw []byte) (KString, int, int32) {
	if len(raw) < 2 {
		return KString{}, 0, ErrTicketInvalid
	}
	l := int(binary.BigEndian.Uint16(raw[:2]))
	if len(raw) < 2+l {
		return KString{}, 0, ErrTicketInvalid
	}
	return KString{Len: uint16(l), Data: append([]byte(nil), raw[2:2+l]...)}, 2 + l, KRBOK
}

func EncodeKStringStruct(ks KString) []byte {
	if int(ks.Len) != len(ks.Data) {
		ks.Len = uint16(len(ks.Data))
	}
	out := make([]byte, 2+len(ks.Data))
	binary.BigEndian.PutUint16(out[:2], ks.Len)
	copy(out[2:], ks.Data)
	return out
}

func PackHeader(msgType uint8, seqNum, timestamp uint32, payloadLen uint32) []byte {
	out := make([]byte, 20)
	binary.BigEndian.PutUint16(out[0:2], MagicNumber)
	out[2] = Version1
	out[3] = msgType
	binary.BigEndian.PutUint32(out[4:8], payloadLen)
	binary.BigEndian.PutUint32(out[8:12], seqNum)
	binary.BigEndian.PutUint32(out[12:16], timestamp)
	binary.BigEndian.PutUint32(out[16:20], 0)
	return out
}

func UnpackHeader(raw []byte) (KerHeader, int32) {
	if len(raw) < 20 {
		return KerHeader{}, ErrSocketRecv
	}
	h := KerHeader{
		Magic:     binary.BigEndian.Uint16(raw[0:2]),
		Version:   raw[2],
		MsgType:   raw[3],
		TotalLen:  binary.BigEndian.Uint32(raw[4:8]),
		SeqNum:    binary.BigEndian.Uint32(raw[8:12]),
		Timestamp: binary.BigEndian.Uint32(raw[12:16]),
		Addition:  binary.BigEndian.Uint32(raw[16:20]),
	}
	if h.Magic != MagicNumber {
		return KerHeader{}, ErrMagicMismatch
	}
	if h.Version != Version1 {
		return KerHeader{}, ErrVersionUnsupported
	}
	return h, KRBOK
}

func PackPacket(msgType uint8, seqNum, timestamp uint32, payload []byte) []byte {
	header := PackHeader(msgType, seqNum, timestamp, uint32(len(payload)))
	return append(header, payload...)
}

func ReadPacket(conn net.Conn, maxPayload uint32) (KerHeader, []byte, int32) {
	headerBuf := make([]byte, 20)
	if _, err := io.ReadFull(conn, headerBuf); err != nil {
		return KerHeader{}, nil, ErrSocketRecv
	}
	h, code := UnpackHeader(headerBuf)
	if code != KRBOK {
		return KerHeader{}, nil, code
	}
	if h.TotalLen > maxPayload {
		return KerHeader{}, nil, ErrPayloadTooLarge
	}
	payload := make([]byte, h.TotalLen)
	if h.TotalLen > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return KerHeader{}, nil, ErrSocketRecv
		}
	}
	return h, payload, KRBOK
}

func WritePacket(conn net.Conn, msgType uint8, seqNum, timestamp uint32, payload []byte) error {
	packet := PackPacket(msgType, seqNum, timestamp, payload)
	_, err := conn.Write(packet)
	return err
}

func CheckHeaderType(msgType uint8, allowed ...uint8) int32 {
	for _, v := range allowed {
		if v == msgType {
			return KRBOK
		}
	}
	if msgType == MsgErr {
		return KRBOK
	}
	return ErrMsgTypeInvalid
}

func BuildErrorPayload(code int32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(code))
	return buf
}

func ParseASReqPayload(raw []byte) (ASReqPayload, int32) {
	idClient, off, code := DecodeKString(raw)
	if code != KRBOK {
		return ASReqPayload{}, code
	}
	idTGS, off2, code := DecodeKString(raw[off:])
	if code != KRBOK {
		return ASReqPayload{}, code
	}
	if len(raw) < off+off2+4 {
		return ASReqPayload{}, ErrTicketInvalid
	}
	return ASReqPayload{
		IDClient: idClient,
		IDTGS:    idTGS,
		TS1:      binary.BigEndian.Uint32(raw[off+off2 : off+off2+4]),
	}, KRBOK
}

func BuildTicketTGSPlain(c ASClientSecret, idTGS string, keyCTGS [8]byte, ts2 uint32, lifetime uint32) ([]byte, int32) {
	buf := bytes.NewBuffer(nil)
	buf.Write(keyCTGS[:])
	buf.Write(EncodeKString(c.IDClient))
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, c.ADc)
	buf.Write(tmp)
	buf.Write(EncodeKString(idTGS))
	binary.BigEndian.PutUint32(tmp, ts2)
	buf.Write(tmp)
	binary.BigEndian.PutUint32(tmp, lifetime)
	buf.Write(tmp)
	return buf.Bytes(), KRBOK
}

func BuildASRepPlain(keyCTGS [8]byte, idTGS string, ts2 uint32, lifetime uint32, ticketTGS []byte) ([]byte, int32) {
	buf := bytes.NewBuffer(nil)
	buf.Write(keyCTGS[:])
	buf.Write(EncodeKString(idTGS))
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, ts2)
	buf.Write(tmp)
	binary.BigEndian.PutUint32(tmp, lifetime)
	buf.Write(tmp)
	binary.BigEndian.PutUint32(tmp, uint32(len(ticketTGS)))
	buf.Write(tmp)
	buf.Write(ticketTGS)
	return buf.Bytes(), KRBOK
}

func BuildASRepPayload(encPart []byte) ([]byte, int32) {
	buf := bytes.NewBuffer(nil)
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, uint32(len(encPart)))
	buf.Write(tmp)
	buf.Write(encPart)
	return buf.Bytes(), KRBOK
}

func ParseASRepPayload(raw []byte) (ASRepPayloadWire, int32) {
	if len(raw) < 4 {
		return ASRepPayloadWire{}, ErrTicketInvalid
	}
	cipherLen := binary.BigEndian.Uint32(raw[:4])
	if len(raw) < 4+int(cipherLen) {
		return ASRepPayloadWire{}, ErrTicketInvalid
	}
	return ASRepPayloadWire{
		CipherLen: cipherLen,
		EncPart:   append([]byte(nil), raw[4:4+int(cipherLen)]...),
	}, KRBOK
}

func ParseTGSReqPayload(raw []byte) (TGSReqPayload, int32) {
	idV, off, code := DecodeKString(raw)
	if code != KRBOK {
		return TGSReqPayload{}, code
	}
	if len(raw) < off+4 {
		return TGSReqPayload{}, ErrTicketInvalid
	}
	ticketLen := binary.BigEndian.Uint32(raw[off : off+4])
	start := off + 4
	if len(raw) < start+int(ticketLen)+4 {
		return TGSReqPayload{}, ErrTicketInvalid
	}
	ticketTGS := append([]byte(nil), raw[start:start+int(ticketLen)]...)
	authOff := start + int(ticketLen)
	authLen := binary.BigEndian.Uint32(raw[authOff : authOff+4])
	authStart := authOff + 4
	if len(raw) < authStart+int(authLen) {
		return TGSReqPayload{}, ErrTicketInvalid
	}
	return TGSReqPayload{
		IDV:        idV,
		TicketLen:  ticketLen,
		TicketTGS:  ticketTGS,
		AuthLen:    authLen,
		AuthCipher: append([]byte(nil), raw[authStart:authStart+int(authLen)]...),
	}, KRBOK
}

func DecodeTicketTGS(ticketCipher []byte, ktgs [8]byte) (TicketTGSPlain, int32) {
	plain, err := DecryptDESCBC(ktgs, ticketCipher)
	if err != nil {
		return TicketTGSPlain{}, ErrDESDecryptFail
	}
	key := TicketTGSPlain{}
	if len(plain) < 8 {
		return TicketTGSPlain{}, ErrTicketInvalid
	}
	copy(key.KeyCTGS[:], plain[:8])
	idClient, off, code := DecodeKString(plain[8:])
	if code != KRBOK {
		return TicketTGSPlain{}, code
	}
	if len(plain) < 8+off+4+2 {
		return TicketTGSPlain{}, ErrTicketInvalid
	}
	key.IDClient = idClient
	key.ADc = binary.BigEndian.Uint32(plain[8+off : 8+off+4])
	idTGS, off2, code := DecodeKString(plain[8+off+4:])
	if code != KRBOK {
		return TicketTGSPlain{}, code
	}
	if len(plain) < 8+off+4+off2+8 {
		return TicketTGSPlain{}, ErrTicketInvalid
	}
	key.IDTGS = idTGS
	base := 8 + off + 4 + off2
	key.TS2 = binary.BigEndian.Uint32(plain[base : base+4])
	key.Lifetime = binary.BigEndian.Uint32(plain[base+4 : base+8])
	return key, KRBOK
}

func DecodeAuthenticatorCTGS(authCipher []byte, keyCTGS [8]byte) (AuthenticatorCTGSPlain, int32) {
	plain, err := DecryptDESCBC(keyCTGS, authCipher)
	if err != nil {
		return AuthenticatorCTGSPlain{}, ErrDESDecryptFail
	}
	idClient, off, code := DecodeKString(plain)
	if code != KRBOK {
		return AuthenticatorCTGSPlain{}, code
	}
	if len(plain) < off+8 {
		return AuthenticatorCTGSPlain{}, ErrTicketInvalid
	}
	return AuthenticatorCTGSPlain{
		IDClient: idClient,
		ADc:      binary.BigEndian.Uint32(plain[off : off+4]),
		TS3:      binary.BigEndian.Uint32(plain[off+4 : off+8]),
	}, KRBOK
}

func BuildTicketVPlain(idClient string, adC uint32, idV string, keyCV [8]byte, ts4 uint32, lifetime uint32) ([]byte, int32) {
	buf := bytes.NewBuffer(nil)
	buf.Write(keyCV[:])
	buf.Write(EncodeKString(idClient))
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, adC)
	buf.Write(tmp)
	buf.Write(EncodeKString(idV))
	binary.BigEndian.PutUint32(tmp, ts4)
	buf.Write(tmp)
	binary.BigEndian.PutUint32(tmp, lifetime)
	buf.Write(tmp)
	return buf.Bytes(), KRBOK
}

func BuildTGSRepPlain(keyCV [8]byte, idV string, ts4 uint32, lifetime uint32, ticketV []byte) ([]byte, int32) {
	buf := bytes.NewBuffer(nil)
	buf.Write(keyCV[:])
	buf.Write(EncodeKString(idV))
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, ts4)
	buf.Write(tmp)
	binary.BigEndian.PutUint32(tmp, lifetime)
	buf.Write(tmp)
	binary.BigEndian.PutUint32(tmp, uint32(len(ticketV)))
	buf.Write(tmp)
	buf.Write(ticketV)
	return buf.Bytes(), KRBOK
}

func ParseAPReqPayload(raw []byte) (APReqPayload, int32) {
	if len(raw) < 8 {
		return APReqPayload{}, ErrTicketInvalid
	}
	ticketLen := binary.BigEndian.Uint32(raw[:4])
	if len(raw) < 4+int(ticketLen)+4 {
		return APReqPayload{}, ErrTicketInvalid
	}
	ticket := append([]byte(nil), raw[4:4+int(ticketLen)]...)
	authOff := 4 + int(ticketLen)
	authLen := binary.BigEndian.Uint32(raw[authOff : authOff+4])
	if len(raw) < authOff+4+int(authLen) {
		return APReqPayload{}, ErrTicketInvalid
	}
	return APReqPayload{
		TicketVLen: ticketLen,
		TicketV:    ticket,
		AuthLen:    authLen,
		AuthCipher: append([]byte(nil), raw[authOff+4:authOff+4+int(authLen)]...),
	}, KRBOK
}

func DecodeTicketV(ticketCipher []byte, kv [8]byte) (TicketVPlain, int32) {
	plain, err := DecryptDESCBC(kv, ticketCipher)
	if err != nil {
		return TicketVPlain{}, ErrDESDecryptFail
	}
	if len(plain) < 8 {
		return TicketVPlain{}, ErrTicketInvalid
	}
	out := TicketVPlain{}
	copy(out.KeyCV[:], plain[:8])
	idClient, off, code := DecodeKString(plain[8:])
	if code != KRBOK {
		return TicketVPlain{}, code
	}
	out.IDClient = idClient
	base := 8 + off
	if len(plain) < base+4 {
		return TicketVPlain{}, ErrTicketInvalid
	}
	out.ADc = binary.BigEndian.Uint32(plain[base : base+4])
	idV, off2, code := DecodeKString(plain[base+4:])
	if code != KRBOK {
		return TicketVPlain{}, code
	}
	out.IDV = idV
	base = base + 4 + off2
	if len(plain) < base+8 {
		return TicketVPlain{}, ErrTicketInvalid
	}
	out.TS4 = binary.BigEndian.Uint32(plain[base : base+4])
	out.Lifetime = binary.BigEndian.Uint32(plain[base+4 : base+8])
	return out, KRBOK
}

func DecodeAuthenticatorCV(authCipher []byte, keyCV [8]byte) (AuthenticatorCVPlain, int32) {
	plain, err := DecryptDESCBC(keyCV, authCipher)
	if err != nil {
		return AuthenticatorCVPlain{}, ErrDESDecryptFail
	}
	idClient, off, code := DecodeKString(plain)
	if code != KRBOK {
		return AuthenticatorCVPlain{}, code
	}
	if len(plain) < off+8 {
		return AuthenticatorCVPlain{}, ErrTicketInvalid
	}
	return AuthenticatorCVPlain{
		IDClient: idClient,
		ADc:      binary.BigEndian.Uint32(plain[off : off+4]),
		TS5:      binary.BigEndian.Uint32(plain[off+4 : off+8]),
	}, KRBOK
}

func BuildAPRepPayload(ts5 uint32, keyCV [8]byte) ([]byte, int32) {
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, ts5+1)
	cipherData, err := EncryptDESCBC(keyCV, tmp)
	if err != nil {
		return nil, ErrDESPadding
	}
	return BuildASRepPayload(cipherData)
}

func ParseAPPReqPayload(raw []byte) (APPReqPayload, int32) {
	idClient, off, code := DecodeKString(raw)
	if code != KRBOK {
		return APPReqPayload{}, code
	}
	if len(raw) < off+2 {
		return APPReqPayload{}, ErrTicketInvalid
	}
	cipherLen := binary.BigEndian.Uint16(raw[off : off+2])
	start := off + 2
	if len(raw) < start+int(cipherLen)+256 {
		return APPReqPayload{}, ErrTicketInvalid
	}
	var sig [256]byte
	copy(sig[:], raw[start+int(cipherLen):start+int(cipherLen)+256])
	return APPReqPayload{
		IDClient:  idClient,
		CipherLen: cipherLen,
		Cipher:    append([]byte(nil), raw[start:start+int(cipherLen)]...),
		RSASignC:  sig,
	}, KRBOK
}

func DecryptAPPReqPlain(cipherBytes []byte, keyCV [8]byte) (APPReqPlain, int32) {
	plain, err := DecryptDESCBC(keyCV, cipherBytes)
	if err != nil {
		return APPReqPlain{}, ErrDESDecryptFail
	}
	if len(plain) < 9 {
		return APPReqPlain{}, ErrTicketInvalid
	}
	out := APPReqPlain{}
	out.PtyOp = plain[0]
	out.PtySessionID = binary.BigEndian.Uint32(plain[1:5])
	out.PayloadLen = binary.BigEndian.Uint32(plain[5:9])
	if len(plain) < 9+int(out.PayloadLen) {
		return APPReqPlain{}, ErrTicketInvalid
	}
	out.Payload = append([]byte(nil), plain[9:9+int(out.PayloadLen)]...)
	return out, KRBOK
}

func BuildAPPRepPayload(ptyEvent uint8, ptySessionID uint32, exitCode int32, payload []byte, keyCV [8]byte, signV func([]byte) [256]byte) ([]byte, int32) {
	buf := bytes.NewBuffer(nil)
	body := bytes.NewBuffer(nil)
	body.WriteByte(ptyEvent)
	tmp4 := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp4, ptySessionID)
	body.Write(tmp4)
	binary.BigEndian.PutUint32(tmp4, uint32(exitCode))
	body.Write(tmp4)
	binary.BigEndian.PutUint32(tmp4, uint32(len(payload)))
	body.Write(tmp4)
	body.Write(payload)
	cipherData, err := EncryptDESCBC(keyCV, body.Bytes())
	if err != nil {
		return nil, ErrDESPadding
	}
	tmp2 := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp2, uint16(len(cipherData)))
	buf.Write(tmp2)
	buf.Write(cipherData)
	sig := signV(cipherData)
	buf.Write(sig[:])
	return buf.Bytes(), KRBOK
}

func BuildAPRepPlain(ts5 uint32, keyCV [8]byte) ([]byte, int32) {
	return BuildAPRepPayload(ts5, keyCV)
}

func DecryptAPRepPlain(cipherBytes []byte, keyCV [8]byte) (APRepPlain, int32) {
	plain, err := DecryptDESCBC(keyCV, cipherBytes)
	if err != nil {
		return APRepPlain{}, ErrDESDecryptFail
	}
	if len(plain) < 4 {
		return APRepPlain{}, ErrTicketInvalid
	}
	return APRepPlain{
		TS5Plus1: binary.BigEndian.Uint32(plain[:4]),
	}, KRBOK
}

func VerifyCipherSignature(seq uint32, cipherData []byte, sig [256]byte, pub *RSAKey) int32 {
	return rsaVerifySignature(seq, cipherData, sig, pub)
}

func SignSHA256(msg []byte, priv *RSAKey) ([256]byte, int32) {
	return rsaSignMessage(msg, priv)
}

func VerifySHA256(msg []byte, sig [256]byte, pub *RSAKey) int32 {
	return rsaVerifyMessage(msg, sig, pub)
}

func LoadKey8(path string, fallbackSeed string) ([8]byte, error) {
	var out [8]byte
	if path != "" {
		b, err := os.ReadFile(path)
		if err == nil {
			switch {
			case len(b) == 8:
				copy(out[:], b)
				return out, nil
			default:
				if key, ok := parseKeyBytes(b); ok {
					copy(out[:], key)
					return out, nil
				}
			}
		}
	}
	if fallbackSeed == "" {
		return out, errors.New("no key material")
	}
	sum := Sum256([]byte(fallbackSeed))
	copy(out[:], sum[:8])
	return out, nil
}

func parseKeyBytes(raw []byte) ([]byte, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, false
	}
	if raw[0] == '{' {
		var doc struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal(raw, &doc); err == nil && doc.Key != "" {
			if decoded, ok := decodeKeyString(doc.Key); ok {
				return decoded, true
			}
		}
	}
	if decoded, ok := decodeKeyString(string(raw)); ok {
		return decoded, true
	}
	return nil, false
}

func decodeKeyString(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	if decoded, err := hex.DecodeString(s); err == nil && len(decoded) >= 8 {
		return decoded[:8], true
	}
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil && len(decoded) >= 8 {
		return decoded[:8], true
	}
	return nil, false
}

func LoadRSAPrivateKey(path string) (*RSAKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc RSAKeyJSON
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	n, err := parseBigIntHex(doc.N)
	if err != nil {
		return nil, err
	}
	e, err := parseBigIntHex(doc.E)
	if err != nil {
		return nil, err
	}
	d, err := parseBigIntHex(doc.D)
	if err != nil {
		return nil, err
	}
	return &RSAKey{N: n, E: e, D: d}, nil
}

func LoadRSAPublicKey(path string) (*RSAKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc RSAKeyJSON
	if err := json.Unmarshal(b, &doc); err != nil {
		var cert Certificate
		if err2 := json.Unmarshal(b, &cert); err2 == nil && cert.PublicKey.N != "" {
			doc.N = cert.PublicKey.N
			doc.E = cert.PublicKey.E
		} else {
			return nil, err
		}
	}
	n, err := parseBigIntHex(doc.N)
	if err != nil {
		return nil, err
	}
	e, err := parseBigIntHex(doc.E)
	if err != nil {
		return nil, err
	}
	return &RSAKey{N: n, E: e}, nil
}

func parseBigIntHex(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty big integer")
	}
	if v, ok := new(big.Int).SetString(s, 16); ok {
		return v, nil
	}
	if v, ok := new(big.Int).SetString(s, 10); ok {
		return v, nil
	}
	return nil, fmt.Errorf("invalid integer: %s", s)
}

func CertLoad(path string) (*Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cert Certificate
	if err := json.Unmarshal(b, &cert); err != nil {
		return nil, err
	}
	return &cert, nil
}

func CertBodyBytes(cert *Certificate) ([]byte, error) {
	if cert == nil {
		return nil, errors.New("nil cert")
	}
	var body certBody
	body.ID = cert.ID
	body.Issuer = cert.Issuer
	body.PublicKey.N = cert.PublicKey.N
	body.PublicKey.E = cert.PublicKey.E
	body.Expire = cert.Expire
	return json.Marshal(body)
}

func CertVerify(cert *Certificate) int32 {
	if cert == nil {
		return ErrCertLoadFail
	}
	expire, err := time.Parse("2006-01-02", cert.Expire)
	if err != nil {
		return ErrCertLoadFail
	}
	if time.Now().After(expire.Add(24 * time.Hour)) {
		return ErrCertExpired
	}
	body, err := CertBodyBytes(cert)
	if err != nil {
		return ErrCertLoadFail
	}
	pub, err := cert.PublicKeyRSA()
	if err != nil {
		return ErrCertSigInvalid
	}
	sig, err := decodeSignature(cert.Sign)
	if err != nil {
		return ErrCertSigInvalid
	}
	sum := Sum256(body)
	if code := rsaVerifyDigest(sum[:], sig, pub); code != KRBOK {
		return code
	}
	return KRBOK
}

func (c *Certificate) PublicKeyRSA() (*RSAKey, error) {
	n, err := parseBigIntHex(c.PublicKey.N)
	if err != nil {
		return nil, err
	}
	e, err := parseBigIntHex(c.PublicKey.E)
	if err != nil {
		return nil, err
	}
	return &RSAKey{N: n, E: e}, nil
}

func decodeSignature(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty signature")
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, errors.New("invalid signature format")
}

func CertFindByID(id string, certDB []*Certificate) *Certificate {
	for _, cert := range certDB {
		if cert != nil && cert.ID == id {
			return cert
		}
	}
	return nil
}

func ParseAPPRepPayload(raw []byte) (APPRepPayload, int32) {
	if len(raw) < 2+256 {
		return APPRepPayload{}, ErrTicketInvalid
	}
	cipherLen := binary.BigEndian.Uint16(raw[:2])
	if len(raw) < 2+int(cipherLen)+256 {
		return APPRepPayload{}, ErrTicketInvalid
	}
	var sig [256]byte
	copy(sig[:], raw[2+int(cipherLen):2+int(cipherLen)+256])
	return APPRepPayload{
		CipherLen: cipherLen,
		Cipher:    append([]byte(nil), raw[2:2+int(cipherLen)]...),
		RSASignV:  sig,
	}, KRBOK
}

func DecryptAPPRepPlain(cipherBytes []byte, keyCV [8]byte) (APPRepPlain, int32) {
	plain, err := DecryptDESCBC(keyCV, cipherBytes)
	if err != nil {
		return APPRepPlain{}, ErrDESDecryptFail
	}
	if len(plain) < 13 {
		return APPRepPlain{}, ErrTicketInvalid
	}
	return APPRepPlain{
		PtyEvent:     plain[0],
		PtySessionID: binary.BigEndian.Uint32(plain[1:5]),
		ExitCode:     int32(binary.BigEndian.Uint32(plain[5:9])),
		PayloadLen:   binary.BigEndian.Uint32(plain[9:13]),
		Payload:      append([]byte(nil), plain[13:]...),
	}, KRBOK
}

func EncryptDESCBC(key [8]byte, plain []byte) ([]byte, error) {
	return desCBCEncrypt(key, plain)
}

func DecryptDESCBC(key [8]byte, cipherBytes []byte) ([]byte, error) {
	return desCBCDecrypt(key, cipherBytes)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	if blockSize <= 0 {
		return append([]byte(nil), data...)
	}
	pad := blockSize - len(data)%blockSize
	if pad == 0 {
		pad = blockSize
	}
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid padding length")
	}
	pad := int(data[len(data)-1])
	if pad < 1 || pad > blockSize || pad > len(data) {
		return nil, errors.New("invalid padding value")
	}
	for i := len(data) - pad; i < len(data); i++ {
		if int(data[i]) != pad {
			return nil, errors.New("invalid padding content")
		}
	}
	return append([]byte(nil), data[:len(data)-pad]...), nil
}

func Hash256(data []byte) [32]byte {
	return Sum256(data)
}

func Uint32ToBytes(v uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, v)
	return out
}

func BytesToUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

func BuildSessionKey(seed string) ([8]byte, int32) {
	var out [8]byte
	sum := Sum256([]byte(seed + time.Now().UTC().Format(time.RFC3339Nano)))
	copy(out[:], sum[:8])
	return out, KRBOK
}

func ToUint32IP(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v4)
}

func PeerIP(conn net.Conn) uint32 {
	if conn == nil {
		return 0
	}
	addr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return 0
	}
	return ToUint32IP(addr.IP)
}

func EnsureDir(path string) error {
	if path == "" {
		return nil
	}
	return os.MkdirAll(path, 0o755)
}

func WriteJSONFile(path string, v any) error {
	if err := EnsureDir(dirOf(path)); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func dirOf(path string) string {
	if path == "" {
		return ""
	}
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		return path[:i]
	}
	return ""
}

func ContextWithCancel(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithCancel(parent)
}
