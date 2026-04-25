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
	"security-project/common/crypto"
	"strings"
	"sync"
	"time"
)

// ASClientSecret 是AS服务器中保存的客户端信息结构体，包含了客户端的ID、与TGS共享的密钥以及客户端的ADc（地址）。
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

func (r *ReplayWindow) Check(ts, seq uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := uint32(time.Now().Unix())
	diff := int64(ts) - int64(now)
	if diff < 0 {
		diff = -diff
	}
	if diff > 5 {
		return errorFromCode(ErrReplayTimestamp)
	}
	if _, ok := r.seen[seq]; ok {
		return errorFromCode(ErrReplaySeq)
	}
	r.seen[seq] = struct{}{}
	r.order = append(r.order, seq)
	if len(r.order) > r.max {
		old := r.order[0]
		r.order = r.order[1:]
		delete(r.seen, old)
	}
	return nil
}

func EncodeKString(s string) []byte {
	out := make([]byte, 2+len(s))
	binary.BigEndian.PutUint16(out[:2], uint16(len(s)))
	copy(out[2:], s)
	return out
}

// DecodeKString 解析KString格式的数据，返回KString结构体、总字节数和错误码
func DecodeKString(raw []byte) (KString, int, error) {
	c := NewCursor(raw)
	ks, err := c.ReadKString()
	if err != nil {
		return KString{}, 0, err
	}
	return ks, c.off, nil
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

// PackHeader 构建一个协议头的字节切片，包含了消息类型、序列号、时间戳和负载长度等信息。返回构建好的字节切片。
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

// UnpackHeader 从原始字节切片中解析出一个协议头结构体，校验魔数和版本号的正确性，并返回解析出的协议头和错误码。
func UnpackHeader(raw []byte) (ProtocolHeader, error) {
	if len(raw) < 20 {
		return ProtocolHeader{}, errorFromCode(ErrSocketRecv)
	}
	h := ProtocolHeader{
		Magic:     binary.BigEndian.Uint16(raw[0:2]),
		Version:   raw[2],
		MsgType:   raw[3],
		TotalLen:  binary.BigEndian.Uint32(raw[4:8]),
		SeqNum:    binary.BigEndian.Uint32(raw[8:12]),
		Timestamp: binary.BigEndian.Uint32(raw[12:16]),
		Addition:  binary.BigEndian.Uint32(raw[16:20]),
	}
	if h.Magic != MagicNumber {
		return ProtocolHeader{}, errorFromCode(ErrMagicMismatch)
	}
	if h.Version != Version1 {
		return ProtocolHeader{}, errorFromCode(ErrVersionUnsupported)
	}
	return h, nil
}

func PackPacket(msgType uint8, seqNum, timestamp uint32, payload []byte) []byte {
	header := PackHeader(msgType, seqNum, timestamp, uint32(len(payload)))
	return append(header, payload...)
}

// ReadPacket 从连接中读取一个完整的协议包，返回解析后的协议头、负载数据和错误码
func ReadPacket(conn net.Conn, maxPayload uint32) (ProtocolHeader, []byte, error) {
	//解析前20字节的header
	headerBuf := make([]byte, 20)
	if _, err := io.ReadFull(conn, headerBuf); err != nil {
		return ProtocolHeader{}, nil, errorFromCode(ErrSocketRecv)
	}
	h, code := UnpackHeader(headerBuf)
	//校验header合法性
	if code != nil {
		return ProtocolHeader{}, nil, code
	}
	//校验payload长度
	if h.TotalLen > maxPayload {
		return ProtocolHeader{}, nil, errorFromCode(ErrPayloadTooLarge)
	}
	payload := make([]byte, h.TotalLen)
	if h.TotalLen > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return ProtocolHeader{}, nil, errorFromCode(ErrSocketRecv)
		}
	}
	return h, payload, nil
}

func WritePacket(conn net.Conn, msgType uint8, seqNum, timestamp uint32, payload []byte) error {
	packet := PackPacket(msgType, seqNum, timestamp, payload)
	_, err := conn.Write(packet)
	return err
}

// CheckHeaderType 检查消息类型是否在允许的范围内，或者是否为错误消息类型
func CheckHeaderType(msgType uint8, allowed ...uint8) error {
	for _, v := range allowed {
		if v == msgType {
			return nil
		}
	}
	if msgType == MsgErr {
		return nil
	}
	return errorFromCode(ErrMsgTypeInvalid)
}

// BuildErrorPayload 构建一个错误消息的负载，包含了错误码
func BuildErrorPayload(code int32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(code))
	return buf
}

// ParseASReqPayload 解析错误消息的负载，返回错误码
func ParseASReqPayload(raw []byte) (ASReqPayload, error) {
	c := NewCursor(raw)
	idClient, err := c.ReadKString()
	if err != nil {
		return ASReqPayload{}, err
	}
	idTGS, err := c.ReadKString()
	if err != nil {
		return ASReqPayload{}, err
	}
	ts1, err := c.ReadUint32()
	if err != nil {
		return ASReqPayload{}, err
	}
	return ASReqPayload{
		IDClient: idClient,
		IDTGS:    idTGS,
		TS1:      ts1,
	}, nil
}

func BuildTicketTGSPlain(c ASClientSecret, idTGS string, keyCTGS [8]byte, ts2 uint32, lifetime uint32) ([]byte, error) {
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
	return buf.Bytes(), nil
}

func BuildASRepPlain(keyCTGS [8]byte, idTGS string, ts2 uint32, lifetime uint32, ticketTGS []byte) ([]byte, error) {
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
	return buf.Bytes(), nil
}

func BuildASRepPayload(encPart []byte) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, uint32(len(encPart)))
	buf.Write(tmp)
	buf.Write(encPart)
	return buf.Bytes(), nil
}

func ParseASRepPayload(raw []byte) (ASRepPayloadWire, error) {
	c := NewCursor(raw)
	cipherLen, err := c.ReadUint32()
	if err != nil {
		return ASRepPayloadWire{}, err
	}
	encPart, err := c.ReadBytes(int(cipherLen))
	if err != nil {
		return ASRepPayloadWire{}, err
	}
	return ASRepPayloadWire{
		CipherLen: cipherLen,
		EncPart:   encPart,
	}, nil
}

func ParseTGSReqPayload(raw []byte) (TGSReqPayload, error) {
	c := NewCursor(raw)
	idV, err := c.ReadKString()
	if err != nil {
		return TGSReqPayload{}, err
	}
	ticketLen, err := c.ReadUint32()
	if err != nil {
		return TGSReqPayload{}, err
	}
	ticketTGS, err := c.ReadBytes(int(ticketLen))
	if err != nil {
		return TGSReqPayload{}, err
	}
	authLen, err := c.ReadUint32()
	if err != nil {
		return TGSReqPayload{}, err
	}
	authCipher, err := c.ReadBytes(int(authLen))
	if err != nil {
		return TGSReqPayload{}, err
	}
	return TGSReqPayload{
		IDV:        idV,
		TicketLen:  ticketLen,
		TicketTGS:  ticketTGS,
		AuthLen:    authLen,
		AuthCipher: authCipher,
	}, nil
}

func DecodeTicketTGS(ticketCipher []byte, ktgs [8]byte) (TicketTGSPlain, error) {
	plain, err := crypto.DecryptDESCBC(ktgs, ticketCipher)
	if err != nil {
		return TicketTGSPlain{}, errorFromCode(ErrDESDecryptFail)
	}
	c := NewCursor(plain)
	keyBytes, err := c.ReadBytes(8)
	if err != nil {
		return TicketTGSPlain{}, err
	}
	idClient, err := c.ReadKString()
	if err != nil {
		return TicketTGSPlain{}, err
	}
	adc, err := c.ReadUint32()
	if err != nil {
		return TicketTGSPlain{}, err
	}
	idTGS, err := c.ReadKString()
	if err != nil {
		return TicketTGSPlain{}, err
	}
	ts2, err := c.ReadUint32()
	if err != nil {
		return TicketTGSPlain{}, err
	}
	lifetime, err := c.ReadUint32()
	if err != nil {
		return TicketTGSPlain{}, err
	}
	var key TicketTGSPlain
	copy(key.KeyCTGS[:], keyBytes)
	key.IDClient = idClient
	key.ADc = adc
	key.IDTGS = idTGS
	key.TS2 = ts2
	key.Lifetime = lifetime
	return key, nil
}

func DecodeAuthenticatorCTGS(authCipher []byte, keyCTGS [8]byte) (AuthenticatorCTGSPlain, error) {
	plain, err := crypto.DecryptDESCBC(keyCTGS, authCipher)
	if err != nil {
		return AuthenticatorCTGSPlain{}, errorFromCode(ErrDESDecryptFail)
	}
	c := NewCursor(plain)
	idClient, err := c.ReadKString()
	if err != nil {
		return AuthenticatorCTGSPlain{}, err
	}
	adc, err := c.ReadUint32()
	if err != nil {
		return AuthenticatorCTGSPlain{}, err
	}
	ts3, err := c.ReadUint32()
	if err != nil {
		return AuthenticatorCTGSPlain{}, err
	}
	return AuthenticatorCTGSPlain{
		IDClient: idClient,
		ADc:      adc,
		TS3:      ts3,
	}, nil
}

func BuildTicketVPlain(idClient string, adC uint32, idV string, keyCV [8]byte, ts4 uint32, lifetime uint32) ([]byte, error) {
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
	return buf.Bytes(), nil
}

func BuildTGSRepPlain(keyCV [8]byte, idV string, ts4 uint32, lifetime uint32, ticketV []byte) ([]byte, error) {
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
	return buf.Bytes(), nil
}

func ParseAPReqPayload(raw []byte) (APReqPayload, error) {
	c := NewCursor(raw)
	ticketLen, err := c.ReadUint32()
	if err != nil {
		return APReqPayload{}, err
	}
	ticket, err := c.ReadBytes(int(ticketLen))
	if err != nil {
		return APReqPayload{}, err
	}
	authLen, err := c.ReadUint32()
	if err != nil {
		return APReqPayload{}, err
	}
	authCipher, err := c.ReadBytes(int(authLen))
	if err != nil {
		return APReqPayload{}, err
	}
	return APReqPayload{
		TicketVLen: ticketLen,
		TicketV:    ticket,
		AuthLen:    authLen,
		AuthCipher: authCipher,
	}, nil
}

func DecodeTicketV(ticketCipher []byte, kv [8]byte) (TicketVPlain, error) {
	plain, err := crypto.DecryptDESCBC(kv, ticketCipher)
	if err != nil {
		return TicketVPlain{}, errorFromCode(ErrDESDecryptFail)
	}
	c := NewCursor(plain)
	keyBytes, err := c.ReadBytes(8)
	if err != nil {
		return TicketVPlain{}, err
	}
	idClient, err := c.ReadKString()
	if err != nil {
		return TicketVPlain{}, err
	}
	adc, err := c.ReadUint32()
	if err != nil {
		return TicketVPlain{}, err
	}
	idV, err := c.ReadKString()
	if err != nil {
		return TicketVPlain{}, err
	}
	ts4, err := c.ReadUint32()
	if err != nil {
		return TicketVPlain{}, err
	}
	lifetime, err := c.ReadUint32()
	if err != nil {
		return TicketVPlain{}, err
	}
	var out TicketVPlain
	copy(out.KeyCV[:], keyBytes)
	out.IDClient = idClient
	out.ADc = adc
	out.IDV = idV
	out.TS4 = ts4
	out.Lifetime = lifetime
	return out, nil
}

func DecodeAuthenticatorCV(authCipher []byte, keyCV [8]byte) (AuthenticatorCVPlain, error) {
	plain, err := crypto.DecryptDESCBC(keyCV, authCipher)
	if err != nil {
		return AuthenticatorCVPlain{}, errorFromCode(ErrDESDecryptFail)
	}
	c := NewCursor(plain)
	idClient, err := c.ReadKString()
	if err != nil {
		return AuthenticatorCVPlain{}, err
	}
	adc, err := c.ReadUint32()
	if err != nil {
		return AuthenticatorCVPlain{}, err
	}
	ts5, err := c.ReadUint32()
	if err != nil {
		return AuthenticatorCVPlain{}, err
	}
	return AuthenticatorCVPlain{
		IDClient: idClient,
		ADc:      adc,
		TS5:      ts5,
	}, nil
}

func BuildAPRepPayload(ts5 uint32, keyCV [8]byte) ([]byte, error) {
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, ts5+1)
	cipherData, err := crypto.EncryptDESCBC(keyCV, tmp)
	if err != nil {
		return nil, errorFromCode(ErrDESPadding)
	}
	return BuildASRepPayload(cipherData)
}

// ParseAPPReqPayload 解析AP-REQ消息的负载，返回一个APPReqPayload结构体和错误信息
func ParseAPPReqPayload(raw []byte) (APPReqPayload, error) {
	c := NewCursor(raw)
	idClient, err := c.ReadKString()
	if err != nil {
		return APPReqPayload{}, err
	}
	cipherLen, err := c.ReadUint16()
	if err != nil {
		return APPReqPayload{}, err
	}
	cipher, err := c.ReadBytes(int(cipherLen))
	if err != nil {
		return APPReqPayload{}, err
	}
	sigBytes, err := c.ReadBytes(256)
	if err != nil {
		return APPReqPayload{}, err
	}
	var sig [256]byte
	copy(sig[:], sigBytes)
	return APPReqPayload{
		IDClient:  idClient,
		CipherLen: cipherLen,
		Cipher:    cipher,
		RSASignC:  sig,
	}, nil
}

// DecryptAPPReqPlain 解密AP-REQ消息中的密文数据，返回一个APPReqPlain结构体和错误信息
func DecryptAPPReqPlain(cipherBytes []byte, keyCV [8]byte) (APPReqPlain, error) {
	plain, err := crypto.DecryptDESCBC(keyCV, cipherBytes)
	if err != nil {
		return APPReqPlain{}, errorFromCode(ErrDESDecryptFail)
	}
	c := NewCursor(plain)
	ptyOp, err := c.ReadBytes(1)
	if err != nil {
		return APPReqPlain{}, err
	}
	ptySessionID, err := c.ReadUint32()
	if err != nil {
		return APPReqPlain{}, err
	}
	payloadLen, err := c.ReadUint32()
	if err != nil {
		return APPReqPlain{}, err
	}
	payload, err := c.ReadBytes(int(payloadLen))
	if err != nil {
		return APPReqPlain{}, err
	}
	return APPReqPlain{
		PtyOp:        ptyOp[0],
		PtySessionID: ptySessionID,
		PayloadLen:   payloadLen,
		Payload:      payload,
	}, nil
}

func BuildAPPRepPayload(ptyEvent uint8, ptySessionID uint32, exitCode int32, payload []byte, keyCV [8]byte, signV func([]byte) ([256]byte, error)) ([]byte, error) {
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
	cipherData, err := crypto.EncryptDESCBC(keyCV, body.Bytes())
	if err != nil {
		return nil, errorFromCode(ErrDESPadding)
	}
	tmp2 := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp2, uint16(len(cipherData)))
	buf.Write(tmp2)
	buf.Write(cipherData)
	sig, err := signV(cipherData)
	if err != nil {
		return nil, err
	}
	buf.Write(sig[:])
	return buf.Bytes(), nil
}

func BuildAPRepPlain(ts5 uint32, keyCV [8]byte) ([]byte, error) {
	return BuildAPRepPayload(ts5, keyCV)
}

func DecryptAPRepPlain(cipherBytes []byte, keyCV [8]byte) (APRepPlain, error) {
	plain, err := crypto.DecryptDESCBC(keyCV, cipherBytes)
	if err != nil {
		return APRepPlain{}, errorFromCode(ErrDESDecryptFail)
	}
	if len(plain) < 4 {
		return APRepPlain{}, errorFromCode(ErrTicketInvalid)
	}
	return APRepPlain{
		TS5Plus1: binary.BigEndian.Uint32(plain[:4]),
	}, nil
}

func VerifyCipherSignature(seq uint32, cipherData []byte, sig [256]byte, pub *crypto.RSAKey) error {
	return errorFromCode(crypto.RsaVerifySignature(seq, cipherData, sig, pub))
}

func SignSHA256(msg []byte, priv *crypto.RSAKey) ([256]byte, error) {
	sig, code := crypto.RsaSignMessage(msg, priv)
	return sig, errorFromCode(code)
}

func VerifySHA256(msg []byte, sig [256]byte, pub *crypto.RSAKey) error {
	return errorFromCode(crypto.RsaVerifyMessage(msg, sig, pub))
}

// LoadKey8 从指定路径加载一个8字节的密钥（DES密钥），
// 如果路径为空或加载失败，则使用fallbackSeed生成一个8字节的密钥。返回加载的密钥和错误信息。
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
	sum := crypto.Sum256([]byte(fallbackSeed))
	copy(out[:], sum[:8])
	return out, nil
}

// parseKeyBytes 尝试从原始字节数据中解析出一个8字节的密钥，
// 支持直接的8字节数据、十六进制字符串和Base64字符串三种格式。返回解析出的密钥和一个布尔值表示是否成功解析。
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

func LoadRSAPrivateKey(path string) (*crypto.RSAKey, error) {
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
	return &crypto.RSAKey{N: n, E: e, D: d}, nil
}

func LoadRSAPublicKey(path string) (*crypto.RSAKey, error) {
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
	return &crypto.RSAKey{N: n, E: e}, nil
}

// parseBigIntHex 尝试将输入字符串解析为一个大整数，
// 支持十六进制和十进制两种格式。返回解析出的大整数和错误信息。
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

// CertVerify 验证证书的有效性，包括过期时间和签名的正确性。
// 返回错误信息，如果验证成功则返回nil。
func CertVerify(cert *Certificate) error {
	if cert == nil {
		return errorFromCode(ErrCertLoadFail)
	}
	expire, err := time.Parse("2006-01-02", cert.Expire)
	if err != nil {
		return errorFromCode(ErrCertLoadFail)
	}
	if time.Now().After(expire.Add(24 * time.Hour)) {
		return errorFromCode(ErrCertExpired)
	}
	body, err := CertBodyBytes(cert)
	if err != nil {
		return errorFromCode(ErrCertLoadFail)
	}
	pub, err := cert.PublicKeyRSA()
	if err != nil {
		return errorFromCode(ErrCertSigInvalid)
	}
	sig, err := decodeSignature(cert.Sign)
	if err != nil {
		return errorFromCode(ErrCertSigInvalid)
	}
	sum := crypto.Sum256(body)
	if code := crypto.RsaVerifyDigest(sum[:], sig, pub); code != crypto.KRBOK {
		return errorFromCode(code)
	}
	return nil
}

// PublicKeyRSA 从证书的公钥信息中解析出一个RSAKey结构体，返回解析出的RSAKey和错误信息。
func (c *Certificate) PublicKeyRSA() (*crypto.RSAKey, error) {
	n, err := parseBigIntHex(c.PublicKey.N)
	if err != nil {
		return nil, err
	}
	e, err := parseBigIntHex(c.PublicKey.E)
	if err != nil {
		return nil, err
	}
	return &crypto.RSAKey{N: n, E: e}, nil
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

func ParseAPPRepPayload(raw []byte) (APPRepPayload, error) {
	c := NewCursor(raw)
	cipherLen, err := c.ReadUint16()
	if err != nil {
		return APPRepPayload{}, err
	}
	cipher, err := c.ReadBytes(int(cipherLen))
	if err != nil {
		return APPRepPayload{}, err
	}
	sigBytes, err := c.ReadBytes(256)
	if err != nil {
		return APPRepPayload{}, err
	}
	var sig [256]byte
	copy(sig[:], sigBytes)
	return APPRepPayload{
		CipherLen: cipherLen,
		Cipher:    cipher,
		RSASignV:  sig,
	}, nil
}

func DecryptAPPRepPlain(cipherBytes []byte, keyCV [8]byte) (APPRepPlain, error) {
	plain, err := crypto.DecryptDESCBC(keyCV, cipherBytes)
	if err != nil {
		return APPRepPlain{}, errorFromCode(ErrDESDecryptFail)
	}
	c := NewCursor(plain)
	ptyEvent, err := c.ReadBytes(1)
	if err != nil {
		return APPRepPlain{}, err
	}
	ptySessionID, err := c.ReadUint32()
	if err != nil {
		return APPRepPlain{}, err
	}
	exitCode, err := c.ReadUint32()
	if err != nil {
		return APPRepPlain{}, err
	}
	payloadLen, err := c.ReadUint32()
	if err != nil {
		return APPRepPlain{}, err
	}
	payload, err := c.ReadBytes(int(payloadLen))
	if err != nil {
		return APPRepPlain{}, err
	}
	return APPRepPlain{
		PtyEvent:     ptyEvent[0],
		PtySessionID: ptySessionID,
		ExitCode:     int32(exitCode),
		PayloadLen:   payloadLen,
		Payload:      payload,
	}, nil
}

func Hash256(data []byte) [32]byte {
	return crypto.Sum256(data)
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
	sum := crypto.Sum256([]byte(seed + time.Now().UTC().Format(time.RFC3339Nano)))
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
