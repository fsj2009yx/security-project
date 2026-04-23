package krb

//msg 定义报文结构体

// 定义协议相关的常量和数据结构
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
)

// KString 是一个简单的结构体，用于表示一个长度前缀字符串。它包含一个 uint16 类型的 Len 字段，表示字符串的长度，以及一个 byte 切片 Data 字段，
// 主要作用是在TCP流中防截包
type KString struct {
	Len  uint16
	Data []byte
}

// ProtocolHeader 是所有通用协议中每个消息的固定长度头部结构，包含了消息的基本信息和控制字段。
type ProtocolHeader struct {
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
