package msg

/*
消息格式定义
*/

// KString 定义了一个长度前缀字符串类型，包含一个 uint16 类型的长度字段和一个字节切片数据字段。
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

// APReqPayload 消息 5：AP_REQ（Client -> V）
type APReqPayload struct {
	TicketVLen uint32 // Ticket_V_Len
	TicketV    []byte // Ticket_V
	AuthLen    uint32 // Auth_Len
	AuthCipher []byte // Authenticator_c(密文)
}

// AuthenticatorCVPlain 消息 5 内层：Authenticator_c 明文
type AuthenticatorCVPlain struct {
	IDClient KString // ID_Client
	ADc      uint32  // AD_c
	TS5      uint32  // TS5
}

// Ticket_V 明文（V 用 Kv 解密）
type TicketVPlain struct {
	KeyCV    [8]byte // Key_c_v
	IDClient KString // ID_Client
	ADc      uint32  // AD_c
	IDV      KString // ID_V
	TS4      uint32  // TS4
	Lifetime uint32  // Lifetime
}

// 消息 6：AP_REP（V -> Client）
type APRepPayloadWire struct {
	CipherLen uint32 // Cipher_Len
	EncPart   []byte // Enc_Part(DES, K_c_v)
}

type APRepPlain struct {
	TS5Plus1 uint32 // TS5 + 1
}

// 消息 7 请求：APP_REQ（Client -> V）
type APPReqPayload struct {
	IDClient  KString   // ID_Client
	CipherLen uint16    // Cipher_Len
	Cipher    []byte    // Cipher_Data
	RSASignC  [256]byte // RSA_Sign_c
}

type APPReqPlain struct {
	PtyOp        uint8  // PTY_Op: OPEN/INPUT/RESIZE/SIGNAL/CLOSE
	PtySessionID uint32 // PTY_Session_ID
	PayloadLen   uint32 // Payload_Len
	Payload      []byte // Payload
}

// 消息 7 响应：APP_REP（V -> Client）
type APPRepPayload struct {
	CipherLen uint16    // Cipher_Len
	Cipher    []byte    // Cipher_Data
	RSASignV  [256]byte // RSA_Sign_v
}

type APPRepPlain struct {
	PtyEvent     uint8  // PTY_Event: OPEN_OK/OUTPUT/EXIT/ERROR
	PtySessionID uint32 // PTY_Session_ID
	ExitCode     int32  // Exit_Code: 仅 EXIT 事件有效
	PayloadLen   uint32 // Payload_Len
	Payload      []byte // Payload
}
