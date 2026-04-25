package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	cryptoutil "security-project/common/crypto"
	"security-project/common/krb"
	"security-project/test/cmd/internal/testio"
)

type input struct {
	PacketHex string `json:"packet_hex"`
	Client    string `json:"client"`
	ADC       uint32 `json:"ad_c"`
	IDV       string `json:"id_v"`
	KVHex     string `json:"kv_hex"`
	KeyCVHex  string `json:"key_cv_hex"`
	TS4       uint32 `json:"ts4"`
	TS5       uint32 `json:"ts5"`
	Lifetime  uint32 `json:"lifetime"`
}

type output struct {
	APReqOK         bool   `json:"ap_req_ok"`
	APRepOK         bool   `json:"ap_rep_ok"`
	Client          string `json:"client"`
	IDV             string `json:"id_v"`
	APReqPacketHex  string `json:"ap_req_packet_hex"`
	APReqPayloadHex string `json:"ap_req_payload_hex"`
	APRepPacketHex  string `json:"ap_rep_packet_hex"`
	APRepPayloadHex string `json:"ap_rep_payload_hex"`
	TicketVHex      string `json:"ticket_v_hex"`
	AuthCipherHex   string `json:"auth_cipher_hex"`
	APRepTS5Plus1   uint32 `json:"ap_rep_ts5_plus_1"`
	OK              bool   `json:"ok"`
}

type packetOutput struct {
	OK         bool                 `json:"ok"`
	PacketHex  string               `json:"packet_hex"`
	Header     testio.KRBHeaderJSON `json:"header"`
	PayloadHex string               `json:"payload_hex"`
	APReq      *apReqParsed         `json:"ap_req,omitempty"`
	APRep      *apRepParsed         `json:"ap_rep,omitempty"`
}

type apReqParsed struct {
	TicketLen     uint32                 `json:"ticket_len"`
	TicketVHex    string                 `json:"ticket_v_hex"`
	AuthLen       uint32                 `json:"auth_len"`
	AuthHex       string                 `json:"auth_cipher_hex"`
	TicketV       *ticketVParsed         `json:"ticket_v,omitempty"`
	Authenticator *authenticatorCVParsed `json:"authenticator_cv,omitempty"`
}

type ticketVParsed struct {
	KeyCVHex string `json:"key_cv_hex"`
	IDClient string `json:"id_client"`
	ADC      uint32 `json:"ad_c"`
	IDV      string `json:"id_v"`
	TS4      uint32 `json:"ts4"`
	Lifetime uint32 `json:"lifetime"`
}

type authenticatorCVParsed struct {
	IDClient string `json:"id_client"`
	ADC      uint32 `json:"ad_c"`
	TS5      uint32 `json:"ts5"`
}

type apRepParsed struct {
	CipherLen  uint32            `json:"cipher_len"`
	EncPartHex string            `json:"enc_part_hex"`
	Plain      *apRepPlainParsed `json:"plain,omitempty"`
}

type apRepPlainParsed struct {
	TS5Plus1 uint32 `json:"ts5_plus_1"`
}

func main() {
	in := input{
		Client:   "alice",
		ADC:      0xC0A80164,
		IDV:      "verify",
		KVHex:    "6162636465666768",
		KeyCVHex: "7172737475767778",
		TS4:      1700000204,
		TS5:      1700000205,
		Lifetime: 1200,
	}
	if used, err := testio.ReadJSON(&in); err != nil {
		testio.Failf("read input: %v", err)
	} else if used && in.PacketHex != "" {
		parseAPPacket(in)
		return
	} else if !used && testio.StdinIsTerminal() {
		runInteractiveAP()
		return
	}

	kv, err := testio.Key8FromHex(in.KVHex)
	if err != nil {
		testio.Failf("parse kv_hex: %v", err)
	}
	keyCV, err := testio.Key8FromHex(in.KeyCVHex)
	if err != nil {
		testio.Failf("parse key_cv_hex: %v", err)
	}

	ticketVPlain, err := krb.BuildTicketVPlain(in.Client, in.ADC, in.IDV, keyCV, in.TS4, in.Lifetime)
	if err != nil {
		testio.Failf("BuildTicketVPlain failed: %v", err)
	}
	ticketVCipher, err := cryptoutil.EncryptDESCBC(kv, ticketVPlain)
	if err != nil {
		testio.Failf("EncryptDESCBC(ticket_v) failed: %v", err)
	}
	authCipher, err := buildAuthenticatorCVCipher(keyCV, in.Client, in.ADC, in.TS5)
	if err != nil {
		testio.Failf("buildAuthenticatorCVCipher failed: %v", err)
	}
	reqRaw := buildAPReqPayload(ticketVCipher, authCipher)
	reqPacket := krb.PackPacket(krb.MsgAPReq, 5, in.TS5, reqRaw)
	req, err := krb.ParseAPReqPayload(reqRaw)
	if err != nil {
		testio.Failf("ParseAPReqPayload failed: %v", err)
	}
	if !bytes.Equal(req.TicketV, ticketVCipher) || !bytes.Equal(req.AuthCipher, authCipher) {
		testio.Failf("AP_REQ mismatch")
	}

	ticketDecoded, err := krb.DecodeTicketV(req.TicketV, kv)
	if err != nil {
		testio.Failf("DecodeTicketV failed: %v", err)
	}
	authDecoded, err := krb.DecodeAuthenticatorCV(req.AuthCipher, ticketDecoded.KeyCV)
	if err != nil {
		testio.Failf("DecodeAuthenticatorCV failed: %v", err)
	}
	if string(ticketDecoded.IDClient.Data) != in.Client || ticketDecoded.ADc != in.ADC || string(ticketDecoded.IDV.Data) != in.IDV || ticketDecoded.TS4 != in.TS4 || ticketDecoded.Lifetime != in.Lifetime {
		testio.Failf("ticket_v mismatch")
	}
	if string(authDecoded.IDClient.Data) != in.Client || authDecoded.ADc != in.ADC || authDecoded.TS5 != in.TS5 {
		testio.Failf("authenticator_cv mismatch")
	}

	wire, err := krb.BuildAPRepPayload(in.TS5, keyCV)
	if err != nil {
		testio.Failf("BuildAPRepPayload failed: %v", err)
	}
	repPacket := krb.PackPacket(krb.MsgAPRep, 6, in.TS5+1, wire)
	outer, err := krb.ParseASRepPayload(wire)
	if err != nil {
		testio.Failf("ParseASRepPayload failed: %v", err)
	}
	plain, err := krb.DecryptAPRepPlain(outer.EncPart, keyCV)
	if err != nil {
		testio.Failf("DecryptAPRepPlain failed: %v", err)
	}
	if plain.TS5Plus1 != in.TS5+1 {
		testio.Failf("AP_REP mismatch: got %d want %d", plain.TS5Plus1, in.TS5+1)
	}

	if err := testio.WriteJSON(output{
		APReqOK:         true,
		APRepOK:         true,
		Client:          in.Client,
		IDV:             in.IDV,
		APReqPacketHex:  testio.BytesToHex(reqPacket),
		APReqPayloadHex: testio.BytesToHex(reqRaw),
		APRepPacketHex:  testio.BytesToHex(repPacket),
		APRepPayloadHex: testio.BytesToHex(wire),
		TicketVHex:      testio.BytesToHex(ticketVCipher),
		AuthCipherHex:   testio.BytesToHex(authCipher),
		APRepTS5Plus1:   plain.TS5Plus1,
		OK:              true,
	}); err != nil {
		testio.Failf("write output: %v", err)
	}
}

func runInteractiveAP() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("==================================================")
	fmt.Println(" Kerberos AP 完整封包 Hex 解析")
	fmt.Println("==================================================")
	fmt.Println("[输入] 请粘贴完整 AP_REQ 或 AP_REP 封包 Hex，格式为 20 字节协议头 + payload。")
	packetHex, err := testio.PromptLine(reader, "1. 封包 Hex: ")
	if err != nil {
		testio.Failf("read packet_hex: %v", err)
	}
	kvHex, err := testio.PromptLine(reader, "2. kv_hex（可选，用于解 AP_REQ 的 TicketV）: ")
	if err != nil {
		testio.Failf("read kv_hex: %v", err)
	}
	keyCVHex, err := testio.PromptLine(reader, "3. key_cv_hex（可选，用于解 Authenticator/AP_REP enc_part）: ")
	if err != nil {
		testio.Failf("read key_cv_hex: %v", err)
	}
	parseAPPacket(input{
		PacketHex: packetHex,
		KVHex:     kvHex,
		KeyCVHex:  keyCVHex,
	})
}

func parseAPPacket(in input) {
	h, payload, raw, err := testio.ParseKRBPacketHex(in.PacketHex)
	if err != nil {
		testio.Failf("parse packet_hex: %v", err)
	}
	out := packetOutput{
		OK:         true,
		PacketHex:  testio.BytesToHex(raw),
		Header:     testio.KRBHeaderToJSON(h),
		PayloadHex: testio.BytesToHex(payload),
	}
	switch h.MsgType {
	case krb.MsgAPReq:
		req, err := krb.ParseAPReqPayload(payload)
		if err != nil {
			testio.Failf("ParseAPReqPayload failed: %v", err)
		}
		parsed := &apReqParsed{
			TicketLen:  req.TicketVLen,
			TicketVHex: testio.BytesToHex(req.TicketV),
			AuthLen:    req.AuthLen,
			AuthHex:    testio.BytesToHex(req.AuthCipher),
		}
		var keyCV [8]byte
		hasKeyCV := false
		if in.KVHex != "" {
			kv, err := testio.Key8FromHex(in.KVHex)
			if err != nil {
				testio.Failf("parse kv_hex: %v", err)
			}
			ticket, err := krb.DecodeTicketV(req.TicketV, kv)
			if err != nil {
				testio.Failf("DecodeTicketV failed: %v", err)
			}
			keyCV = ticket.KeyCV
			hasKeyCV = true
			parsed.TicketV = &ticketVParsed{
				KeyCVHex: testio.Key8ToHex(ticket.KeyCV),
				IDClient: string(ticket.IDClient.Data),
				ADC:      ticket.ADc,
				IDV:      string(ticket.IDV.Data),
				TS4:      ticket.TS4,
				Lifetime: ticket.Lifetime,
			}
		}
		if in.KeyCVHex != "" {
			keyCV, err = testio.Key8FromHex(in.KeyCVHex)
			if err != nil {
				testio.Failf("parse key_cv_hex: %v", err)
			}
			hasKeyCV = true
		}
		if hasKeyCV {
			auth, err := krb.DecodeAuthenticatorCV(req.AuthCipher, keyCV)
			if err != nil {
				testio.Failf("DecodeAuthenticatorCV failed: %v", err)
			}
			parsed.Authenticator = &authenticatorCVParsed{
				IDClient: string(auth.IDClient.Data),
				ADC:      auth.ADc,
				TS5:      auth.TS5,
			}
		}
		out.APReq = parsed
	case krb.MsgAPRep:
		rep, err := krb.ParseASRepPayload(payload)
		if err != nil {
			testio.Failf("ParseAPRepPayload failed: %v", err)
		}
		parsed := &apRepParsed{
			CipherLen:  rep.CipherLen,
			EncPartHex: testio.BytesToHex(rep.EncPart),
		}
		if in.KeyCVHex != "" {
			keyCV, err := testio.Key8FromHex(in.KeyCVHex)
			if err != nil {
				testio.Failf("parse key_cv_hex: %v", err)
			}
			plain, err := krb.DecryptAPRepPlain(rep.EncPart, keyCV)
			if err != nil {
				testio.Failf("DecryptAPRepPlain failed: %v", err)
			}
			parsed.Plain = &apRepPlainParsed{TS5Plus1: plain.TS5Plus1}
		}
		out.APRep = parsed
	default:
		testio.Failf("unsupported AP message type: %s", testio.KRBMsgTypeName(h.MsgType))
	}
	if err := testio.WriteJSON(out); err != nil {
		testio.Failf("write output: %v", err)
	}
}

func buildAPReqPayload(ticketCipher, authCipher []byte) []byte {
	raw := bytes.NewBuffer(nil)
	var tmp4 [4]byte
	binary.BigEndian.PutUint32(tmp4[:], uint32(len(ticketCipher)))
	raw.Write(tmp4[:])
	raw.Write(ticketCipher)
	binary.BigEndian.PutUint32(tmp4[:], uint32(len(authCipher)))
	raw.Write(tmp4[:])
	raw.Write(authCipher)
	return raw.Bytes()
}

func buildAuthenticatorCVCipher(key [8]byte, client string, adc, ts5 uint32) ([]byte, error) {
	raw := bytes.NewBuffer(nil)
	raw.Write(krb.EncodeKString(client))
	var tmp4 [4]byte
	binary.BigEndian.PutUint32(tmp4[:], adc)
	raw.Write(tmp4[:])
	binary.BigEndian.PutUint32(tmp4[:], ts5)
	raw.Write(tmp4[:])
	return cryptoutil.EncryptDESCBC(key, raw.Bytes())
}
