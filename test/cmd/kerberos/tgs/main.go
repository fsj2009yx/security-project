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
	PacketHex  string `json:"packet_hex"`
	Client     string `json:"client"`
	ADC        uint32 `json:"ad_c"`
	IDTGS      string `json:"id_tgs"`
	IDV        string `json:"id_v"`
	KTGSHex    string `json:"ktgs_hex"`
	KVHex      string `json:"kv_hex"`
	KeyCTGSHex string `json:"key_ctgs_hex"`
	KeyCVHex   string `json:"key_cv_hex"`
	TS2        uint32 `json:"ts2"`
	TS3        uint32 `json:"ts3"`
	TS4        uint32 `json:"ts4"`
	Lifetime   uint32 `json:"lifetime"`
}

type output struct {
	TGSReqOK         bool   `json:"tgs_req_ok"`
	TGSRepOK         bool   `json:"tgs_rep_ok"`
	Client           string `json:"client"`
	IDV              string `json:"id_v"`
	TGSReqPacketHex  string `json:"tgs_req_packet_hex"`
	TGSReqPayloadHex string `json:"tgs_req_payload_hex"`
	TGSRepPacketHex  string `json:"tgs_rep_packet_hex"`
	TGSRepPayloadHex string `json:"tgs_rep_payload_hex"`
	TicketTGSHex     string `json:"ticket_tgs_hex"`
	TicketVHex       string `json:"ticket_v_hex"`
	EncPartHex       string `json:"enc_part_hex"`
	OK               bool   `json:"ok"`
}

type packetOutput struct {
	OK         bool                 `json:"ok"`
	PacketHex  string               `json:"packet_hex"`
	Header     testio.KRBHeaderJSON `json:"header"`
	PayloadHex string               `json:"payload_hex"`
	TGSReq     *tgsReqParsed        `json:"tgs_req,omitempty"`
	TGSRep     *tgsRepParsed        `json:"tgs_rep,omitempty"`
}

type tgsReqParsed struct {
	IDV           string                   `json:"id_v"`
	TicketLen     uint32                   `json:"ticket_len"`
	TicketTGSHex  string                   `json:"ticket_tgs_hex"`
	AuthLen       uint32                   `json:"auth_len"`
	AuthHex       string                   `json:"auth_cipher_hex"`
	TicketTGS     *ticketTGSParsed         `json:"ticket_tgs,omitempty"`
	Authenticator *authenticatorCTGSParsed `json:"authenticator_ctgs,omitempty"`
}

type ticketTGSParsed struct {
	KeyCTGSHex string `json:"key_ctgs_hex"`
	IDClient   string `json:"id_client"`
	ADC        uint32 `json:"ad_c"`
	IDTGS      string `json:"id_tgs"`
	TS2        uint32 `json:"ts2"`
	Lifetime   uint32 `json:"lifetime"`
}

type authenticatorCTGSParsed struct {
	IDClient string `json:"id_client"`
	ADC      uint32 `json:"ad_c"`
	TS3      uint32 `json:"ts3"`
}

type tgsRepParsed struct {
	CipherLen  uint32             `json:"cipher_len"`
	EncPartHex string             `json:"enc_part_hex"`
	Plain      *tgsRepPlainParsed `json:"plain,omitempty"`
	TicketV    *ticketVParsed     `json:"ticket_v,omitempty"`
}

type tgsRepPlainParsed struct {
	KeyCVHex   string `json:"key_cv_hex"`
	IDV        string `json:"id_v"`
	TS4        uint32 `json:"ts4"`
	Lifetime   uint32 `json:"lifetime"`
	TicketVHex string `json:"ticket_v_hex"`
}

type ticketVParsed struct {
	KeyCVHex string `json:"key_cv_hex"`
	IDClient string `json:"id_client"`
	ADC      uint32 `json:"ad_c"`
	IDV      string `json:"id_v"`
	TS4      uint32 `json:"ts4"`
	Lifetime uint32 `json:"lifetime"`
}

func main() {
	in := input{
		Client:     "alice",
		ADC:        0xC0A80164,
		IDTGS:      "TGS",
		IDV:        "verify",
		KTGSHex:    "2827262524232221",
		KVHex:      "3132333435363738",
		KeyCTGSHex: "4142434445464748",
		KeyCVHex:   "5152535455565758",
		TS2:        1700000102,
		TS3:        1700000103,
		TS4:        1700000104,
		Lifetime:   900,
	}
	if used, err := testio.ReadJSON(&in); err != nil {
		testio.Failf("read input: %v", err)
	} else if used && in.PacketHex != "" {
		parseTGSPacket(in)
		return
	} else if !used && testio.StdinIsTerminal() {
		runInteractiveTGS()
		return
	}

	ktgs, err := testio.Key8FromHex(in.KTGSHex)
	if err != nil {
		testio.Failf("parse ktgs_hex: %v", err)
	}
	kv, err := testio.Key8FromHex(in.KVHex)
	if err != nil {
		testio.Failf("parse kv_hex: %v", err)
	}
	keyCTGS, err := testio.Key8FromHex(in.KeyCTGSHex)
	if err != nil {
		testio.Failf("parse key_ctgs_hex: %v", err)
	}
	keyCV, err := testio.Key8FromHex(in.KeyCVHex)
	if err != nil {
		testio.Failf("parse key_cv_hex: %v", err)
	}

	ticketPlain, err := krb.BuildTicketTGSPlain(krb.ASClientSecret{IDClient: in.Client, ADc: in.ADC}, in.IDTGS, keyCTGS, in.TS2, in.Lifetime)
	if err != nil {
		testio.Failf("BuildTicketTGSPlain failed: %v", err)
	}
	ticketCipher, err := cryptoutil.EncryptDESCBC(ktgs, ticketPlain)
	if err != nil {
		testio.Failf("EncryptDESCBC(ticket_tgs) failed: %v", err)
	}
	authCipher, err := buildAuthenticatorCTGSCipher(keyCTGS, in.Client, in.ADC, in.TS3)
	if err != nil {
		testio.Failf("buildAuthenticatorCTGSCipher failed: %v", err)
	}
	reqRaw := buildTGSReqPayload(in.IDV, ticketCipher, authCipher)
	reqPacket := krb.PackPacket(krb.MsgTGSReq, 3, in.TS3, reqRaw)
	req, err := krb.ParseTGSReqPayload(reqRaw)
	if err != nil {
		testio.Failf("ParseTGSReqPayload failed: %v", err)
	}
	if string(req.IDV.Data) != in.IDV || !bytes.Equal(req.TicketTGS, ticketCipher) || !bytes.Equal(req.AuthCipher, authCipher) {
		testio.Failf("TGS_REQ mismatch")
	}

	ticketDecoded, err := krb.DecodeTicketTGS(req.TicketTGS, ktgs)
	if err != nil {
		testio.Failf("DecodeTicketTGS failed: %v", err)
	}
	authDecoded, err := krb.DecodeAuthenticatorCTGS(req.AuthCipher, ticketDecoded.KeyCTGS)
	if err != nil {
		testio.Failf("DecodeAuthenticatorCTGS failed: %v", err)
	}
	if string(ticketDecoded.IDClient.Data) != in.Client || ticketDecoded.ADc != in.ADC || string(ticketDecoded.IDTGS.Data) != in.IDTGS || ticketDecoded.TS2 != in.TS2 || ticketDecoded.Lifetime != in.Lifetime {
		testio.Failf("ticket_tgs mismatch")
	}
	if string(authDecoded.IDClient.Data) != in.Client || authDecoded.ADc != in.ADC || authDecoded.TS3 != in.TS3 {
		testio.Failf("authenticator_ctgs mismatch")
	}

	ticketVPlain, err := krb.BuildTicketVPlain(in.Client, in.ADC, in.IDV, keyCV, in.TS4, in.Lifetime)
	if err != nil {
		testio.Failf("BuildTicketVPlain failed: %v", err)
	}
	ticketVCipher, err := cryptoutil.EncryptDESCBC(kv, ticketVPlain)
	if err != nil {
		testio.Failf("EncryptDESCBC(ticket_v) failed: %v", err)
	}
	innerPlain, err := krb.BuildTGSRepPlain(keyCV, in.IDV, in.TS4, in.Lifetime, ticketVCipher)
	if err != nil {
		testio.Failf("BuildTGSRepPlain failed: %v", err)
	}
	encPart, err := cryptoutil.EncryptDESCBC(keyCTGS, innerPlain)
	if err != nil {
		testio.Failf("EncryptDESCBC(tgs rep) failed: %v", err)
	}
	wire, err := krb.BuildASRepPayload(encPart)
	if err != nil {
		testio.Failf("BuildASRepPayload failed: %v", err)
	}
	repPacket := krb.PackPacket(krb.MsgTGSRep, 4, in.TS4, wire)
	outer, err := krb.ParseASRepPayload(wire)
	if err != nil {
		testio.Failf("ParseASRepPayload failed: %v", err)
	}
	if outer.CipherLen != uint32(len(encPart)) || !bytes.Equal(outer.EncPart, encPart) {
		testio.Failf("TGS_REP outer mismatch")
	}
	plain, err := cryptoutil.DecryptDESCBC(keyCTGS, outer.EncPart)
	if err != nil {
		testio.Failf("DecryptDESCBC(tgs rep) failed: %v", err)
	}
	gotKey, gotIDV, gotTS4, gotLifetime, gotTicket, err := decodeTGSRepPlain(plain)
	if err != nil {
		testio.Failf("decodeTGSRepPlain failed: %v", err)
	}
	if gotKey != keyCV || gotIDV != in.IDV || gotTS4 != in.TS4 || gotLifetime != in.Lifetime {
		testio.Failf("TGS_REP plain mismatch")
	}
	if !bytes.Equal(gotTicket, ticketVCipher) {
		testio.Failf("ticket_v cipher mismatch")
	}
	ticketVDecoded, err := cryptoutil.DecryptDESCBC(kv, gotTicket)
	if err != nil {
		testio.Failf("DecryptDESCBC(ticket_v) failed: %v", err)
	}
	client2, adc2, idV2, ts42, lifetime2, err := decodeTicketVPlain(ticketVDecoded)
	if err != nil {
		testio.Failf("decodeTicketVPlain failed: %v", err)
	}
	if client2 != in.Client || adc2 != in.ADC || idV2 != in.IDV || ts42 != in.TS4 || lifetime2 != in.Lifetime {
		testio.Failf("ticket_v mismatch")
	}

	if err := testio.WriteJSON(output{
		TGSReqOK:         true,
		TGSRepOK:         true,
		Client:           in.Client,
		IDV:              in.IDV,
		TGSReqPacketHex:  testio.BytesToHex(reqPacket),
		TGSReqPayloadHex: testio.BytesToHex(reqRaw),
		TGSRepPacketHex:  testio.BytesToHex(repPacket),
		TGSRepPayloadHex: testio.BytesToHex(wire),
		TicketTGSHex:     testio.BytesToHex(ticketCipher),
		TicketVHex:       testio.BytesToHex(ticketVCipher),
		EncPartHex:       testio.BytesToHex(encPart),
		OK:               true,
	}); err != nil {
		testio.Failf("write output: %v", err)
	}
}

func runInteractiveTGS() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("==================================================")
	fmt.Println(" Kerberos TGS 完整封包 Hex 解析")
	fmt.Println("==================================================")
	fmt.Println("[输入] 请粘贴完整 TGS_REQ 或 TGS_REP 封包 Hex，格式为 20 字节协议头 + payload。")
	packetHex, err := testio.PromptLine(reader, "1. 封包 Hex: ")
	if err != nil {
		testio.Failf("read packet_hex: %v", err)
	}
	ktgsHex, err := testio.PromptLine(reader, "2. ktgs_hex（可选，用于解 TGS_REQ 的 TicketTGS）: ")
	if err != nil {
		testio.Failf("read ktgs_hex: %v", err)
	}
	keyCTGSHex, err := testio.PromptLine(reader, "3. key_ctgs_hex（可选，用于解 Authenticator/TGS_REP enc_part）: ")
	if err != nil {
		testio.Failf("read key_ctgs_hex: %v", err)
	}
	kvHex, err := testio.PromptLine(reader, "4. kv_hex（可选，用于继续解 TicketV）: ")
	if err != nil {
		testio.Failf("read kv_hex: %v", err)
	}
	parseTGSPacket(input{
		PacketHex:  packetHex,
		KTGSHex:    ktgsHex,
		KeyCTGSHex: keyCTGSHex,
		KVHex:      kvHex,
	})
}

func parseTGSPacket(in input) {
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
	case krb.MsgTGSReq:
		req, err := krb.ParseTGSReqPayload(payload)
		if err != nil {
			testio.Failf("ParseTGSReqPayload failed: %v", err)
		}
		parsed := &tgsReqParsed{
			IDV:          string(req.IDV.Data),
			TicketLen:    req.TicketLen,
			TicketTGSHex: testio.BytesToHex(req.TicketTGS),
			AuthLen:      req.AuthLen,
			AuthHex:      testio.BytesToHex(req.AuthCipher),
		}
		var keyCTGS [8]byte
		hasKeyCTGS := false
		if in.KTGSHex != "" {
			ktgs, err := testio.Key8FromHex(in.KTGSHex)
			if err != nil {
				testio.Failf("parse ktgs_hex: %v", err)
			}
			ticket, err := krb.DecodeTicketTGS(req.TicketTGS, ktgs)
			if err != nil {
				testio.Failf("DecodeTicketTGS failed: %v", err)
			}
			keyCTGS = ticket.KeyCTGS
			hasKeyCTGS = true
			parsed.TicketTGS = &ticketTGSParsed{
				KeyCTGSHex: testio.Key8ToHex(ticket.KeyCTGS),
				IDClient:   string(ticket.IDClient.Data),
				ADC:        ticket.ADc,
				IDTGS:      string(ticket.IDTGS.Data),
				TS2:        ticket.TS2,
				Lifetime:   ticket.Lifetime,
			}
		}
		if in.KeyCTGSHex != "" {
			keyCTGS, err = testio.Key8FromHex(in.KeyCTGSHex)
			if err != nil {
				testio.Failf("parse key_ctgs_hex: %v", err)
			}
			hasKeyCTGS = true
		}
		if hasKeyCTGS {
			auth, err := krb.DecodeAuthenticatorCTGS(req.AuthCipher, keyCTGS)
			if err != nil {
				testio.Failf("DecodeAuthenticatorCTGS failed: %v", err)
			}
			parsed.Authenticator = &authenticatorCTGSParsed{
				IDClient: string(auth.IDClient.Data),
				ADC:      auth.ADc,
				TS3:      auth.TS3,
			}
		}
		out.TGSReq = parsed
	case krb.MsgTGSRep:
		rep, err := krb.ParseASRepPayload(payload)
		if err != nil {
			testio.Failf("ParseTGSRepPayload failed: %v", err)
		}
		parsed := &tgsRepParsed{
			CipherLen:  rep.CipherLen,
			EncPartHex: testio.BytesToHex(rep.EncPart),
		}
		if in.KeyCTGSHex != "" {
			keyCTGS, err := testio.Key8FromHex(in.KeyCTGSHex)
			if err != nil {
				testio.Failf("parse key_ctgs_hex: %v", err)
			}
			plain, err := cryptoutil.DecryptDESCBC(keyCTGS, rep.EncPart)
			if err != nil {
				testio.Failf("DecryptDESCBC(tgs rep) failed: %v", err)
			}
			gotKey, gotIDV, gotTS4, gotLifetime, gotTicket, err := decodeTGSRepPlain(plain)
			if err != nil {
				testio.Failf("decodeTGSRepPlain failed: %v", err)
			}
			parsed.Plain = &tgsRepPlainParsed{
				KeyCVHex:   testio.Key8ToHex(gotKey),
				IDV:        gotIDV,
				TS4:        gotTS4,
				Lifetime:   gotLifetime,
				TicketVHex: testio.BytesToHex(gotTicket),
			}
			if in.KVHex != "" {
				kv, err := testio.Key8FromHex(in.KVHex)
				if err != nil {
					testio.Failf("parse kv_hex: %v", err)
				}
				ticket, err := krb.DecodeTicketV(gotTicket, kv)
				if err != nil {
					testio.Failf("DecodeTicketV failed: %v", err)
				}
				parsed.TicketV = &ticketVParsed{
					KeyCVHex: testio.Key8ToHex(ticket.KeyCV),
					IDClient: string(ticket.IDClient.Data),
					ADC:      ticket.ADc,
					IDV:      string(ticket.IDV.Data),
					TS4:      ticket.TS4,
					Lifetime: ticket.Lifetime,
				}
			}
		}
		out.TGSRep = parsed
	default:
		testio.Failf("unsupported TGS message type: %s", testio.KRBMsgTypeName(h.MsgType))
	}
	if err := testio.WriteJSON(out); err != nil {
		testio.Failf("write output: %v", err)
	}
}

func buildTGSReqPayload(idV string, ticketCipher, authCipher []byte) []byte {
	raw := bytes.NewBuffer(nil)
	raw.Write(krb.EncodeKString(idV))
	var tmp4 [4]byte
	binary.BigEndian.PutUint32(tmp4[:], uint32(len(ticketCipher)))
	raw.Write(tmp4[:])
	raw.Write(ticketCipher)
	binary.BigEndian.PutUint32(tmp4[:], uint32(len(authCipher)))
	raw.Write(tmp4[:])
	raw.Write(authCipher)
	return raw.Bytes()
}

func buildAuthenticatorCTGSCipher(key [8]byte, client string, adc, ts3 uint32) ([]byte, error) {
	raw := bytes.NewBuffer(nil)
	raw.Write(krb.EncodeKString(client))
	var tmp4 [4]byte
	binary.BigEndian.PutUint32(tmp4[:], adc)
	raw.Write(tmp4[:])
	binary.BigEndian.PutUint32(tmp4[:], ts3)
	raw.Write(tmp4[:])
	return cryptoutil.EncryptDESCBC(key, raw.Bytes())
}

func decodeTGSRepPlain(raw []byte) ([8]byte, string, uint32, uint32, []byte, error) {
	var key [8]byte
	if len(raw) < 8 {
		return key, "", 0, 0, nil, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	copy(key[:], raw[:8])
	idV, off, err := krb.DecodeKString(raw[8:])
	if err != nil {
		return key, "", 0, 0, nil, err
	}
	base := 8 + off
	if len(raw) < base+12 {
		return key, "", 0, 0, nil, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	ts4 := binary.BigEndian.Uint32(raw[base : base+4])
	lifetime := binary.BigEndian.Uint32(raw[base+4 : base+8])
	ticketLen := binary.BigEndian.Uint32(raw[base+8 : base+12])
	if len(raw) < base+12+int(ticketLen) {
		return key, "", 0, 0, nil, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	return key, string(idV.Data), ts4, lifetime, append([]byte(nil), raw[base+12:base+12+int(ticketLen)]...), nil
}

func decodeTicketVPlain(raw []byte) (string, uint32, string, uint32, uint32, error) {
	if len(raw) < 8 {
		return "", 0, "", 0, 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	idClient, off, err := krb.DecodeKString(raw[8:])
	if err != nil {
		return "", 0, "", 0, 0, err
	}
	base := 8 + off
	if len(raw) < base+12 {
		return "", 0, "", 0, 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	adc := binary.BigEndian.Uint32(raw[base : base+4])
	idV, off2, err := krb.DecodeKString(raw[base+4:])
	if err != nil {
		return "", 0, "", 0, 0, err
	}
	base = base + 4 + off2
	if len(raw) < base+8 {
		return "", 0, "", 0, 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	ts4 := binary.BigEndian.Uint32(raw[base : base+4])
	lifetime := binary.BigEndian.Uint32(raw[base+4 : base+8])
	return string(idClient.Data), adc, string(idV.Data), ts4, lifetime, nil
}
