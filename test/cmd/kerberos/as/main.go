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
	KCHex      string `json:"kc_hex"`
	KTGSHex    string `json:"ktgs_hex"`
	KeyCTGSHex string `json:"key_ctgs_hex"`
	TS1        uint32 `json:"ts1"`
	TS2        uint32 `json:"ts2"`
	Lifetime   uint32 `json:"lifetime"`
}

type output struct {
	ASReqOK          bool   `json:"as_req_ok"`
	ASRepOK          bool   `json:"as_rep_ok"`
	Client           string `json:"client"`
	IDTGS            string `json:"id_tgs"`
	ASReqPacketHex   string `json:"as_req_packet_hex"`
	ASReqPayloadHex  string `json:"as_req_payload_hex"`
	ASRepPacketHex   string `json:"as_rep_packet_hex"`
	ASRepPayloadHex  string `json:"as_rep_payload_hex"`
	TicketCipherHex  string `json:"ticket_cipher_hex"`
	EncPartHex       string `json:"enc_part_hex"`
	ASRepOuterHexLen uint32 `json:"as_rep_outer_len"`
	OK               bool   `json:"ok"`
}

type packetOutput struct {
	OK         bool                 `json:"ok"`
	PacketHex  string               `json:"packet_hex"`
	Header     testio.KRBHeaderJSON `json:"header"`
	PayloadHex string               `json:"payload_hex"`
	ASReq      *asReqParsed         `json:"as_req,omitempty"`
	ASRep      *asRepParsed         `json:"as_rep,omitempty"`
}

type asReqParsed struct {
	IDClient string `json:"id_client"`
	IDTGS    string `json:"id_tgs"`
	TS1      uint32 `json:"ts1"`
}

type asRepParsed struct {
	CipherLen  uint32            `json:"cipher_len"`
	EncPartHex string            `json:"enc_part_hex"`
	Plain      *asRepPlainParsed `json:"plain,omitempty"`
	TicketTGS  *ticketTGSParsed  `json:"ticket_tgs,omitempty"`
}

type asRepPlainParsed struct {
	KeyCTGSHex   string `json:"key_ctgs_hex"`
	IDTGS        string `json:"id_tgs"`
	TS2          uint32 `json:"ts2"`
	Lifetime     uint32 `json:"lifetime"`
	TicketTGSHex string `json:"ticket_tgs_hex"`
}

type ticketTGSParsed struct {
	KeyCTGSHex string `json:"key_ctgs_hex"`
	IDClient   string `json:"id_client"`
	ADC        uint32 `json:"ad_c"`
	IDTGS      string `json:"id_tgs"`
	TS2        uint32 `json:"ts2"`
	Lifetime   uint32 `json:"lifetime"`
}

func main() {
	in := input{
		Client:     "alice",
		ADC:        0xC0A80164,
		IDTGS:      "TGS",
		KCHex:      "1122334455667788",
		KTGSHex:    "8877665544332211",
		KeyCTGSHex: "0123456789abcdef",
		TS1:        1700000001,
		TS2:        1700000002,
		Lifetime:   600,
	}
	if used, err := testio.ReadJSON(&in); err != nil {
		testio.Failf("read input: %v", err)
	} else if used && in.PacketHex != "" {
		parseASPacket(in)
		return
	} else if !used && testio.StdinIsTerminal() {
		runInteractiveAS()
		return
	}

	kc, err := testio.Key8FromHex(in.KCHex)
	if err != nil {
		testio.Failf("parse kc_hex: %v", err)
	}
	ktgs, err := testio.Key8FromHex(in.KTGSHex)
	if err != nil {
		testio.Failf("parse ktgs_hex: %v", err)
	}
	keyCTGS, err := testio.Key8FromHex(in.KeyCTGSHex)
	if err != nil {
		testio.Failf("parse key_ctgs_hex: %v", err)
	}

	reqRaw := buildASReqPayload(in.Client, in.IDTGS, in.TS1)
	reqPacket := krb.PackPacket(krb.MsgASReq, 1, in.TS1, reqRaw)
	req, err := krb.ParseASReqPayload(reqRaw)
	if err != nil {
		testio.Failf("ParseASReqPayload failed: %v", err)
	}
	if string(req.IDClient.Data) != in.Client || string(req.IDTGS.Data) != in.IDTGS || req.TS1 != in.TS1 {
		testio.Failf("AS_REQ mismatch: %+v", req)
	}

	ticketPlain, err := krb.BuildTicketTGSPlain(krb.ASClientSecret{IDClient: in.Client, ADc: in.ADC}, in.IDTGS, keyCTGS, in.TS2, in.Lifetime)
	if err != nil {
		testio.Failf("BuildTicketTGSPlain failed: %v", err)
	}
	ticketCipher, err := cryptoutil.EncryptDESCBC(ktgs, ticketPlain)
	if err != nil {
		testio.Failf("EncryptDESCBC(ticket) failed: %v", err)
	}
	innerPlain, err := krb.BuildASRepPlain(keyCTGS, in.IDTGS, in.TS2, in.Lifetime, ticketCipher)
	if err != nil {
		testio.Failf("BuildASRepPlain failed: %v", err)
	}
	encPart, err := cryptoutil.EncryptDESCBC(kc, innerPlain)
	if err != nil {
		testio.Failf("EncryptDESCBC(as rep) failed: %v", err)
	}
	wire, err := krb.BuildASRepPayload(encPart)
	if err != nil {
		testio.Failf("BuildASRepPayload failed: %v", err)
	}
	repPacket := krb.PackPacket(krb.MsgASRep, 2, in.TS2, wire)
	outer, err := krb.ParseASRepPayload(wire)
	if err != nil {
		testio.Failf("ParseASRepPayload failed: %v", err)
	}
	if outer.CipherLen != uint32(len(encPart)) || !bytes.Equal(outer.EncPart, encPart) {
		testio.Failf("AS_REP outer mismatch")
	}
	plain, err := cryptoutil.DecryptDESCBC(kc, outer.EncPart)
	if err != nil {
		testio.Failf("DecryptDESCBC(as rep) failed: %v", err)
	}
	gotKey, gotIDTGS, gotTS2, gotLifetime, gotTicket, err := decodeASRepPlain(plain)
	if err != nil {
		testio.Failf("decodeASRepPlain failed: %v", err)
	}
	if gotKey != keyCTGS || gotIDTGS != in.IDTGS || gotTS2 != in.TS2 || gotLifetime != in.Lifetime {
		testio.Failf("AS_REP plain mismatch")
	}
	if !bytes.Equal(gotTicket, ticketCipher) {
		testio.Failf("ticket cipher mismatch")
	}
	ticketDecoded, err := cryptoutil.DecryptDESCBC(ktgs, gotTicket)
	if err != nil {
		testio.Failf("DecryptDESCBC(ticket) failed: %v", err)
	}
	decodedClient, decodedIDTGS, decodedTS2, decodedLifetime, decodedADc, err := decodeTicketTGSPlain(ticketDecoded)
	if err != nil {
		testio.Failf("decodeTicketTGSPlain failed: %v", err)
	}
	if decodedClient != in.Client || decodedIDTGS != in.IDTGS || decodedTS2 != in.TS2 || decodedLifetime != in.Lifetime || decodedADc != in.ADC {
		testio.Failf("ticket plain mismatch")
	}

	if err := testio.WriteJSON(output{
		ASReqOK:          true,
		ASRepOK:          true,
		Client:           in.Client,
		IDTGS:            in.IDTGS,
		ASReqPacketHex:   testio.BytesToHex(reqPacket),
		ASReqPayloadHex:  testio.BytesToHex(reqRaw),
		ASRepPacketHex:   testio.BytesToHex(repPacket),
		ASRepPayloadHex:  testio.BytesToHex(wire),
		TicketCipherHex:  testio.BytesToHex(ticketCipher),
		EncPartHex:       testio.BytesToHex(encPart),
		ASRepOuterHexLen: outer.CipherLen,
		OK:               true,
	}); err != nil {
		testio.Failf("write output: %v", err)
	}
}

func runInteractiveAS() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("==================================================")
	fmt.Println(" Kerberos AS 完整封包 Hex 解析")
	fmt.Println("==================================================")
	fmt.Println("[输入] 请粘贴完整 AS_REQ 或 AS_REP 封包 Hex，格式为 20 字节协议头 + payload。")
	packetHex, err := testio.PromptLine(reader, "1. 封包 Hex: ")
	if err != nil {
		testio.Failf("read packet_hex: %v", err)
	}
	kcHex, err := testio.PromptLine(reader, "2. kc_hex（可选，用于解 AS_REP enc_part，直接回车跳过）: ")
	if err != nil {
		testio.Failf("read kc_hex: %v", err)
	}
	ktgsHex, err := testio.PromptLine(reader, "3. ktgs_hex（可选，用于继续解 TicketTGS，直接回车跳过）: ")
	if err != nil {
		testio.Failf("read ktgs_hex: %v", err)
	}
	parseASPacket(input{
		PacketHex: packetHex,
		KCHex:     kcHex,
		KTGSHex:   ktgsHex,
	})
}

func parseASPacket(in input) {
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
	case krb.MsgASReq:
		req, err := krb.ParseASReqPayload(payload)
		if err != nil {
			testio.Failf("ParseASReqPayload failed: %v", err)
		}
		out.ASReq = &asReqParsed{
			IDClient: string(req.IDClient.Data),
			IDTGS:    string(req.IDTGS.Data),
			TS1:      req.TS1,
		}
	case krb.MsgASRep:
		rep, err := krb.ParseASRepPayload(payload)
		if err != nil {
			testio.Failf("ParseASRepPayload failed: %v", err)
		}
		parsed := &asRepParsed{
			CipherLen:  rep.CipherLen,
			EncPartHex: testio.BytesToHex(rep.EncPart),
		}
		if in.KCHex != "" {
			kc, err := testio.Key8FromHex(in.KCHex)
			if err != nil {
				testio.Failf("parse kc_hex: %v", err)
			}
			plain, err := cryptoutil.DecryptDESCBC(kc, rep.EncPart)
			if err != nil {
				testio.Failf("DecryptDESCBC(as rep) failed: %v", err)
			}
			gotKey, gotIDTGS, gotTS2, gotLifetime, gotTicket, err := decodeASRepPlain(plain)
			if err != nil {
				testio.Failf("decodeASRepPlain failed: %v", err)
			}
			parsed.Plain = &asRepPlainParsed{
				KeyCTGSHex:   testio.Key8ToHex(gotKey),
				IDTGS:        gotIDTGS,
				TS2:          gotTS2,
				Lifetime:     gotLifetime,
				TicketTGSHex: testio.BytesToHex(gotTicket),
			}
			if in.KTGSHex != "" {
				ktgs, err := testio.Key8FromHex(in.KTGSHex)
				if err != nil {
					testio.Failf("parse ktgs_hex: %v", err)
				}
				ticket, err := krb.DecodeTicketTGS(gotTicket, ktgs)
				if err != nil {
					testio.Failf("DecodeTicketTGS failed: %v", err)
				}
				parsed.TicketTGS = &ticketTGSParsed{
					KeyCTGSHex: testio.Key8ToHex(ticket.KeyCTGS),
					IDClient:   string(ticket.IDClient.Data),
					ADC:        ticket.ADc,
					IDTGS:      string(ticket.IDTGS.Data),
					TS2:        ticket.TS2,
					Lifetime:   ticket.Lifetime,
				}
			}
		}
		out.ASRep = parsed
	default:
		testio.Failf("unsupported AS message type: %s", testio.KRBMsgTypeName(h.MsgType))
	}
	if err := testio.WriteJSON(out); err != nil {
		testio.Failf("write output: %v", err)
	}
}

func buildASReqPayload(idClient, idTGS string, ts1 uint32) []byte {
	raw := bytes.NewBuffer(nil)
	raw.Write(krb.EncodeKString(idClient))
	raw.Write(krb.EncodeKString(idTGS))
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], ts1)
	raw.Write(tmp[:])
	return raw.Bytes()
}

func decodeASRepPlain(raw []byte) ([8]byte, string, uint32, uint32, []byte, error) {
	var key [8]byte
	if len(raw) < 8 {
		return key, "", 0, 0, nil, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	copy(key[:], raw[:8])
	idTGS, off, err := krb.DecodeKString(raw[8:])
	if err != nil {
		return key, "", 0, 0, nil, err
	}
	if len(raw) < 8+off+12 {
		return key, "", 0, 0, nil, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	base := 8 + off
	ts2 := binary.BigEndian.Uint32(raw[base : base+4])
	lifetime := binary.BigEndian.Uint32(raw[base+4 : base+8])
	ticketLen := binary.BigEndian.Uint32(raw[base+8 : base+12])
	if len(raw) < base+12+int(ticketLen) {
		return key, "", 0, 0, nil, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	return key, string(idTGS.Data), ts2, lifetime, append([]byte(nil), raw[base+12:base+12+int(ticketLen)]...), nil
}

func decodeTicketTGSPlain(raw []byte) (string, string, uint32, uint32, uint32, error) {
	if len(raw) < 8 {
		return "", "", 0, 0, 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	idClient, off, err := krb.DecodeKString(raw[8:])
	if err != nil {
		return "", "", 0, 0, 0, err
	}
	base := 8 + off
	idTGS, off2, err := krb.DecodeKString(raw[base+4:])
	if err != nil {
		return "", "", 0, 0, 0, err
	}
	base = base + 4 + off2
	if len(raw) < base+8 {
		return "", "", 0, 0, 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	ts2 := binary.BigEndian.Uint32(raw[base : base+4])
	lifetime := binary.BigEndian.Uint32(raw[base+4 : base+8])
	adc := binary.BigEndian.Uint32(raw[8+off : 8+off+4])
	return string(idClient.Data), string(idTGS.Data), ts2, lifetime, adc, nil
}
