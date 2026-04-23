package kerberos_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"security-project/common/krb"
)

func TestKerberosASMessages(t *testing.T) {
	kc := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	ktgs := [8]byte{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11}
	client := krb.ASClientSecret{IDClient: "alice", ADc: 0xC0A80164}
	idTGS := "TGS"
	ts1 := uint32(1700000001)
	ts2 := uint32(1700000002)
	lifetime := uint32(600)
	keyCTGS := [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	reqRaw := buildASReqPayload(client.IDClient, idTGS, ts1)
	req, code := krb.ParseASReqPayload(reqRaw)
	if code != krb.KRBOK {
		t.Fatalf("ParseASReqPayload failed: %d", code)
	}
	if string(req.IDClient.Data) != client.IDClient || string(req.IDTGS.Data) != idTGS || req.TS1 != ts1 {
		t.Fatalf("AS_REQ mismatch: %+v", req)
	}

	ticketPlain, code := krb.BuildTicketTGSPlain(client, idTGS, keyCTGS, ts2, lifetime)
	if code != krb.KRBOK {
		t.Fatalf("BuildTicketTGSPlain failed: %d", code)
	}
	ticketCipher, err := krb.EncryptDESCBC(ktgs, ticketPlain)
	if err != nil {
		t.Fatalf("EncryptDESCBC(ticket) failed: %v", err)
	}
	innerPlain, code := krb.BuildASRepPlain(keyCTGS, idTGS, ts2, lifetime, ticketCipher)
	if code != krb.KRBOK {
		t.Fatalf("BuildASRepPlain failed: %d", code)
	}
	encPart, err := krb.EncryptDESCBC(kc, innerPlain)
	if err != nil {
		t.Fatalf("EncryptDESCBC(as rep) failed: %v", err)
	}
	wire, code := krb.BuildASRepPayload(encPart)
	if code != krb.KRBOK {
		t.Fatalf("BuildASRepPayload failed: %d", code)
	}
	outer, code := krb.ParseASRepPayload(wire)
	if code != krb.KRBOK {
		t.Fatalf("ParseASRepPayload failed: %d", code)
	}
	if outer.CipherLen != uint32(len(encPart)) || !bytes.Equal(outer.EncPart, encPart) {
		t.Fatalf("AS_REP outer mismatch")
	}
	plain, err := krb.DecryptDESCBC(kc, outer.EncPart)
	if err != nil {
		t.Fatalf("DecryptDESCBC(as rep) failed: %v", err)
	}
	gotKey, gotIDTGS, gotTS2, gotLifetime, gotTicket, code := decodeASRepPlain(plain)
	if code != krb.KRBOK {
		t.Fatalf("decodeASRepPlain failed: %d", code)
	}
	if gotKey != keyCTGS || gotIDTGS != idTGS || gotTS2 != ts2 || gotLifetime != lifetime {
		t.Fatalf("AS_REP plain mismatch")
	}
	if !bytes.Equal(gotTicket, ticketCipher) {
		t.Fatalf("ticket cipher mismatch")
	}
	ticketDecoded, err := krb.DecryptDESCBC(ktgs, gotTicket)
	if err != nil {
		t.Fatalf("DecryptDESCBC(ticket) failed: %v", err)
	}
	decodedClient, decodedIDTGS, decodedTS2, decodedLifetime, decodedADc, code := decodeTicketTGSPlain(ticketDecoded)
	if code != krb.KRBOK {
		t.Fatalf("decodeTicketTGSPlain failed: %d", code)
	}
	if decodedClient != client.IDClient || decodedIDTGS != idTGS || decodedTS2 != ts2 || decodedLifetime != lifetime || decodedADc != client.ADc {
		t.Fatalf("ticket plain mismatch")
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

func decodeASRepPlain(raw []byte) ([8]byte, string, uint32, uint32, []byte, int32) {
	var key [8]byte
	if len(raw) < 8 {
		return key, "", 0, 0, nil, krb.ErrTicketInvalid
	}
	copy(key[:], raw[:8])
	idTGS, off, code := krb.DecodeKString(raw[8:])
	if code != krb.KRBOK {
		return key, "", 0, 0, nil, code
	}
	if len(raw) < 8+off+12 {
		return key, "", 0, 0, nil, krb.ErrTicketInvalid
	}
	base := 8 + off
	ts2 := binary.BigEndian.Uint32(raw[base : base+4])
	lifetime := binary.BigEndian.Uint32(raw[base+4 : base+8])
	ticketLen := binary.BigEndian.Uint32(raw[base+8 : base+12])
	if len(raw) < base+12+int(ticketLen) {
		return key, "", 0, 0, nil, krb.ErrTicketInvalid
	}
	return key, string(idTGS.Data), ts2, lifetime, append([]byte(nil), raw[base+12:base+12+int(ticketLen)]...), krb.KRBOK
}

func decodeTicketTGSPlain(raw []byte) (string, string, uint32, uint32, uint32, int32) {
	if len(raw) < 8 {
		return "", "", 0, 0, 0, krb.ErrTicketInvalid
	}
	idClient, off, code := krb.DecodeKString(raw[8:])
	if code != krb.KRBOK {
		return "", "", 0, 0, 0, code
	}
	base := 8 + off
	if len(raw) < base+4 {
		return "", "", 0, 0, 0, krb.ErrTicketInvalid
	}
	adc := binary.BigEndian.Uint32(raw[base : base+4])
	idTGS, off2, code := krb.DecodeKString(raw[base+4:])
	if code != krb.KRBOK {
		return "", "", 0, 0, 0, code
	}
	base = base + 4 + off2
	if len(raw) < base+8 {
		return "", "", 0, 0, 0, krb.ErrTicketInvalid
	}
	ts2 := binary.BigEndian.Uint32(raw[base : base+4])
	lifetime := binary.BigEndian.Uint32(raw[base+4 : base+8])
	return string(idClient.Data), string(idTGS.Data), ts2, lifetime, adc, krb.KRBOK
}
