package kerberos_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	cryptoutil "security-project/common/crypto"
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
	req, err := krb.ParseASReqPayload(reqRaw)
	if err != nil {
		t.Fatalf("ParseASReqPayload failed: %v", err)
	}
	if string(req.IDClient.Data) != client.IDClient || string(req.IDTGS.Data) != idTGS || req.TS1 != ts1 {
		t.Fatalf("AS_REQ mismatch: %+v", req)
	}

	ticketPlain, err := krb.BuildTicketTGSPlain(client, idTGS, keyCTGS, ts2, lifetime)
	if err != nil {
		t.Fatalf("BuildTicketTGSPlain failed: %v", err)
	}
	ticketCipher, err := cryptoutil.EncryptDESCBC(ktgs, ticketPlain)
	if err != nil {
		t.Fatalf("EncryptDESCBC(ticket) failed: %v", err)
	}
	innerPlain, err := krb.BuildASRepPlain(keyCTGS, idTGS, ts2, lifetime, ticketCipher)
	if err != nil {
		t.Fatalf("BuildASRepPlain failed: %v", err)
	}
	encPart, err := cryptoutil.EncryptDESCBC(kc, innerPlain)
	if err != nil {
		t.Fatalf("EncryptDESCBC(as rep) failed: %v", err)
	}
	wire, err := krb.BuildASRepPayload(encPart)
	if err != nil {
		t.Fatalf("BuildASRepPayload failed: %v", err)
	}
	outer, err := krb.ParseASRepPayload(wire)
	if err != nil {
		t.Fatalf("ParseASRepPayload failed: %v", err)
	}
	if outer.CipherLen != uint32(len(encPart)) || !bytes.Equal(outer.EncPart, encPart) {
		t.Fatalf("AS_REP outer mismatch")
	}
	plain, err := cryptoutil.DecryptDESCBC(kc, outer.EncPart)
	if err != nil {
		t.Fatalf("DecryptDESCBC(as rep) failed: %v", err)
	}
	gotKey, gotIDTGS, gotTS2, gotLifetime, gotTicket, err := decodeASRepPlain(plain)
	if err != nil {
		t.Fatalf("decodeASRepPlain failed: %v", err)
	}
	if gotKey != keyCTGS || gotIDTGS != idTGS || gotTS2 != ts2 || gotLifetime != lifetime {
		t.Fatalf("AS_REP plain mismatch")
	}
	if !bytes.Equal(gotTicket, ticketCipher) {
		t.Fatalf("ticket cipher mismatch")
	}
	ticketDecoded, err := cryptoutil.DecryptDESCBC(ktgs, gotTicket)
	if err != nil {
		t.Fatalf("DecryptDESCBC(ticket) failed: %v", err)
	}
	decodedClient, decodedIDTGS, decodedTS2, decodedLifetime, decodedADc, err := decodeTicketTGSPlain(ticketDecoded)
	if err != nil {
		t.Fatalf("decodeTicketTGSPlain failed: %v", err)
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
