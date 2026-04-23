package kerberos_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	cryptoutil "security-project/common/crypto"
	"security-project/common/krb"
)

func TestKerberosTGSMessages(t *testing.T) {
	ktgs := [8]byte{0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21}
	kv := [8]byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
	client := "alice"
	idV := "verify"
	idTGS := "TGS"
	adc := uint32(0xC0A80164)
	ts2 := uint32(1700000102)
	ts3 := uint32(1700000103)
	ts4 := uint32(1700000104)
	lifetime := uint32(900)
	keyCTGS := [8]byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48}
	keyCV := [8]byte{0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58}

	ticketPlain, err := krb.BuildTicketTGSPlain(krb.ASClientSecret{IDClient: client, ADc: adc}, idTGS, keyCTGS, ts2, lifetime)
	if err != nil {
		t.Fatalf("BuildTicketTGSPlain failed: %v", err)
	}
	ticketCipher, err := cryptoutil.EncryptDESCBC(ktgs, ticketPlain)
	if err != nil {
		t.Fatalf("EncryptDESCBC(ticket_tgs) failed: %v", err)
	}
	authCipher, err := buildAuthenticatorCTGSCipher(keyCTGS, client, adc, ts3)
	if err != nil {
		t.Fatalf("buildAuthenticatorCTGSCipher failed: %v", err)
	}
	reqRaw := buildTGSReqPayload(idV, ticketCipher, authCipher)
	req, err := krb.ParseTGSReqPayload(reqRaw)
	if err != nil {
		t.Fatalf("ParseTGSReqPayload failed: %v", err)
	}
	if string(req.IDV.Data) != idV || !bytes.Equal(req.TicketTGS, ticketCipher) || !bytes.Equal(req.AuthCipher, authCipher) {
		t.Fatalf("TGS_REQ mismatch")
	}

	ticketDecoded, err := krb.DecodeTicketTGS(req.TicketTGS, ktgs)
	if err != nil {
		t.Fatalf("DecodeTicketTGS failed: %v", err)
	}
	authDecoded, err := krb.DecodeAuthenticatorCTGS(req.AuthCipher, ticketDecoded.KeyCTGS)
	if err != nil {
		t.Fatalf("DecodeAuthenticatorCTGS failed: %v", err)
	}
	if string(ticketDecoded.IDClient.Data) != client || ticketDecoded.ADc != adc || string(ticketDecoded.IDTGS.Data) != idTGS || ticketDecoded.TS2 != ts2 || ticketDecoded.Lifetime != lifetime {
		t.Fatalf("ticket_tgs mismatch")
	}
	if string(authDecoded.IDClient.Data) != client || authDecoded.ADc != adc || authDecoded.TS3 != ts3 {
		t.Fatalf("authenticator_ctgs mismatch")
	}

	ticketVPlain, err := krb.BuildTicketVPlain(client, adc, idV, keyCV, ts4, lifetime)
	if err != nil {
		t.Fatalf("BuildTicketVPlain failed: %v", err)
	}
	ticketVCipher, err := cryptoutil.EncryptDESCBC(kv, ticketVPlain)
	if err != nil {
		t.Fatalf("EncryptDESCBC(ticket_v) failed: %v", err)
	}
	innerPlain, err := krb.BuildTGSRepPlain(keyCV, idV, ts4, lifetime, ticketVCipher)
	if err != nil {
		t.Fatalf("BuildTGSRepPlain failed: %v", err)
	}
	encPart, err := cryptoutil.EncryptDESCBC(keyCTGS, innerPlain)
	if err != nil {
		t.Fatalf("EncryptDESCBC(tgs rep) failed: %v", err)
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
		t.Fatalf("TGS_REP outer mismatch")
	}
	plain, err := cryptoutil.DecryptDESCBC(keyCTGS, outer.EncPart)
	if err != nil {
		t.Fatalf("DecryptDESCBC(tgs rep) failed: %v", err)
	}
	gotKey, gotIDV, gotTS4, gotLifetime, gotTicket, err := decodeTGSRepPlain(plain)
	if err != nil {
		t.Fatalf("decodeTGSRepPlain failed: %v", err)
	}
	if gotKey != keyCV || gotIDV != idV || gotTS4 != ts4 || gotLifetime != lifetime {
		t.Fatalf("TGS_REP plain mismatch")
	}
	if !bytes.Equal(gotTicket, ticketVCipher) {
		t.Fatalf("ticket_v cipher mismatch")
	}
	ticketVDecoded, err := cryptoutil.DecryptDESCBC(kv, gotTicket)
	if err != nil {
		t.Fatalf("DecryptDESCBC(ticket_v) failed: %v", err)
	}
	client2, adc2, idV2, ts42, lifetime2, err := decodeTicketVPlain(ticketVDecoded)
	if err != nil {
		t.Fatalf("decodeTicketVPlain failed: %v", err)
	}
	if client2 != client || adc2 != adc || idV2 != idV || ts42 != ts4 || lifetime2 != lifetime {
		t.Fatalf("ticket_v mismatch")
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
