package kerberos_test

import (
	"bytes"
	"encoding/binary"
	"testing"

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

	ticketPlain, code := krb.BuildTicketTGSPlain(krb.ASClientSecret{IDClient: client, ADc: adc}, idTGS, keyCTGS, ts2, lifetime)
	if code != krb.KRBOK {
		t.Fatalf("BuildTicketTGSPlain failed: %d", code)
	}
	ticketCipher, err := krb.EncryptDESCBC(ktgs, ticketPlain)
	if err != nil {
		t.Fatalf("EncryptDESCBC(ticket_tgs) failed: %v", err)
	}
	authCipher, err := buildAuthenticatorCTGSCipher(keyCTGS, client, adc, ts3)
	if err != nil {
		t.Fatalf("buildAuthenticatorCTGSCipher failed: %v", err)
	}
	reqRaw := buildTGSReqPayload(idV, ticketCipher, authCipher)
	req, code := krb.ParseTGSReqPayload(reqRaw)
	if code != krb.KRBOK {
		t.Fatalf("ParseTGSReqPayload failed: %d", code)
	}
	if string(req.IDV.Data) != idV || !bytes.Equal(req.TicketTGS, ticketCipher) || !bytes.Equal(req.AuthCipher, authCipher) {
		t.Fatalf("TGS_REQ mismatch")
	}

	ticketDecoded, code := krb.DecodeTicketTGS(req.TicketTGS, ktgs)
	if code != krb.KRBOK {
		t.Fatalf("DecodeTicketTGS failed: %d", code)
	}
	authDecoded, code := krb.DecodeAuthenticatorCTGS(req.AuthCipher, ticketDecoded.KeyCTGS)
	if code != krb.KRBOK {
		t.Fatalf("DecodeAuthenticatorCTGS failed: %d", code)
	}
	if string(ticketDecoded.IDClient.Data) != client || ticketDecoded.ADc != adc || string(ticketDecoded.IDTGS.Data) != idTGS || ticketDecoded.TS2 != ts2 || ticketDecoded.Lifetime != lifetime {
		t.Fatalf("ticket_tgs mismatch")
	}
	if string(authDecoded.IDClient.Data) != client || authDecoded.ADc != adc || authDecoded.TS3 != ts3 {
		t.Fatalf("authenticator_ctgs mismatch")
	}

	ticketVPlain, code := krb.BuildTicketVPlain(client, adc, idV, keyCV, ts4, lifetime)
	if code != krb.KRBOK {
		t.Fatalf("BuildTicketVPlain failed: %d", code)
	}
	ticketVCipher, err := krb.EncryptDESCBC(kv, ticketVPlain)
	if err != nil {
		t.Fatalf("EncryptDESCBC(ticket_v) failed: %v", err)
	}
	innerPlain, code := krb.BuildTGSRepPlain(keyCV, idV, ts4, lifetime, ticketVCipher)
	if code != krb.KRBOK {
		t.Fatalf("BuildTGSRepPlain failed: %d", code)
	}
	encPart, err := krb.EncryptDESCBC(keyCTGS, innerPlain)
	if err != nil {
		t.Fatalf("EncryptDESCBC(tgs rep) failed: %v", err)
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
		t.Fatalf("TGS_REP outer mismatch")
	}
	plain, err := krb.DecryptDESCBC(keyCTGS, outer.EncPart)
	if err != nil {
		t.Fatalf("DecryptDESCBC(tgs rep) failed: %v", err)
	}
	gotKey, gotIDV, gotTS4, gotLifetime, gotTicket, code := decodeTGSRepPlain(plain)
	if code != krb.KRBOK {
		t.Fatalf("decodeTGSRepPlain failed: %d", code)
	}
	if gotKey != keyCV || gotIDV != idV || gotTS4 != ts4 || gotLifetime != lifetime {
		t.Fatalf("TGS_REP plain mismatch")
	}
	if !bytes.Equal(gotTicket, ticketVCipher) {
		t.Fatalf("ticket_v cipher mismatch")
	}
	ticketVDecoded, err := krb.DecryptDESCBC(kv, gotTicket)
	if err != nil {
		t.Fatalf("DecryptDESCBC(ticket_v) failed: %v", err)
	}
	client2, adc2, idV2, ts42, lifetime2, code := decodeTicketVPlain(ticketVDecoded)
	if code != krb.KRBOK {
		t.Fatalf("decodeTicketVPlain failed: %d", code)
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
	return krb.EncryptDESCBC(key, raw.Bytes())
}

func decodeTGSRepPlain(raw []byte) ([8]byte, string, uint32, uint32, []byte, int32) {
	var key [8]byte
	if len(raw) < 8 {
		return key, "", 0, 0, nil, krb.ErrTicketInvalid
	}
	copy(key[:], raw[:8])
	idV, off, code := krb.DecodeKString(raw[8:])
	if code != krb.KRBOK {
		return key, "", 0, 0, nil, code
	}
	base := 8 + off
	if len(raw) < base+12 {
		return key, "", 0, 0, nil, krb.ErrTicketInvalid
	}
	ts4 := binary.BigEndian.Uint32(raw[base : base+4])
	lifetime := binary.BigEndian.Uint32(raw[base+4 : base+8])
	ticketLen := binary.BigEndian.Uint32(raw[base+8 : base+12])
	if len(raw) < base+12+int(ticketLen) {
		return key, "", 0, 0, nil, krb.ErrTicketInvalid
	}
	return key, string(idV.Data), ts4, lifetime, append([]byte(nil), raw[base+12:base+12+int(ticketLen)]...), krb.KRBOK
}

func decodeTicketVPlain(raw []byte) (string, uint32, string, uint32, uint32, int32) {
	if len(raw) < 8 {
		return "", 0, "", 0, 0, krb.ErrTicketInvalid
	}
	idClient, off, code := krb.DecodeKString(raw[8:])
	if code != krb.KRBOK {
		return "", 0, "", 0, 0, code
	}
	base := 8 + off
	if len(raw) < base+4 {
		return "", 0, "", 0, 0, krb.ErrTicketInvalid
	}
	adc := binary.BigEndian.Uint32(raw[base : base+4])
	idV, off2, code := krb.DecodeKString(raw[base+4:])
	if code != krb.KRBOK {
		return "", 0, "", 0, 0, code
	}
	base = base + 4 + off2
	if len(raw) < base+8 {
		return "", 0, "", 0, 0, krb.ErrTicketInvalid
	}
	ts4 := binary.BigEndian.Uint32(raw[base : base+4])
	lifetime := binary.BigEndian.Uint32(raw[base+4 : base+8])
	return string(idClient.Data), adc, string(idV.Data), ts4, lifetime, krb.KRBOK
}
