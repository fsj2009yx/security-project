package kerberos_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	cryptoutil "security-project/common/crypto"
	"security-project/common/krb"
)

func TestKerberosAPMessages(t *testing.T) {
	kv := [8]byte{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68}
	keyCV := [8]byte{0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78}
	client := "alice"
	idV := "verify"
	adc := uint32(0xC0A80164)
	ts4 := uint32(1700000204)
	ts5 := uint32(1700000205)
	lifetime := uint32(1200)

	ticketVPlain, err := krb.BuildTicketVPlain(client, adc, idV, keyCV, ts4, lifetime)
	if err != nil {
		t.Fatalf("BuildTicketVPlain failed: %v", err)
	}
	ticketVCipher, err := cryptoutil.EncryptDESCBC(kv, ticketVPlain)
	if err != nil {
		t.Fatalf("EncryptDESCBC(ticket_v) failed: %v", err)
	}
	authCipher, err := buildAuthenticatorCVCipher(keyCV, client, adc, ts5)
	if err != nil {
		t.Fatalf("buildAuthenticatorCVCipher failed: %v", err)
	}
	reqRaw := buildAPReqPayload(ticketVCipher, authCipher)
	req, err := krb.ParseAPReqPayload(reqRaw)
	if err != nil {
		t.Fatalf("ParseAPReqPayload failed: %v", err)
	}
	if !bytes.Equal(req.TicketV, ticketVCipher) || !bytes.Equal(req.AuthCipher, authCipher) {
		t.Fatalf("AP_REQ mismatch")
	}

	ticketDecoded, err := krb.DecodeTicketV(req.TicketV, kv)
	if err != nil {
		t.Fatalf("DecodeTicketV failed: %v", err)
	}
	authDecoded, err := krb.DecodeAuthenticatorCV(req.AuthCipher, ticketDecoded.KeyCV)
	if err != nil {
		t.Fatalf("DecodeAuthenticatorCV failed: %v", err)
	}
	if string(ticketDecoded.IDClient.Data) != client || ticketDecoded.ADc != adc || string(ticketDecoded.IDV.Data) != idV || ticketDecoded.TS4 != ts4 || ticketDecoded.Lifetime != lifetime {
		t.Fatalf("ticket_v mismatch")
	}
	if string(authDecoded.IDClient.Data) != client || authDecoded.ADc != adc || authDecoded.TS5 != ts5 {
		t.Fatalf("authenticator_cv mismatch")
	}

	wire, err := krb.BuildAPRepPayload(ts5, keyCV)
	if err != nil {
		t.Fatalf("BuildAPRepPayload failed: %v", err)
	}
	outer, err := krb.ParseASRepPayload(wire)
	if err != nil {
		t.Fatalf("ParseASRepPayload failed: %v", err)
	}
	plain, err := krb.DecryptAPRepPlain(outer.EncPart, keyCV)
	if err != nil {
		t.Fatalf("DecryptAPRepPlain failed: %v", err)
	}
	if plain.TS5Plus1 != ts5+1 {
		t.Fatalf("AP_REP mismatch: got %d want %d", plain.TS5Plus1, ts5+1)
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
