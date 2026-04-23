package krb

import (
	"bytes"
	"encoding/binary"
	"math/big"
)

var rsaSHA256DigestInfoPrefix = []byte{
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
	0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
}

type RSAKey struct {
	N *big.Int
	E *big.Int
	D *big.Int
}

func (k *RSAKey) PublicKey() *RSAKey {
	if k == nil || k.N == nil || k.E == nil {
		return nil
	}
	return &RSAKey{
		N: new(big.Int).Set(k.N),
		E: new(big.Int).Set(k.E),
	}
}

func (k *RSAKey) IsPrivate() bool {
	return k != nil && k.N != nil && k.D != nil && k.E != nil
}

func rsaModExp(base, exp, mod *big.Int) *big.Int {
	if base == nil || exp == nil || mod == nil || mod.Sign() <= 0 {
		return nil
	}
	result := big.NewInt(1)
	baseMod := new(big.Int).Mod(new(big.Int).Set(base), mod)
	if baseMod.Sign() < 0 {
		baseMod.Add(baseMod, mod)
	}
	for i := exp.BitLen() - 1; i >= 0; i-- {
		result.Mul(result, result)
		result.Mod(result, mod)
		if exp.Bit(i) == 1 {
			result.Mul(result, baseMod)
			result.Mod(result, mod)
		}
	}
	return result
}

func rsaModBytes(modexp *big.Int, size int) []byte {
	if modexp == nil || size <= 0 {
		return nil
	}
	out := make([]byte, size)
	b := modexp.Bytes()
	if len(b) >= size {
		copy(out, b[len(b)-size:])
		return out
	}
	copy(out[size-len(b):], b)
	return out
}

func rsaKeySizeBytes(key *RSAKey) int {
	if key == nil || key.N == nil {
		return 0
	}
	return (key.N.BitLen() + 7) / 8
}

func rsaBuildEMSA(hash []byte, size int) ([]byte, int32) {
	if len(hash) != 32 || size < len(rsaSHA256DigestInfoPrefix)+len(hash)+3 {
		return nil, ErrRSAVerifyFail
	}
	psLen := size - 3 - len(rsaSHA256DigestInfoPrefix) - len(hash)
	if psLen < 8 {
		return nil, ErrRSAVerifyFail
	}
	em := make([]byte, size)
	em[0] = 0x00
	em[1] = 0x01
	for i := 2; i < 2+psLen; i++ {
		em[i] = 0xff
	}
	em[2+psLen] = 0x00
	copy(em[3+psLen:], rsaSHA256DigestInfoPrefix)
	copy(em[3+psLen+len(rsaSHA256DigestInfoPrefix):], hash)
	return em, KRBOK
}

func rsaSignDigest(hash []byte, priv *RSAKey) ([256]byte, int32) {
	var out [256]byte
	if priv == nil || !priv.IsPrivate() {
		return out, ErrRSAKeyInvalid
	}
	size := rsaKeySizeBytes(priv)
	if size != 256 {
		return out, ErrRSAKeyInvalid
	}
	em, code := rsaBuildEMSA(hash, size)
	if code != KRBOK {
		return out, code
	}
	m := new(big.Int).SetBytes(em)
	s := rsaModExp(m, priv.D, priv.N)
	if s == nil {
		return out, ErrRSASignFail
	}
	copy(out[:], rsaModBytes(s, size))
	return out, KRBOK
}

func rsaVerifyDigest(hash []byte, sig []byte, pub *RSAKey) int32 {
	if pub == nil || pub.N == nil || pub.E == nil {
		return ErrRSAKeyInvalid
	}
	size := rsaKeySizeBytes(pub)
	if size == 0 || len(sig) != size || size != 256 {
		return ErrRSAKeyInvalid
	}
	s := new(big.Int).SetBytes(sig)
	m := rsaModExp(s, pub.E, pub.N)
	if m == nil {
		return ErrRSAVerifyFail
	}
	recovered := rsaModBytes(m, size)
	expected, code := rsaBuildEMSA(hash, size)
	if code != KRBOK {
		return code
	}
	if !bytes.Equal(recovered, expected) {
		return ErrRSAVerifyFail
	}
	return KRBOK
}

func rsaVerifySignature(seq uint32, cipherData []byte, sig [256]byte, pub *RSAKey) int32 {
	buf := make([]byte, 4+len(cipherData))
	binary.BigEndian.PutUint32(buf[:4], seq)
	copy(buf[4:], cipherData)
	sum := Sum256(buf)
	return rsaVerifyDigest(sum[:], sig[:], pub)
}

func rsaSignMessage(msg []byte, priv *RSAKey) ([256]byte, int32) {
	sum := Sum256(msg)
	return rsaSignDigest(sum[:], priv)
}

func rsaVerifyMessage(msg []byte, sig [256]byte, pub *RSAKey) int32 {
	sum := Sum256(msg)
	return rsaVerifyDigest(sum[:], sig[:], pub)
}
