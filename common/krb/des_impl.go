package krb

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

type desCtx struct {
	subKeys [16]uint64
}

var desIP = [64]uint8{
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
}

var desFP = [64]uint8{
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25,
}

var desE = [48]uint8{
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1,
}

var desP = [32]uint8{
	16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25,
}

var desPC1 = [56]uint8{
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4,
}

var desPC2 = [48]uint8{
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32,
}

var desShifts = [16]uint8{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}

var desSBoxes = [8][64]uint8{
	{
		14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
	},
	{
		15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
	},
	{
		10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
	},
	{
		7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
	},
	{
		2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
	},
	{
		12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
	},
	{
		4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
	},
	{
		13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
	},
}

func newDESCtx(key [8]byte) *desCtx {
	ctx := &desCtx{}
	ctx.subKeys = generateDESSubKeys(key)
	return ctx
}

func generateDESSubKeys(key [8]byte) [16]uint64 {
	var out [16]uint64
	key64 := binary.BigEndian.Uint64(key[:])
	key56 := permuteBits(key64, 64, desPC1[:])
	c := uint32((key56 >> 28) & 0x0fffffff)
	d := uint32(key56 & 0x0fffffff)
	for i := 0; i < 16; i++ {
		c = leftRotate28(c, desShifts[i])
		d = leftRotate28(d, desShifts[i])
		merged := (uint64(c) << 28) | uint64(d)
		out[i] = permuteBits(merged, 56, desPC2[:])
	}
	return out
}

func leftRotate28(v uint32, shift uint8) uint32 {
	s := uint(shift % 28)
	v &= 0x0fffffff
	return ((v << s) | (v >> (28 - s))) & 0x0fffffff
}

func permuteBits(in uint64, inputBits int, table []uint8) uint64 {
	var out uint64
	for _, pos := range table {
		bit := (in >> uint(inputBits-int(pos))) & 1
		out = (out << 1) | bit
	}
	return out
}

func desEncryptBlock(block uint64, subKeys [16]uint64) uint64 {
	permuted := permuteBits(block, 64, desIP[:])
	l := uint32(permuted >> 32)
	r := uint32(permuted)
	for i := 0; i < 16; i++ {
		l, r = r, l^desRound(r, subKeys[i])
	}
	preOutput := (uint64(r) << 32) | uint64(l)
	return permuteBits(preOutput, 64, desFP[:])
}

func desDecryptBlock(block uint64, subKeys [16]uint64) uint64 {
	permuted := permuteBits(block, 64, desIP[:])
	l := uint32(permuted >> 32)
	r := uint32(permuted)
	for i := 15; i >= 0; i-- {
		l, r = r, l^desRound(r, subKeys[i])
		if i == 0 {
			break
		}
	}
	preOutput := (uint64(r) << 32) | uint64(l)
	return permuteBits(preOutput, 64, desFP[:])
}

func desRound(r uint32, subKey uint64) uint32 {
	expanded := permuteBits(uint64(r), 32, desE[:])
	x := expanded ^ subKey
	var out uint32
	for i := 0; i < 8; i++ {
		shift := uint(42 - 6*i)
		chunk := uint8((x >> shift) & 0x3f)
		row := ((chunk & 0x20) >> 4) | (chunk & 0x01)
		col := (chunk >> 1) & 0x0f
		val := desSBoxes[i][int(row)*16+int(col)]
		out = (out << 4) | uint32(val)
	}
	return uint32(permuteBits(uint64(out), 32, desP[:]))
}

func desCBCEncrypt(key [8]byte, plain []byte) ([]byte, error) {
	iv := make([]byte, 8)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plain, 8)
	out := make([]byte, 8+len(padded))
	copy(out[:8], iv)
	ctx := newDESCtx(key)
	prev := binary.BigEndian.Uint64(iv)
	for i := 0; i < len(padded); i += 8 {
		block := binary.BigEndian.Uint64(padded[i : i+8])
		block ^= prev
		enc := desEncryptBlock(block, ctx.subKeys)
		binary.BigEndian.PutUint64(out[8+i:8+i+8], enc)
		prev = enc
	}
	return out, nil
}

func desCBCDecrypt(key [8]byte, cipherBytes []byte) ([]byte, error) {
	if len(cipherBytes) < 8 || len(cipherBytes)%8 != 0 {
		return nil, errors.New("invalid des cipher length")
	}
	iv := cipherBytes[:8]
	ctx := newDESCtx(key)
	prev := binary.BigEndian.Uint64(iv)
	plain := make([]byte, len(cipherBytes)-8)
	for i := 8; i < len(cipherBytes); i += 8 {
		block := binary.BigEndian.Uint64(cipherBytes[i : i+8])
		dec := desDecryptBlock(block, ctx.subKeys)
		dec ^= prev
		binary.BigEndian.PutUint64(plain[i-8:i], dec)
		prev = block
	}
	return pkcs7Unpad(plain, 8)
}
