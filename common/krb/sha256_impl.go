package krb

type SHA256Ctx struct {
	h         [8]uint32
	buf       [64]byte
	totalBits uint64
	bufLen    uint32
}

var sha256InitState = [8]uint32{
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19,
}

var sha256K = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

func NewSHA256Ctx() *SHA256Ctx {
	ctx := &SHA256Ctx{}
	sha256Init(ctx)
	return ctx
}

func sha256Init(ctx *SHA256Ctx) int32 {
	if ctx == nil {
		return ErrSHA256Fail
	}
	ctx.h = sha256InitState
	ctx.totalBits = 0
	ctx.bufLen = 0
	for i := range ctx.buf {
		ctx.buf[i] = 0
	}
	return KRBOK
}

func sha256Update(ctx *SHA256Ctx, data []byte) int32 {
	if ctx == nil {
		return ErrSHA256Fail
	}
	if len(data) == 0 {
		return KRBOK
	}
	ctx.totalBits += uint64(len(data)) * 8
	for len(data) > 0 {
		n := copy(ctx.buf[ctx.bufLen:], data)
		ctx.bufLen += uint32(n)
		data = data[n:]
		if ctx.bufLen == 64 {
			sha256Compress(&ctx.h, ctx.buf[:])
			ctx.bufLen = 0
		}
	}
	return KRBOK
}

func sha256Final(ctx *SHA256Ctx) ([32]byte, int32) {
	var digest [32]byte
	if ctx == nil {
		return digest, ErrSHA256Fail
	}
	b := make([]byte, 0, 128)
	b = append(b, ctx.buf[:ctx.bufLen]...)
	b = append(b, 0x80)
	for (len(b) % 64) != 56 {
		b = append(b, 0x00)
	}
	var lenBuf [8]byte
	putUint64BE(lenBuf[:], ctx.totalBits)
	b = append(b, lenBuf[:]...)
	for len(b) > 0 {
		sha256Compress(&ctx.h, b[:64])
		b = b[64:]
	}
	for i, v := range ctx.h {
		putUint32BE(digest[i*4:(i+1)*4], v)
	}
	return digest, KRBOK
}

func Sum256(data []byte) [32]byte {
	ctx := NewSHA256Ctx()
	_ = sha256Update(ctx, data)
	digest, _ := sha256Final(ctx)
	return digest
}

func sha256Compress(h *[8]uint32, block []byte) {
	var w [64]uint32
	for i := 0; i < 16; i++ {
		w[i] = uint32(block[i*4])<<24 |
			uint32(block[i*4+1])<<16 |
			uint32(block[i*4+2])<<8 |
			uint32(block[i*4+3])
	}
	for i := 16; i < 64; i++ {
		s0 := rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3)
		s1 := rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10)
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}
	a, b, c, d := h[0], h[1], h[2], h[3]
	e, f, g, hh := h[4], h[5], h[6], h[7]
	for i := 0; i < 64; i++ {
		s1 := rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
		ch := (e & f) ^ (^e & g)
		t1 := hh + s1 + ch + sha256K[i] + w[i]
		s0 := rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
		maj := (a & b) ^ (a & c) ^ (b & c)
		t2 := s0 + maj
		hh = g
		g = f
		f = e
		e = d + t1
		d = c
		c = b
		b = a
		a = t1 + t2
	}
	h[0] += a
	h[1] += b
	h[2] += c
	h[3] += d
	h[4] += e
	h[5] += f
	h[6] += g
	h[7] += hh
}

func rotr32(v uint32, n uint) uint32 {
	return (v >> n) | (v << (32 - n))
}

func putUint32BE(dst []byte, v uint32) {
	dst[0] = byte(v >> 24)
	dst[1] = byte(v >> 16)
	dst[2] = byte(v >> 8)
	dst[3] = byte(v)
}

func putUint64BE(dst []byte, v uint64) {
	dst[0] = byte(v >> 56)
	dst[1] = byte(v >> 48)
	dst[2] = byte(v >> 40)
	dst[3] = byte(v >> 32)
	dst[4] = byte(v >> 24)
	dst[5] = byte(v >> 16)
	dst[6] = byte(v >> 8)
	dst[7] = byte(v)
}
