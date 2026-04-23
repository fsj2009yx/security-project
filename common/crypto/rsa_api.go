package crypto

// RsaSignDigest 使用 RSA 私钥对消息摘要进行签名，返回签名结果和状态码。
func RsaSignDigest(hash []byte, priv *RSAKey) ([256]byte, int32) {
	return rsaSignDigest(hash, priv)
}

// RsaVerifyDigest 使用 RSA 公钥验证消息摘要的签名，返回状态码。
func RsaVerifyDigest(hash []byte, sig []byte, pub *RSAKey) int32 {
	return rsaVerifyDigest(hash, sig, pub)
}

// RsaSignMessage 使用 RSA 私钥对消息进行签名，返回签名结果和状态码。
func RsaSignMessage(msg []byte, priv *RSAKey) ([256]byte, int32) {
	return rsaSignMessage(msg, priv)
}

// RsaVerifyMessage 使用 RSA 公钥验证消息的签名，返回状态码。
func RsaVerifyMessage(msg []byte, sig [256]byte, pub *RSAKey) int32 {
	return rsaVerifyMessage(msg, sig, pub)
}
