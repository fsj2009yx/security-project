package crypto

func EncryptDESCBC(key [8]byte, plain []byte) ([]byte, error) {
	return desCBCEncrypt(key, plain)
}

func DecryptDESCBC(key [8]byte, cipherBytes []byte) ([]byte, error) {
	return desCBCDecrypt(key, cipherBytes)
}
