package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// PKCS7Padding 填充
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS7UnPadding 去除填充并严格校验
func PKCS7UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	if length == 0 {
		return nil, fmt.Errorf("解密失败: 数据为空")
	}
	unpadding := int(origData[length-1])
	if unpadding > length || unpadding == 0 {
		return nil, fmt.Errorf("解密失败: Padding 格式非法 (尾部字节为 %d)", unpadding)
	}
	// 校验 Padding 字节是否一致
	for i := length - unpadding; i < length; i++ {
		if int(origData[i]) != unpadding {
			return nil, fmt.Errorf("解密失败: Padding 字节不一致")
		}
	}
	return origData[:(length - unpadding)], nil
}

// AES256Encrypt 标准加密：返回 IV + Ciphertext
func AES256Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	plaintext = PKCS7Padding(plaintext, blockSize)

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

// AES256Decrypt 标准解密：输入 IV + Ciphertext
func AES256Decrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("密文长度小于 IV 长度 (16 字节)")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("密文部分长度不是 16 的倍数")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	return PKCS7UnPadding(ciphertext)
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	// --- 阶段一：C 语言加密，Go 语言验证 ---
	fmt.Println("==================================================")
	fmt.Println(" 阶段一：正向验证 (手写加密 -> 解密)")
	fmt.Println("==================================================")

	// 随机生成一段明文用于测试
	plain1 := "Kerberos_Auth_Test_Payload_2026"
	fmt.Printf("[任务] 请在自实现算法中加密以下明文 (Raw Bytes):\n👉 %s\n\n", plain1)

	fmt.Print("1. 请输入你使用的 32 字节 Key (Hex格式): ")
	keyHex, _ := reader.ReadString('\n')
	keyHex = strings.TrimSpace(keyHex)
	key1, err := hex.DecodeString(keyHex)
	if err != nil || len(key1) != 32 {
		fmt.Println("❌ 失败: Key 格式错误或不是 32 字节")
		return
	}

	fmt.Print("2. 请输入自实现算法生成的密文 (必须包含 16 字节 IV 前缀, Hex格式): ")
	cipherHex, _ := reader.ReadString('\n')
	cipherHex = strings.TrimSpace(cipherHex)
	cipher1, err := hex.DecodeString(cipherHex)
	if err != nil {
		fmt.Println("❌ 失败: 密文 Hex 解析错误")
		return
	}

	decrypted1, err := AES256Decrypt(cipher1, key1)
	if err != nil {
		fmt.Printf("❌ 阶段一失败: 解密或去除 Padding 报错 -> %v\n", err)
		return
	}
	if string(decrypted1) != plain1 {
		fmt.Printf("❌ 阶段一失败: 解密结果不匹配 -> 实际得到 '%s'\n", string(decrypted1))
		return
	}
	fmt.Println("阶段一通过：成功还原了密文！\n")

	// --- 阶段二：Go 语言加密，C 语言验证 ---
	fmt.Println("==================================================")
	fmt.Println(" 阶段二：逆向验证 (加密 -> 手写解密)")
	fmt.Println("==================================================")

	key2 := make([]byte, 32)
	io.ReadFull(rand.Reader, key2)
	plain2 := "System_Oriented_Engineer_Success"
	cipher2, _ := AES256Encrypt([]byte(plain2), key2)

	fmt.Printf("生成了 32 字节随机 Key (Hex):\n👉 %X\n\n", key2)
	fmt.Printf("生成了密文 (IV + Ciphertext, Hex):\n👉 %X\n\n", cipher2)

	fmt.Print("[任务] 请在自实现算法程序中解密以上内容，并输入你还原的明文: ")
	inputPlain, _ := reader.ReadString('\n')
	inputPlain = strings.TrimSpace(inputPlain)

	if inputPlain != plain2 {
		fmt.Printf("❌ 阶段二失败: 明文不匹配，期望 '%s'，实际得到 '%s'\n", plain2, inputPlain)
		return
	}
	fmt.Println("✅ 阶段二通过：成功还原了测试生成的密文！\n")

	// --- 结论 ---
	fmt.Println("All tests passed successfully!")
}
