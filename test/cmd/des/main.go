package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	cryptoutil "security-project/common/crypto"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("==================================================")
	fmt.Println(" DES-CBC 双向一致性验证")
	fmt.Println("==================================================")

	stage1EncryptVerify(reader)
	stage2DecryptVerify(reader)

	fmt.Println("\nAll tests Passed Successfully!")
}

func stage1EncryptVerify(reader *bufio.Reader) {
	fmt.Println("\n[阶段一] 验证目标程序的 DES 加密能力")

	keyHex := "133457799bbcdff1"
	plainText := "DES_Interoperability_Test_2026"
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 8 {
		fail("测试密钥构造失败")
	}

	fmt.Printf("1. 密钥 Key (Hex, 8字节):\n👉 %s\n", strings.ToUpper(keyHex))
	fmt.Printf("2. 待加密明文 (ASCII):\n👉 %s\n", plainText)
	fmt.Printf("   明文 Hex:\n👉 %X\n\n", []byte(plainText))

	fmt.Print("3. 请输入目标程序输出的密文 Cipher (Hex, 含 IV): ")
	cipherHex, _ := reader.ReadString('\n')
	cipherHex = strings.TrimSpace(cipherHex)
	cipherBytes, err := hex.DecodeString(cipherHex)
	if err != nil || len(cipherBytes) < 16 || len(cipherBytes)%8 != 0 {
		fail("❌ 测试失败: 密文输入格式错误，要求 Hex 且长度为 16 字节及以上。")
	}

	plainBytes, err := cryptoutil.DecryptDESCBC([8]byte{key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]}, cipherBytes)
	if err != nil {
		fail("❌ 阶段一失败: DES 解密报错 -> %v", err)
	}
	if !bytes.Equal(plainBytes, []byte(plainText)) {
		fmt.Printf("❌ 阶段一失败: 解密结果不匹配！\n期望明文: %X\n实际明文: %X\n", []byte(plainText), plainBytes)
		return
	}

	fmt.Println("✅ 阶段一通过：目标程序输出的 DES 密文可被正确解密，说明加密格式与 CBC/PKCS7 处理一致。")
}

func stage2DecryptVerify(reader *bufio.Reader) {
	fmt.Println("\n" + strings.Repeat("-", 50))
	fmt.Println("[阶段二] 验证目标程序的 DES 解密能力")

	keyHex := "a1b2c3d4e5f60718"
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil || len(keyBytes) != 8 {
		fail("测试密钥构造失败")
	}
	var key [8]byte
	copy(key[:], keyBytes)

	binaryData := make([]byte, 45)
	if _, err := rand.Read(binaryData); err != nil {
		fail("rand.Read: %v", err)
	}
	binaryData[10] = 0x00
	binaryData[25] = 0x00

	cipherBytes, err := cryptoutil.EncryptDESCBC(key, binaryData)
	if err != nil {
		fail("EncryptDESCBC failed: %v", err)
	}

	fmt.Printf("1. 密钥 Key (Hex, 8字节):\n👉 %s\n", strings.ToUpper(keyHex))
	fmt.Printf("2. 待解密密文 (Hex, 含 IV):\n👉 %X\n\n", cipherBytes)
	fmt.Printf("[提示] 本轮明文是 %d 字节的原始二进制流，包含 0x00，重点检查是否发生截断。\n", len(binaryData))
	fmt.Print("3. 请输入目标程序解密后的明文 Hex: ")
	plainHex, _ := reader.ReadString('\n')
	plainHex = strings.TrimSpace(plainHex)
	actualPlain, err := hex.DecodeString(plainHex)
	if err != nil {
		fail("❌ 测试失败: 明文输入格式错误，要求 Hex 字符串。")
	}

	if !bytes.Equal(actualPlain, binaryData) {
		fmt.Printf("❌ 阶段二失败: 明文不匹配！\n测试模块期望值: %X\n目标程序实际值: %X\n", binaryData, actualPlain)
		return
	}

	fmt.Println("✅ 阶段二通过：目标程序可正确处理包含 0x00 的 DES-CBC 二进制报文。")
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
