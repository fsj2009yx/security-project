package main

import (
	"bufio"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("==================================================")
	fmt.Println(" RSA-2048 裸数据一致性验证 (无 ASN.1 模式)")
	fmt.Println("==================================================")

	// --- 阶段一：目标程序验签 (测试模块签名 -> 目标程序验签) ---
	fmt.Println("\n[阶段一] 验证目标程序的 RSA 解密/验签能力")

	// 1. 测试模块生成一对标准密钥（仅用于测试）
	priv, _ := rsa.GenerateKey(nil, 2048)
	nBytes := priv.N.Bytes() // 256字节
	e := priv.E

	message := []byte("RSA_Raw_Interoperability_Test_2026")
	hashed := sha256.Sum256(message)
	// 使用 PKCS#1 v1.5 进行签名
	sig, _ := rsa.SignPKCS1v15(nil, priv, crypto.SHA256, hashed[:])

	fmt.Printf("1. 公钥 N (Hex, 256字节):\n👉 %X\n", nBytes)
	fmt.Printf("2. 公钥 E (十进制): %d\n", e)
	fmt.Printf("3. 待验签原始消息 (明文):\n👉 %s\n", string(message))
	fmt.Printf("4. 产生的签名 Sign (Hex, 256字节):\n👉 %X\n", sig)

	fmt.Print("\n[任务] 请在您的程序中使用上述 N, E 验证该签名，验证通过吗？(y/n): ")
	result, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(result)) == "y" {
		fmt.Println("✅ 阶段一通过！目标程序能够正确处理标准的 PKCS#1 v1.5 填充。")
	} else {
		fmt.Println("❌ 阶段一失败。请检查大数幂模运算逻辑或 PKCS#1 v1.5 解包逻辑。")
	}

	// --- 阶段二：测试模块验签 (目标程序签名 -> 测试模块验签) ---
	fmt.Println("\n" + strings.Repeat("-", 50))
	fmt.Println("[阶段二] 验证目标程序的签名生成能力")

	fmt.Println("1. 请输入您的目标程序生成的公钥 N (Hex, 256字节):")
	nHex, _ := reader.ReadString('\n')
	nHex = strings.TrimSpace(nHex)
	nRaw, _ := hex.DecodeString(nHex)

	fmt.Println("2. 请输入您的目标程序生成的公钥 E (十进制, 通常为 65537):")
	var eInt int
	fmt.Fscanf(reader, "%d\n", &eInt)

	testMsg := []byte("Verify_Target_Signature_Logic")
	testHashed := sha256.Sum256(testMsg)
	fmt.Printf("3. 待签名消息 (明文): %s\n", string(testMsg))
	fmt.Printf("   对应 SHA-256 哈希 (Hex): %X\n", testHashed)

	fmt.Println("4. 请输入您的目标程序对该哈希生成的签名 Sign (Hex, 256字节):")
	sigHex, _ := reader.ReadString('\n')
	sigHex = strings.TrimSpace(sigHex)
	sigRaw, _ := hex.DecodeString(sigHex)

	// 构造标准库公钥对象
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nRaw),
		E: eInt,
	}

	// 执行标准验签
	err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, testHashed[:], sigRaw)
	if err != nil {
		fmt.Printf("❌ 阶段二失败: 标准库验签报错 -> %v\n", err)
		fmt.Println("提示: 请检查是否正确添加了 SHA-256 的 DigestInfo 前缀，或 PS 填充长度是否有误。")
	} else {
		fmt.Println("✅ 阶段二通过！目标程序生成的签名完全符合 RSASSA-PKCS1-v1_5 工业标准。")
	}
}
