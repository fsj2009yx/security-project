package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	// --- 阶段一：基础 ASCII 字符串哈希 ---
	fmt.Println("==================================================")
	fmt.Println(" 阶段一：常规字符串验证 (ASCII 文本)")
	fmt.Println("==================================================")

	plainStr := "Kerberos_Auth_SHA256_Test_2026"
	expectedHash1 := sha256.Sum256([]byte(plainStr))

	fmt.Printf("[任务] 请在您的目标程序中计算以下字符串的 SHA-256 (不包含换行符):\n👉 %s\n\n", plainStr)

	fmt.Print("1. 请输入计算出的哈希值 (Hex格式, 64个字符): ")
	hashHex1, _ := reader.ReadString('\n')
	hashHex1 = strings.TrimSpace(hashHex1)
	actualHash1, err := hex.DecodeString(hashHex1)

	if err != nil || len(actualHash1) != 32 {
		fmt.Println("❌ 测试失败: 输入格式错误，要求 64 位 Hex 字符串（即 32 字节）。")
		return
	}

	if hex.EncodeToString(actualHash1) != hex.EncodeToString(expectedHash1[:]) {
		fmt.Printf("❌ 阶段一失败: 哈希值不匹配！\n测试模块期望值: %x\n目标程序实际值: %x\n提示: 请检查内部状态的大端序转换或末尾 Padding 逻辑。\n", expectedHash1, actualHash1)
		return
	}
	fmt.Println("✅ 阶段一通过：常规文本哈希计算完全一致！\n")

	// --- 阶段二：纯二进制流/防截断测试 ---
	fmt.Println("==================================================")
	fmt.Println(" 阶段二：二进制流抗截断验证 (Raw Bytes)")
	fmt.Println("==================================================")

	// 故意构造一个包含 0x00 的二进制流，测试实现是否会因为遇到 NULL 字符导致截断
	binaryData := make([]byte, 45)
	rand.Read(binaryData)
	binaryData[10] = 0x00 // 埋雷：强行插入 NULL 字符
	binaryData[25] = 0x00 // 埋雷：强行插入 NULL 字符

	expectedHash2 := sha256.Sum256(binaryData)

	fmt.Printf("[警告] 本轮测试数据内部包含 NULL (0x00) 字符，请确保您的哈希实现不会将其视为数据结尾而导致截断！\n")
	fmt.Printf("[任务] 请将以下 Hex 字符串转为 %d 字节的二进制流，并计算 SHA-256:\n👉 %X\n\n", len(binaryData), binaryData)

	fmt.Print("2. 请输入计算出的哈希值 (Hex格式): ")
	hashHex2, _ := reader.ReadString('\n')
	hashHex2 = strings.TrimSpace(hashHex2)
	actualHash2, err := hex.DecodeString(hashHex2)

	if err != nil || len(actualHash2) != 32 {
		fmt.Println("❌ 测试失败: 输入格式错误。")
		return
	}

	if hex.EncodeToString(actualHash2) != hex.EncodeToString(expectedHash2[:]) {
		fmt.Printf("❌ 阶段二失败: 二进制流哈希值不匹配！\n测试模块期望值: %x\n目标程序实际值: %x\n提示: 您的程序可能将 0x00 误认为了数据结尾导致读取提前终止，必须显式传递数据长度并按纯二进制流处理！\n", expectedHash2, actualHash2)
		return
	}
	fmt.Println("✅ 阶段二通过：二进制流哈希计算完全一致！能够安全承载加密网络报文。\n")

	// --- 结论 ---
	fmt.Println("All tests Passed Successfully! ")
}
