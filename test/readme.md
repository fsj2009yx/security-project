# Test
该目录下存放通用测试代码，每个代码放在独立子目录下单独编译运行。

`test/cmd/` 下是对应的可执行版本，`go build ./test/cmd/...` 可一次性编译全部通用测试程序。

Kerberos 测试命令支持两种用法：

1. 终端直接运行时，会在控制台提示输入完整封包 Hex。封包格式是 `20` 字节协议头 + payload，例如：

   ```bash
   go run ./test/cmd/kerberos/as
   go run ./test/cmd/kerberos/tgs
   go run ./test/cmd/kerberos/ap
   ```

2. 通过 `stdin` 输入 JSON 时，可传入 `packet_hex`，命令会把封包头和 payload 解析结果输出为 JSON。加密字段需要同时传入对应密钥 Hex 才会继续解密内部结构。

   ```json
   {
     "packet_hex": "4b450101...",
     "kc_hex": "1122334455667788",
     "ktgs_hex": "8877665544332211"
   }
   ```

通过管道输入字段 JSON，或管道输入为空且不传 `packet_hex` 时，Kerberos 命令会执行内置默认用例，并在输出 JSON 中给出 `*_packet_hex`，可作为其他语言实现的通用测试输入。
