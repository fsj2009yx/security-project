# Test
该目录下存放通用测试代码，每个代码放在独立子目录下单独编译运行，测试结果通过 `stdin` 输入、`stdout` 输出 JSON。

`test/cmd/` 下是对应的可执行版本，`go build ./test/cmd/...` 可一次性编译全部通用测试程序。
