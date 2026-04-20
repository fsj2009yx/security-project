# 基于 Kerberos 的安全通信系统 — 详细设计说明书

<br/>


> **版本**：V1.0　**状态**：正式发布　**适用对象**：全体开发成员  
> **角色定位**：本文档由担任高级架构师与课程设计技术指导的资深工程师撰写，旨在为团队提供可直接落地的详细设计依据，开发人员无需额外猜测设计意图，按文档实现即可通过所有验收项。

---

## 目录

<br/>


1. [全局统一规范](#第一章全局统一规范)
2. [加密模块设计](#第二章加密模块设计)
3. [AS 认证服务器模块](#第三章as认证服务器模块设计)
4. [TGS 票据许可服务器模块](#第四章tgs票据许可服务器模块设计)
5. [V 应用服务器模块](#第五章v应用服务器模块设计)
6. [Client 客户端模块](#第六章client客户端模块设计)
7. [封包与拆包详细设计](#第七章封包与拆包详细设计)
8. [自定义证书设计](#第八章自定义证书设计)
9. [完整通信时序规范](#第九章完整通信时序规范)
10. [测试用例清单](#第十章测试用例清单)
11. [工程目录结构](#第十一章推荐工程目录结构)
12. [关键算法伪代码](#第十二章关键算法伪代码)

---

# 第一章　全局统一规范

<br/>


## 1.1　设计原则与强制约束

<br/>


在分布式安全系统中，任何细节上的不一致都可能导致严重的安全漏洞或互操作性故障。因此，本项目在工程层面设立以下几条不可违反的强制约束，所有开发成员必须严格遵守。

**字节序约束**：所有整型字段（`uint8_t`、`uint16_t`、`uint32_t`、`uint64_t`）在网络传输中严格采用 **大端序（Big-Endian / Network Byte Order）**。（例如在 C/C++ 中应使用 `htonl()`/`ntohl()` 或自实现的宏完成转换；在 Python 中应使用 `struct.pack('>I', val)` 格式字符串显式指定大端）

**内存对齐约束**：所有协议结构体必须使用 `#pragma pack(push, 1)` / `#pragma pack(pop)` 包裹，完全禁止编译器隐式插入 Padding 字节。协议规范给出了精确的字节偏移布局，任何 Padding 都会导致字段错位。

**版本兼容约束**：协议版本号固定为 `0x01`。若将来需要扩展协议字段，必须同时递增版本号，并更新本文档中的内存布局图。任何接收方在解析报文时，遇到不支持的版本号必须立即返回 `ERR_VERSION_UNSUPPORTED` 并丢弃报文

## 1.2　全链路错误码定义

<br/>


统一的错误码体系是保证系统可调试性的基础。所有节点的所有函数返回 `uint32_t`，其中 `0`（`KRB_OK`）表示成功，所有负数表示不同类别的错误。错误码按模块分段，便于快速定位问题所在层次

### 1.2.1　网络与封包拆包错误（-1000 段）

<br/>


| 错误码 | 宏定义 | 适用模块 | 触发场景 | 处理策略 |
|--------|--------|----------|----------|----------|
| `0` | `KRB_OK` | 全局 | 操作成功 | 继续执行 |
| `-1001` | `ERR_MAGIC_MISMATCH` | 拆包 | 接收到的前 2 字节不为 `0x4B45`，说明非 Kerberos 报文或数据被严重损坏 | 立即丢弃该报文，记录 WARN 级别日志（含对端 IP），关闭该连接 |
| `-1002` | `ERR_VERSION_UNSUPPORTED` | 拆包 | Version 字段值不为 `0x01` | 发送错误响应后断开连接，记录日志（含实际版本号） |
| `-1003` | `ERR_MSG_TYPE_INVALID` | 拆包 | MSG_TYPE 超出 `0x01`~`0x04` 已定义范围 | 丢弃报文，记录 WARN 日志 |
| `-1004` | `ERR_PAYLOAD_TOO_LARGE` | 拆包 | `TotalLength` 字段值超过预设上限（建议 64KB） | 拒绝读取后续字节，断开连接，记录 WARN 日志 |
| `-1005` | `ERR_REPLAY_TIMESTAMP` | 防重放 | 报文时间戳与服务端当前时间差值超过 5 秒（无论早于还是晚于） | 丢弃报文，返回 `-1005` 错误响应，记录 WARN 日志（含时间差值） |
| `-1006` | `ERR_REPLAY_SEQ` | 防重放 | 该 `SEQ_NUM` 在滑动窗口内已被处理过（重复序列号） | 丢弃报文，返回 `-1006` 错误响应，记录 WARN 日志 |
| `-1007` | `ERR_BUF_TOO_SMALL` | 封包/拆包 | 调用方提供的输出缓冲区不足以容纳封包结果 | 返回错误码，调用方应扩容缓冲区后重试，最多重试 3 次 |
| `-1008` | `ERR_SOCKET_SEND` | 网络层 | `send()` 系统调用返回 -1 或发送字节数少于预期 | 重试最多 3 次（每次间隔 100ms），失败后清理连接资源，记录 ERROR 日志 |
| `-1009` | `ERR_SOCKET_RECV` | 网络层 | `recv()` 返回 0（对端正常关闭）或 -1（系统错误）| 清理该连接的所有资源（Session、缓冲区等），记录 INFO/ERROR 日志 |
| `-1010` | `ERR_THREAD_CREATE` | 并发 | 线程池工作线程创建失败（系统资源不足） | 返回错误，向管理界面推送告警，记录 ERROR 日志 |

### 1.2.2　Kerberos 协议错误（-2000 段）

<br/>


| 错误码 | 宏定义 | 适用模块 | 触发场景 | 处理策略 |
|--------|--------|----------|----------|----------|
| `-2001` | `ERR_CLIENT_NOT_FOUND` | AS | `ID_Client` 在 AS 的客户端数据库中不存在 | 返回 AS 错误报文（不泄露具体原因），记录 WARN 日志 |
| `-2002` | `ERR_TICKET_EXPIRED` | TGS / V | `Ticket.TS + Ticket.Lifetime < 当前时间`，票据已失效 | 返回票据过期错误响应，Client 应重新走 AS 或 TGS 阶段 |
| `-2003` | `ERR_TICKET_INVALID` | TGS / V | Ticket 解密失败（密钥不匹配）或解密后字段长度非法 | 返回票据无效错误，记录 SECURITY 日志（疑似伪造攻击） |
| `-2004` | `ERR_AUTH_MISMATCH` | TGS / V | `Authenticator.ID_Client` 与 `Ticket.ID_Client` 不一致 | 拒绝请求，记录 SECURITY 日志（身份伪造特征） |
| `-2005` | `ERR_AD_MISMATCH` | TGS / V | `Authenticator.AD_c`（客户端 IP）与 `Ticket.AD_c` 不一致 | 拒绝请求，记录 SECURITY 日志（中间人攻击特征） |
| `-2006` | `ERR_KEY_DERIVE` | AS / TGS | `krb_rand_bytes()` 随机数生成失败，无法生成 Session Key | 返回服务端错误，向运维告警，记录 ERROR 日志 |
| `-2007` | `ERR_SESSION_NOT_FOUND` | V | 收到业务消息但找不到对应 Client 的 Session（Client 未完成 AP 认证）| 要求 Client 重新走 AP 认证阶段 |

### 1.2.3　加密模块错误（-3000 段）

<br/>


| 错误码 | 宏定义 | 适用模块 | 触发场景 | 处理策略 |
|--------|--------|----------|----------|----------|
| `-3001` | `ERR_AES_KEY_LEN` | AES-256 | 传入的密钥长度不等于 32 字节 | 拒绝加密操作，调用方须检查密钥来源逻辑 |
| `-3002` | `ERR_AES_PADDING` | AES-256 | PKCS7 填充计算异常（明文长度溢出或对齐逻辑错误） | 返回错误，调用方应检查明文缓冲区 |
| `-3003` | `ERR_AES_DECRYPT_FAIL` | AES-256 | 解密后 PKCS7 校验失败：填充字节值不合法（<1 或 > 16）或填充内容不一致 | 丢弃解密结果，返回错误；在 TGS/V 侧记录 SECURITY 日志（疑似密文被篡改）|
| `-3004` | `ERR_RSA_KEY_INVALID` | RSA | RSA Key 结构体中 `n`/`e`/`d` 任一字段为零，或结构未初始化 | 拒绝所有涉及该密钥的操作，记录 ERROR 日志 |
| `-3005` | `ERR_RSA_SIGN_FAIL` | RSA | RSA 模幂运算中出现内部错误（大整数溢出等） | 返回错误，调用方不得发送带有错误签名的消息 |
| `-3006` | `ERR_RSA_VERIFY_FAIL` | RSA | 验签失败：解密后的 EMSA 编码与重新计算的 Hash 不匹配 | 立即拒绝该请求，记录 SECURITY 日志（疑似消息伪造或私钥泄露） |
| `-3007` | `ERR_HMAC_MISMATCH` | HMAC | 接收到的 MAC 值与重新计算的 HMAC 不匹配 | 丢弃整条消息，记录 SECURITY 日志（消息被篡改） |
| `-3008` | `ERR_SHA256_FAIL` | SHA-256 | SHA-256 内部计算异常（极罕见，通常指内存错误）| 返回错误，记录 ERROR 日志 |

### 1.2.4　证书错误（-4000 段）

<br/>


| 错误码 | 宏定义 | 适用模块 | 触发场景 | 处理策略 |
|--------|--------|----------|----------|----------|
| `-4001` | `ERR_CERT_EXPIRED` | 证书管理 | 证书的 `expire` 日期早于系统当前日期 | 拒绝该证书对应的通信，向 WebUI 推送证书过期告警 |
| `-4002` | `ERR_CERT_SIG_INVALID` | 证书管理 | 证书的 `sign` 字段无法通过证书自身公钥的 RSA 验签 | 拒绝通信，记录 SECURITY 日志（证书被篡改或伪造） |
| `-4003` | `ERR_CERT_ID_MISMATCH` | 证书管理 | 证书中的 `id` 字段与 Ticket 中的 `ID_Client` 不一致 | 拒绝通信，记录 SECURITY 日志 |
| `-4004` | `ERR_CERT_LOAD_FAIL` | 证书管理 | 证书 JSON 文件不存在、格式非法或字段缺失 | 节点启动时若关键证书加载失败，应终止启动并报错 |

**响应方函数调用收到错误码后，响应报文的 `Protocol Header` 中 `msg_type` 填入 `0xff`，同时将错误码按 `int32_t` 写入 `PayLoad` 中发送，随后调用 `关闭 TCP 流` 函数**

---

## 1.3　公共模块函数接口(C/C++示例)

<br/>


这些函数由 `common/` 模块实现，所有节点共享使用。接口设计遵循单一职责原则，每个函数只做一件事，便于单元测试独立验证

（以 c/c++示例仅供参考，不同语言可采用不同风格实现）

### 1.3.1　`krb_pack()` — 封包函数

<br/>


**功能描述**：将业务层已序列化完成的 Payload 字节流，拼装上 20 字节的 Kerberos 协议首部，生成可直接通过 TCP 发送的完整报文字节流。函数内部会自动填充 `Magic Number`、`Version`、`TotalLength`，并根据调用方传入的当前 Unix 时间戳填充 `TIMESTAMP` 字段，`ADDITION` 保留字段填 0。

```c
int32_t krb_pack(
    uint8_t        msg_type,     // [入] 报文类型：0x01 = AS_REQ, 0x02 = AS_REP, 0x03 = TGS_REQ,
                                 //                 0x04 = TGS_REP, 0x05 = AP_REQ, 0x06 = AP_REP, 0x07 = 业务消息,0xff = 非法报文
    uint32_t       seq_num,      // [入] 序列号，由调用方维护单调递增计数器，每次调用后调用方自增
    uint32_t       timestamp,    // [入] 当前 Unix 时间戳（调用 time(NULL) 获得）
    const uint8_t* payload,      // [入] 已序列化的 Payload 字节数组起始指针
    uint32_t       payload_len,  // [入] Payload 的有效字节长度
    uint8_t*       out_buf,      // [出] 输出缓冲区，调用方负责分配，大小必须 ≥ 20 + payload_len
    uint32_t*      out_len       // [出] 输出报文的实际总字节数（= 20 + payload_len）
);
// 返回值：KRB_OK(0) | ERR_MSG_TYPE_INVALID(-1003) | ERR_BUF_TOO_SMALL(-1007)
```

**实现要点**：首部字段写入时必须使用 `WRITE_U16_BE` / `WRITE_U32_BE` 宏完成字节序转换，禁止使用结构体赋值后直接 `memcpy`

`TotalLength` 字段只计 Payload 字节数，不含首部自身的 20 字节。

---

### 1.3.2　`krb_unpack()` — 拆包函数（首部解析）

<br/>


**功能描述**：从 TCP 接收缓冲区中解析固定长度的 20 字节协议首部。该函数只负责解析首部，不负责读取 Payload（Payload 应由调用方根据 `header.total_len` 继续调用 `krb_recv_full()` 读取）

```c
int32_t krb_unpack(
    const uint8_t* raw,            // [入] 原始接收缓冲区，至少包含 20 字节
    uint32_t       raw_len,        // [入] raw 缓冲区的有效字节数，必须 ≥ 20
    Ker_Header*    header_out      // [出] 解析后的首部结构体，调用方分配，函数填充
);
// 返回值：KRB_OK(0) | ERR_MAGIC_MISMATCH(-1001) | ERR_VERSION_UNSUPPORTED(-1002)
//         | ERR_MSG_TYPE_INVALID(-1003) | ERR_PAYLOAD_TOO_LARGE(-1004)
```

**解析后字段已完成字节序转换**：调用方拿到 `Ker_Header` 后，所有字段已是主机字节序，可直接用于逻辑比较（无需再次 `ntohl`）。

---

### 1.3.3　`krb_recv_full()` — 保证完整接收

<br/>


**功能描述**：TCP 的 `recv()` 调用不保证一次性收齐所有字节（可能出现 "TCP 截包"）。此函数循环调用 `recv()` 直到读满 `need` 字节或发生错误，是所有节点 TCP 接收逻辑的基础工具函数。

```c
int32_t krb_recv_full(
    int       fd,    // [入] socket 文件描述符
    uint8_t*  buf,   // [出] 接收缓冲区
    uint32_t  need   // [入] 需要接收的字节数
);
// 返回值：KRB_OK(0) | ERR_SOCKET_RECV(-1009)
```

---

### 1.3.4　`krb_antireplay_check()` — 防重放验证（Pass）

<br/>


**功能描述**：结合时间戳窗口和序列号滑动窗口双重机制，判断一条报文是否为重放攻击。时间戳误差阈值固定为 5 秒，序列号窗口大小为 1024（环形队列实现）。该函数是线程安全的（内含互斥锁）。

```c
// 防重放上下文，每个监听端口一个实例，需在节点初始化时调用 krb_antireplay_init() 初始化
typedef struct {
    uint32_t        window[1024];    // 已处理 SEQ_NUM 的环形队列
    uint32_t        window_head;     // 队列头指针
    uint32_t        window_count;    // 当前队列中元素数量
    pthread_mutex_t lock;            // 保护 window 的互斥锁
} AntiReplay_Ctx;

int32_t krb_antireplay_init(AntiReplay_Ctx* ctx);

int32_t krb_antireplay_check(
    uint32_t        timestamp,  // [入] 报文首部中的 TIMESTAMP 字段（已转为主机序）
    uint32_t        seq_num,    // [入] 报文首部中的 SEQ_NUM 字段（已转为主机序）
    AntiReplay_Ctx* ctx         // [入/出] 防重放上下文，函数内部加锁操作
);
// 返回值：KRB_OK(0) | ERR_REPLAY_TIMESTAMP(-1005) | ERR_REPLAY_SEQ(-1006)
```

**实现细节**：时间戳检查使用 `abs((int32_t)(timestamp - (uint32_t)time(NULL))) > 5` 判断；序列号检查在 `window[1024]` 数组中顺序扫描（窗口较小时线性扫描性能可接受），找到重复则拒绝，否则将新 SEQ 写入窗口并淘汰最旧记录。

---

### 1.3.5　证书管理接口

<br/>


```c
// 证书内存结构（见第八章）
typedef struct { ... } Cert_t;

int32_t cert_load(const char* json_path, Cert_t* out);
// 从 JSON 文件加载证书，解析 id、public_key（n/e）、expire、sign 字段到结构体
// 返回：KRB_OK | ERR_CERT_LOAD_FAIL(-4004) | ERR_CERT_SIG_INVALID(-4002)

int32_t cert_verify(const Cert_t* cert);
// 验证证书有效期（expire >= 当前日期）和自签名（用证书自身公钥验 sign 字段）
// 返回：KRB_OK | ERR_CERT_EXPIRED(-4001) | ERR_CERT_SIG_INVALID(-4002)

int32_t cert_get_pubkey(const Cert_t* cert, RSA_Key_t* out_pub);
// 从 Cert_t 中提取公钥到 RSA_Key_t 结构（仅填充 n 和 e 字段）
// 返回：KRB_OK | ERR_RSA_KEY_INVALID(-3004)

int32_t cert_find_by_id(const char* id, const Cert_t* cert_db, uint32_t db_count, Cert_t* out);
// 在内存证书库数组中按 id 字段查找，找到后拷贝到 out
// 返回：KRB_OK | ERR_CLIENT_NOT_FOUND(-2001)
```

---

## 1.4　通用协议首部结构体

<br/>


```c
#pragma pack(push, 1)
struct Ker_Header {
    uint16_t magic;      // 固定值 0x4B45，标识 Kerberos 协议报文
    uint8_t  version;    // 协议版本，当前固定为 0x01
    uint8_t  msg_type;   // 报文类型（见下表）
    uint32_t total_len;  // Payload 字节数（不含首部的 20 字节本身）
    uint32_t seq_num;    // 序列号，发送方维护，单调递增，用于防重放
    uint32_t timestamp;  // 发送方当前 Unix 时间戳，用于时钟同步和防重放
    uint32_t addition;   // 保留字段，当前全填 0x00000000，用于后续版本扩展
};
#pragma pack(pop)
// sizeof(Ker_Header) 必须恰好等于 20 字节，请在编译期用 static_assert 验证
```

| `msg_type` 值 | 含义 |
|:---:|---|
| `0x01` | AS_REQ（Client → AS） |
| `0x02` | AS_REP（AS → Client） |
| `0x03` | TGS_REQ（Client → TGS） |
| `0x04` | TGS_REP（TGS → Client） |
| `0x05` | AP_REQ（Client → V） |
| `0x06` | AP_REP（V → Client） |
| `0x07` | 业务消息（Client → V，认证后） |
| `0xff` | 错误响应（任意节点发出） |

---

## 1.5　统一日志格式规范

<br/>


日志是系统调试与验收的核心手段。所有节点使用同一结构化日志格式，确保可用 `grep` 或简单的日志分析工具进行全链路问题定位。

**日志行格式**：

```
[TIMESTAMP_ISO8601] [LEVEL] [NODE] [CLIENT_ID] [MSG_TYPE] [SEQ=N] [FUNC_NAME] MESSAGE
```

**字段说明**：

- `TIMESTAMP_ISO8601`：精确到毫秒，如 `2026-05-01T10:23:45.123Z`
- `LEVEL`：`DEBUG` / `INFO` / `WARN` / `ERROR` / `SECURITY`。其中 `SECURITY` 级别专用于安全事件（验签失败、身份伪造嫌疑、HMAC 校验失败等）
- `NODE`：节点标识，如 `AS`、`TGS`、`V`、`CLIENT_1`
- `CLIENT_ID`：当前操作关联的客户端 ID，无关联时填 `-`
- `MSG_TYPE`：当前处理的报文类型，如 `AS_REQ`、`AP_REQ`，无关联时填 `-`

**示例**：

```
[2026-05-01T10:23:45.123Z] [INFO]     [AS]      [CLIENT_1] [AS_REQ]  [SEQ=42]  [krb_handle_as_req]
    TGT issued successfully. K_c_tgs_sha256=a1b2c3d4..., lifetime=28800s, expire=1746441825

[2026-05-01T10:23:45.456Z] [SECURITY] [V]       [CLIENT_2] [AP_REQ]  [SEQ=7]   [krb_rsa_verify]
    RSA signature verification FAILED. err=-3006. Possible forgery attack. client_ip=192.168.1.102

[2026-05-01T10:23:45.789Z] [WARN]     [TGS]     [CLIENT_3] [TGS_REQ] [SEQ=15]  [krb_antireplay_check]
    Replay attack detected. ERR_REPLAY_TIMESTAMP. ts_diff=8s, client_ip=192.168.1.103

[2026-05-01T10:23:46.001Z] [INFO]     [CLIENT_1] [-]        [-]       [-]       [client_do_ap]
    AP authentication complete. Double-sided RSA verification passed. Session established.
```

**注意事项**：
- 日志中 **禁止记录任何明文密钥**（Kc、K_c, tgs、K_c, v 等）。若需记录密钥用于调试，只能记录其 SHA-256 摘要（前 8 字节的十六进制表示）
- 日志中 **禁止记录明文 CLI 指令的完整内容**，只记录指令的哈希值和执行结果状态（成功/失败）
- 加密性能敏感路径（AES 加解密、RSA 模幂）需记录 `DEBUG` 级别耗时日志，格式：`[elapsed=12.3ms]`
- 日志必须持久化到独立的 `security.log` 文件，且该文件不可通过 WebUI 删除

---

## 1.6　配置文件模板

<br/>


各节点使用 JSON 格式配置文件，路径通过命令行参数 `--config` 指定，默认查找当前目录下的 `config.json`。

```json
{
  "node_id": "AS",
  "listen_host": "0.0.0.0",
  "listen_port": 8881,
  "thread_pool_size": 8,
  "anti_replay_window_size": 1024,
  "ticket_lifetime_sec": 28800,
  "max_clients": 16,
  "cert_path": "./certs/as_cert.json",
  "privkey_path": "./keys/as_priv.json",
  "log_level": "INFO",
  "log_file": "./logs/as.log",
  "security_log_file": "./logs/security.log",
  "webui_host": "0.0.0.0",
  "webui_port": 9881,
  "k_tgs_path": "./keys/k_tgs.bin",
  "client_db": [
    { "id": "CLIENT_1", "kc_path": "./keys/kc_client1.bin", "cert_path": "./certs/client1_cert.json" },
    { "id": "CLIENT_2", "kc_path": "./keys/kc_client2.bin", "cert_path": "./certs/client2_cert.json" },
    { "id": "CLIENT_3", "kc_path": "./keys/kc_client3.bin", "cert_path": "./certs/client3_cert.json" },
    { "id": "CLIENT_4", "kc_path": "./keys/kc_client4.bin", "cert_path": "./certs/client4_cert.json" }
  ]
}
```

> TGS 节点额外包含 `"k_v_path"` 字段（与 V 共享的长期密钥路径）；V 节点额外包含 `"k_v_path"` 和 `"cli_whitelist"` 字段；Client 节点包含 `"as_host"`、`"as_port"`、`"tgs_host"`、`"tgs_port"`、`"v_host"`、`"v_port"` 等远端地址配置。

---

# 第二章　加密模块设计

<br/>


## 2.0　总体说明

<br/>


> **核心约束：禁止调用任何第三方加解密库。** 包括但不限于 OpenSSL、PyCryptodome、javax.crypto、BouncyCastle、CryptoJS 等。所有加密相关功能（AES、SHA-256、HMAC、RSA）必须从算法原语开始手写实现。

这个约束是课程设计的核心考核点，目的是让开发者真正理解每个算法的内部工作机制。因此本章对每个算法的实现路径、数据结构和接口进行了详细规范，开发者只需按照本文档的指导实现即可，无需从零摸索算法细节。

加密模块独立于其他业务模块，位于 `common/crypto/` 目录下，便于单独编译、单独测试。每个算法有对应的单元测试文件，测试用例覆盖正常路径、边界条件和错误路径。

### 2.0.1 注意事项

<br/>


下面的算法（除 RSA-2048 以外）在代码实现中，最终要做到和标准库加解密函数互通，也就是 **自实现的加密算法和第三方加解密库标准算法能交叉相互调用，并且成功解析**

**注意以下事项：**

- **字节填充**：例如 **PKCS7 填充**、**PKCS#1 v1.5 编码（签名填充）**
- **字节序**：统一采用 **大端序**
- **密文块：** 密文填充时 **全部转为 uint8/bytes 二进制流，禁止使用 hex 或其他编码**

**算法验收标准**：以跑通根目录 `/test` 下对应的测试模块为底线，尽可能优化运算时间

---

## 2.1　AES-256-CBC

<br/>


### 2.1.1　算法背景

<br/>


AES（高级加密标准）是目前最广泛使用的对称加密算法。本项目使用 256 位密钥（32 字节），CBC（密码块链）工作模式。CBC 模式通过将前一个密文块与当前明文块进行 XOR 后再加密，使得相同的明文在不同位置产生不同的密文，有效抵御了 ECB 模式下的明文模式攻击。

AES-256 的核心参数：
- **密钥长度**：256 位（32 字节）
- **块大小**：128 位（16 字节）
- **轮数**：14 轮（比 AES-128 多 4 轮）
- **密钥扩展**：从 32 字节原始密钥扩展出 15 个轮密钥（每个 16 字节）

### 2.1.2　上下文结构体

<br/>


```c
#pragma pack(push, 1)
typedef struct {
    uint8_t  round_keys[15][16];  // 密钥扩展结果：14 轮加密 + 1 个初始轮密钥，共 15 组，每组 16 字节
    uint8_t  iv[16];              // CBC 模式的初始向量（Initialization Vector），加密前必须设置
    uint8_t  key[32];             // 保存原始 256 位密钥（便于调试和重新派生）
} AES256_Ctx;
#pragma pack(pop)
```

### 2.1.3　函数接口

<br/>


```c
// 初始化上下文：执行密钥扩展，将 key 和 iv 存入 ctx
// key: 32 字节密钥; iv: 16 字节初始向量（加密时使用，解密时须与加密时相同）
int32_t aes256_init(const uint8_t key[32], const uint8_t iv[16], AES256_Ctx* ctx);
// 返回：KRB_OK | ERR_AES_KEY_LEN(-3001)

// 单块 ECB 加密（内部原语，不直接对外使用）：对 16 字节明文块执行 14 轮 AES 加密
int32_t aes256_encrypt_block(const uint8_t in[16], AES256_Ctx* ctx, uint8_t out[16]);

// 单块 ECB 解密（内部原语）：对 16 字节密文块执行 14 轮 AES 解密
int32_t aes256_decrypt_block(const uint8_t in[16], AES256_Ctx* ctx, uint8_t out[16]);

// CBC 模式加密（对外接口）
// plain: 明文字节数组; plain_len: 明文字节数（任意长度，函数内部自动 PKCS7 填充）
// cipher: 输出密文缓冲区（调用方分配，大小 ≥ plain_len + 16，即最多多一个填充块）
// cipher_len: 输出的密文实际字节数（= ((plain_len / 16) + 1) * 16，始终是 16 的倍数）
int32_t aes256_cbc_encrypt(
    const uint8_t* plain, uint32_t plain_len,
    AES256_Ctx* ctx,
    uint8_t* cipher, uint32_t* cipher_len
);
// 返回：KRB_OK | ERR_AES_KEY_LEN | ERR_AES_PADDING(-3002) | ERR_BUF_TOO_SMALL(-1007)

// CBC 模式解密（对外接口）
// cipher: 密文（必须是 16 的倍数，否则视为 ERR_AES_DECRYPT_FAIL）
// plain: 输出明文缓冲区（调用方分配，大小 ≥ cipher_len）
// plain_len: 去除 PKCS7 填充后的明文字节数
int32_t aes256_cbc_decrypt(
    const uint8_t* cipher, uint32_t cipher_len,
    AES256_Ctx* ctx,
    uint8_t* plain, uint32_t* plain_len
);
// 返回：KRB_OK | ERR_AES_KEY_LEN | ERR_AES_DECRYPT_FAIL(-3003)
```

### 2.1.4　实现要点

<br/>


**S-Box（替换字节）**：AES 规范中定义了固定的 256 字节 S-Box 查找表（正向）和 InvS-Box 查找表（逆向），直接硬编码为常量数组即可，无需运行时生成。

**密钥扩展（KeyExpansion）**：
1. 将 32 字节密钥分为 8 个 32 位字（W [0]~W [7]）
2. 从 W [8] 开始迭代计算，规则如下：
   - 若 `i mod 8 == 0`：`W[i] = W[i-8] ⊕ SubWord(RotWord(W[i-1])) ⊕ Rcon[i/8]`
   - 若 `i mod 8 == 4`：`W[i] = W[i-8] ⊕ SubWord(W[i-1])`
   - 其他：`W[i] = W[i-8] ⊕ W[i-1]`
3. 共计算到 W [59]，生成 60 个字，对应 15 组轮密钥

**GF(2^8) 乘法（MixColumns 所需）**：定义 `xtime(a)` 函数实现 GF(2^8) 中乘以 2 的操作：若 a 的最高位为 0，则左移 1 位；若为 1，则左移 1 位后 XOR `0x1b`（不可约多项式）。乘以 3 = xtime(a) ⊕ a，以此类推可实现 MixColumns 所需的所有系数。

**PKCS7 填充**：填充字节的值等于需要填充的字节数量。若明文长度恰好是 16 的倍数，仍需追加 16 字节（值均为 `0x10`）的填充，这样接收方才能明确区分数据结尾和填充结尾。解密时，取最后一个字节的值 `n`，验证末尾 `n` 个字节是否全等于 `n`，若不符合则报 `ERR_AES_DECRYPT_FAIL`。

**IV 传输约定**：加密时由加密方生成随机 16 字节 IV（调用 `krb_rand_bytes(iv, 16)`），将 IV **明文前置** 拼接在密文前一同发送（即实际发送：`IV(16字节) || 密文`）。解密方读取前 16 字节作为 IV，后续字节作为密文。此约定使得 IV 无需单独字段传输，但会使密文总长增加 16 字节——各 Payload 中的 `Cipher_Len` 字段包含 IV 的这 16 字节。

---

## 2.2　SHA-256

<br/>


### 2.2.1　算法背景

<br/>


SHA-256 是 SHA-2 系列哈希函数之一，输出固定 256 位（32 字节）的摘要。在本项目中用于两个场景：（1）RSA 签名前对消息的哈希计算；（2）HMAC-SHA256 的底层哈希函数。SHA-256 的安全性建立在其单向性（难以从摘要还原原始数据）和抗碰撞性（难以找到两个不同输入产生相同摘要）上。

### 2.2.2　上下文结构体

<br/>


```c
typedef struct {
    uint32_t h[8];          // 8 个 32 位哈希状态值（H0~H7），初始值为前 8 个素数平方根的小数部分
    uint8_t  buf[64];       // 512 位（64 字节）的消息块缓冲区，用于流式处理
    uint64_t total_bits;    // 已处理的消息总位数（用于最终填充步骤）
    uint32_t buf_len;       // buf 中当前已填充的有效字节数
} SHA256_Ctx;
```

### 2.2.3　函数接口

<br/>


```c
// 一次性计算接口（内部创建临时 ctx）：最常用接口
int32_t sha256(const uint8_t* data, uint32_t len, uint8_t digest[32]);
// 返回：KRB_OK | ERR_SHA256_FAIL(-3008)

// 流式接口（用于分块处理大数据）
int32_t sha256_init(SHA256_Ctx* ctx);    // 初始化 H0~H7 为标准初始值，清零其他字段
int32_t sha256_update(SHA256_Ctx* ctx, const uint8_t* data, uint32_t len);  // 追加数据
int32_t sha256_final(SHA256_Ctx* ctx, uint8_t digest[32]);   // 执行填充并输出最终摘要
```

### 2.2.4　实现要点

<br/>


**初始哈希值（H0~H7）**：这些是前 8 个素数（2, 3, 5, 7, 11, 13, 17, 19）的平方根的小数部分，取前 32 位（硬编码）：
```
H0=0x6a09e667, H1=0xbb67ae85, H2=0x3c6ef372, H3=0xa54ff53a,
H4=0x510e527f, H5=0x9b05688c, H6=0x1f83d9ab, H7=0x5be0cd19
```

**64 个轮常数（K [0]~K [63]）**：前 64 个素数立方根小数部分的前 32 位，同样硬编码为常量数组。

**消息填充规则（FIPS 180-4）**：在消息末尾追加 `0x80`，然后追加若干 `0x00` 字节，使总长度模 512 等于 448（即留出 64 位用于记录原始消息长度），最后追加原始消息位数的 64 位大端表示。

**压缩函数**：每轮使用 6 个逻辑函数：`Ch(e,f,g)=(e&f)^(~e&g)`，`Maj(a,b,c)=(a&b)^(a&c)^(b&c)`，`Σ0(a)=ROTR(2,a)^ROTR(13,a)^ROTR(22,a)`，`Σ1(e)=ROTR(6,e)^ROTR(11,e)^ROTR(25,e)`，`σ0(x)=ROTR(7,x)^ROTR(18,x)^SHR(3,x)`，`σ1(x)=ROTR(17,x)^ROTR(19,x)^SHR(10,x)`，其中 `ROTR(n,x)` 为 32 位循环右移。

---

## 2.4　RSA-2048

<br/>


> **注意**：标准 RSA-2048 需要处理复杂的 ASN.1 结构，实现相当复杂，所以只要求算法能给出 n, e, d 等参数
>
> 但是签名时仍然需要 PKCS#1 v1.5 编码填充，因为 RSA 数字签名 Sign 已约定为 256 字节

### 2.4.1　算法背景

<br/>


RSA 是最广泛使用的非对称加密算法。安全性基于大整数分解的计算困难性。在本项目中，RSA 仅用于数字签名（不用于加密数据，因为对称加密效率远高于 RSA）：Client 对每条消息用自己的 RSA 私钥签名，V 服务器用 Client 证书中的公钥验签，确保消息的不可否认性（即 Client 无法否认发送过该消息）。

RSA-2048 的参数：
- **模数 n**：2048 位（256 字节）= 两个 1024 位素数 p 和 q 的乘积
- **公钥指数 e**：通常为 65537（`0x010001`）
- **私钥指数 d**：满足 `e*d ≡ 1 (mod φ(n))`，φ(n) = (p-1)(q-1)
- **签名过程**：`s = m^d mod n`（其中 m 是经 PKCS#1 v1.5 编码后的哈希值）
- **验签过程**：`m' = s^e mod n`，比较 m' 是否等于期望的 PKCS#1 v1.5 编码

### 2.4.2　大整数结构体

<br/>


2048 位整数用 32 个 64 位无符号整数（肢，limb）表示，按大端序存储（limbs [0] 为最高有效 64 位）：

```c
typedef struct {
    uint64_t limbs[32];  // 32 * 64 = 2048 位，limbs [0] 为最高有效位
} BigInt2048;

typedef struct {
    BigInt2048 n;    // 模数
    BigInt2048 e;    // 公钥指数（验签时使用）
    BigInt2048 d;    // 私钥指数（签名时使用，公钥结构中此字段为零）
    // 可选：保存 p、q 用于 CRT 优化，课设中可省略
} RSA_Key_t;
```

### 2.4.3　函数接口

<br/>


```c
// 模幂运算：result = base^exp mod mod（核心原语，供签名/验签调用）
// 使用从左到右二进制快速模幂算法（Left-to-Right Binary Exponentiation）
int32_t rsa_modexp(
    const BigInt2048* base, const BigInt2048* exp,
    const BigInt2048* mod,  BigInt2048* result
);
// 返回：KRB_OK | ERR_RSA_KEY_INVALID(-3004)

// 大整数加法：result = a + b（需处理进位，结果可能超过 2048 位，调用方须注意）
int32_t bigint_add(const BigInt2048* a, const BigInt2048* b, BigInt2048* result);

// 大整数乘法：将两个 2048 位数相乘，结果为 4096 位（临时中间值用）
// 注意：模幂计算中需要先乘后取模，中间结果可能需要 4096 位空间
// 课设中可使用学校乘法（schoolbook O(n^2)）实现，性能满足需求
int32_t bigint_mul_mod(const BigInt2048* a, const BigInt2048* b,
                       const BigInt2048* mod, BigInt2048* result);

// 大整数取模：result = a mod n
int32_t bigint_mod(const BigInt2048* a, const BigInt2048* n, BigInt2048* result);

// RSA 签名：对 msg_hash（32 字节）进行 PKCS#1 v1.5 编码后用私钥签名
// sig: 输出签名，调用方分配 256 字节缓冲区
// sig_len: 固定输出 256（2048/8），即使高位为零也做零填充
int32_t rsa_sign(
    const uint8_t*   msg_hash,   // [入] SHA-256 摘要，32 字节
    uint32_t         hash_len,   // [入] 固定为 32
    const RSA_Key_t* priv_key,   // [入] 包含有效 n 和 d 的私钥结构
    uint8_t*         sig,        // [出] 签名输出，256 字节
    uint32_t*        sig_len     // [出] 固定为 256
);
// 返回：KRB_OK | ERR_RSA_KEY_INVALID(-3004) | ERR_RSA_SIGN_FAIL(-3005)

// RSA 验签：用公钥恢复签名中的哈希值，与重新计算的哈希比对
int32_t rsa_verify(
    const uint8_t*   msg_hash,   // [入] 消息的 SHA-256 摘要，32 字节
    uint32_t         hash_len,   // [入] 固定为 32
    const RSA_Key_t* pub_key,    // [入] 包含有效 n 和 e 的公钥结构
    const uint8_t*   sig,        // [入] 待验证的签名，256 字节
    uint32_t         sig_len     // [入] 固定为 256
);
// 返回：KRB_OK | ERR_RSA_KEY_INVALID(-3004) | ERR_RSA_VERIFY_FAIL(-3006)
```

### 2.4.4　PKCS#1 v1.5 编码（签名填充）

<br/>


签名前需将 32 字节哈希值编码为 256 字节的 EM（Encoded Message）格式：

```
EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo || Hash
```

其中：

- `PS`：填充字符串，内容全为 `0xFF`，长度 = 256 - 3 - 19(DigestInfo 前缀) - 32(Hash) = **202 字节**

- `DigestInfo`（SHA-256 的 DER 编码前缀，固定 19 字节）：

  ```
  30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
  ```

- `Hash`：32 字节 SHA-256 摘要

验签时，公钥恢复出 EM 后，检查 `EM[0]=0x00`、`EM[1]=0x01`，找到第一个非 `0xFF` 字节位置（必须为 `0x00`），之后 19 字节须匹配 DigestInfo 前缀，最后 32 字节即为签名中携带的哈希值，与消息重新计算的哈希比对。

### 2.4.5　密钥生成策略

<br/>


RSA-2048 密钥对生成（需要寻找两个 1024 位素数）在普通 CPU 上耗时约 1~3 分钟（取决于随机数质量和素性测试次数）。**强烈建议** 在系统首次部署时预先生成所有节点的密钥对，保存为 JSON 文件（含 n、e、d 的十六进制字符串），运行时直接加载，避免每次启动都重新生成。

素性测试使用 **Miller-Rabin** 算法，对 1024 位候选素数运行 20 轮测试（误判概率 < 4^-20 ≈ 10^-12）

---

## 2.5　随机数生成

<br/>


所有密钥生成和 IV 生成必须使用密码学安全的伪随机数生成器（CSPRNG）：

```c
// 生成 len 字节的密码学安全随机数，写入 buf
// 内部实现：Linux/macOS 读取 /dev/urandom；Windows 调用 BCryptGenRandom
int32_t krb_rand_bytes(uint8_t* buf, uint32_t len);
// 返回：KRB_OK | ERR_KEY_DERIVE(-2006)（若系统熵源不可用）
```

---

# 第三章　AS（认证服务器）模块设计

<br/>


## 3.0　模块职责概述

<br/>


AS 是整个 Kerberos 体系的信任根。它是唯一知道每个客户端长期密钥 Kc 的服务器，也是唯一能够签发 TGT（Ticket Granting Ticket）的服务器。AS 的安全性直接决定整个系统的安全基线——如果 AS 被攻破，攻击者可以为任意客户端签发票据。

因此，AS 模块的设计遵循最小权限原则：
- AS 不保存 Session Key 的完整记录（避免密钥库被盗导致的大规模密钥泄露）
- AS 对外只开放 AS_REQ → AS_REP 这一种交互，不提供其他查询或修改接口
- WebUI 接口只展示摘要信息，不暴露任何密钥明文

## 3.1　内部数据结构

<br/>


```c
// 单个客户端注册记录（从配置文件加载，启动时读入内存）
typedef struct {
    uint64_t id_client;        // 客户端唯一 ID（64 位整数，对应证书中的 id 字段）
    uint8_t  kc[32];           // 与该客户端共享的长期对称密钥（预先配置，离线分发）
    Cert_t   cert;             // 该客户端的证书（含公钥，用于 V 验签时查询）
} AS_ClientRecord;

// AS 全局状态（整个进程生命周期内唯一实例）
typedef struct {
    AS_ClientRecord clients[16];    // 最多支持 16 个注册客户端
    uint32_t        client_count;   // 实际注册客户端数量
    uint8_t         k_tgs[32];      // AS 与 TGS 之间的长期共享密钥（用于加密 Ticket_TGS）
    RSA_Key_t       as_priv_key;    // AS 自身 RSA 私钥（当前版本 AS 不签名，但预留）
    Cert_t          as_cert;        // AS 自身证书
    AntiReplay_Ctx  replay_ctx;     // 全局防重放上下文
    pthread_mutex_t db_lock;        // 保护 clients 数组的读写锁
    // 统计信息（用于 WebUI 展示）
    uint32_t        total_tgt_issued;    // 自启动以来累计签发的 TGT 数量
    uint32_t        total_auth_fail;     // 认证失败次数
} AS_State;
```

## 3.2　线程模型

<br/>


```
主线程（Accept Loop）
    │
    ├─ accept() 新连接
    │
    ▼
工作队列（线程安全阻塞队列，存放 fd）
    │
    ├─ Worker Thread 1 ──→ 处理 AS_REQ → 构造 AS_REP → 发送 → 关闭 fd
    ├─ Worker Thread 2 ──→ 同上
    ├─ ...
    └─ Worker Thread N（N 由配置文件中 thread_pool_size 决定，默认 8）

WebUI 线程（独立运行，只读访问 AS_State，加读锁）
```

**连接模型**：AS 采用 "短连接" 模式，每次 AS_REQ/AS_REP 交互完成后即关闭 TCP 连接。这样设计是因为 AS 阶段仅在客户端启动时进行一次（或 TGT 过期后重新登录），不需要长连接。

## 3.3　核心处理函数

<br/>


### 3.3.1　`krb_handle_as_req()` — 主处理函数

<br/>


这是 AS 的核心业务逻辑函数，由工作线程调用。以下是完整的执行步骤描述：

```c
int32_t krb_handle_as_req(int client_fd, uint32_t client_ip, AS_State* state);
```

**执行步骤详解**：

1. **接收并解析首部**：调用 `krb_recv_full(fd, header_buf, 20)`，然后 `krb_unpack(header_buf, 20, &hdr)`。若 `hdr.msg_type != 0x01`，返回 `ERR_MSG_TYPE_INVALID`。

2. **接收 Payload**：根据 `hdr.total_len` 调用 `krb_recv_full(fd, payload_buf, hdr.total_len)`，解析 `AS_REQ` 结构（`ID_Client`、`ID_TGS`、`TS1`）。

3. **防重放检查**：调用 `krb_antireplay_check(hdr.timestamp, hdr.seq_num, &state->replay_ctx)`。失败时直接返回对应错误码，不发送任何响应（防止攻击者利用错误响应枚举时间窗口）。

4. **查找客户端记录**：调用 `as_find_client(state, id_client, &record)`。若未找到，发送 `ERR_CLIENT_NOT_FOUND` 错误响应并记录日志。**注意**：返回给客户端的错误信息不应区分 "用户不存在" 和 "密码错误"，统一返回 "认证失败"，防止用户枚举攻击。

5. **生成 Session Key**：调用 `krb_rand_bytes(k_c_tgs, 32)` 生成 256 位随机 Session Key。若失败，返回服务端错误。

6. **构造 Ticket_TGS 明文**：填充 `Ticket_TGS` 结构体：
   - `Key_c_tgs = k_c_tgs`
   - `ID_Client = req.id_client`
   - `AD_c = client_ip`（从 socket 层获取的客户端 IP，网络字节序转为主机序）
   - `ID_TGS = req.id_tgs`
   - `TS2 = time(NULL)`（当前时间）
   - `Lifetime = state->ticket_lifetime_sec`（从配置读取，默认 28800 秒）

7. **加密 Ticket_TGS**：生成随机 IV，调用 `aes256_cbc_encrypt(ticket_plain, ticket_plain_len, Kc=state->k_tgs, cipher, &cipher_len)`，得到 `Ticket_TGS` 密文。

8. **构造 AS_REP_Inner 明文**：拼装 `AS_REP_Inner || Ticket_Len(4B) || Ticket_TGS_cipher`，此为整体 inner_plain。

9. **加密 inner_plain**：生成另一个随机 IV，调用 `aes256_cbc_encrypt(inner_plain, inner_len, Kc=record->kc, enc_part, &enc_part_len)`，得到最终 `Enc_Part`。

10. **构造 AS_REP Payload**：拼装 `Cipher_Len(4B, 大端) || Enc_Part`。

11. **封包并发送**：调用 `krb_pack(0x02, seq++, timestamp, payload, payload_len, out_buf, &out_len)`，然后 `send(fd, out_buf, out_len, 0)`。

12. **记录日志**：记录 `INFO` 级别日志，包含 `client_id`、`k_c_tgs_sha256`（仅前 8 字节十六进制）、`issued_at`、`lifetime`。

### 3.3.2　辅助函数

<br/>


```c
// 在 state-> clients 中按 id 线性查找（客户端数量 ≤ 16，O(16) 可接受）
int32_t as_find_client(AS_State* state, uint64_t id, AS_ClientRecord** out_record);
// 返回：KRB_OK | ERR_CLIENT_NOT_FOUND(-2001)

// 序列化 Ticket_TGS 明文结构体到字节数组（注意大端序写入各整型字段）
int32_t as_serialize_ticket_tgs(
    const uint8_t* k_ctgs,       // 32 字节 Session Key
    uint64_t       id_client,
    uint32_t       ad_c,         // 客户端 IPv4，主机序
    uint32_t       id_tgs,
    uint32_t       ts2,
    uint32_t       lifetime,
    uint8_t*       out,          // 输出字节数组（调用方分配，大小 = 56 字节）
    uint32_t*      out_len       // 输出字节数 = sizeof(Ticket_TGS) = 56
);

// 发送错误响应报文
int32_t as_send_error(int fd, int32_t err_code, uint32_t seq, uint32_t timestamp);
```

## 3.4　WebUI API 接口

<br/>


AS 的 WebUI 运行在独立 HTTP 端口（默认 9881），提供只读的监控和调试接口。

| 路径 | 方法 | 说明 | 返回 JSON 关键字段 |
|------|------|------|-------------------|
| `GET /api/status` | GET | AS 节点整体状态 | `{node_id, uptime_s, total_tgt_issued, total_auth_fail, thread_pool_size, thread_pool_busy, client_count}` |
| `GET /api/auth_log?limit=100&offset=0` | GET | 认证日志（分页，时间倒序）| `{total, logs: [{ts, client_id, result, tgt_sha256, lifetime}]}` |
| `GET /api/clients` | GET | 已注册客户端列表 | `{clients: [{id, cert_id, cert_expire}]}` |
| `GET /api/cert/:id` | GET | 获取指定客户端证书 | `{id, public_key:{n,e}, expire, sign}` |
| `GET /api/keys_summary` | GET | 已分发密钥摘要（不含明文）| `{keys: [{client_id, k_ctgs_sha256, issued_at, expire_at}]}` |

---

# 第四章　TGS（票据许可服务器）模块设计

<br/>


## 4.0　模块职责概述

<br/>


TGS 是 Kerberos 单点登录（SSO）的核心。它接受 Client 持有的 TGT，在不重新要求用户提供密码的情况下，为客户端签发访问特定服务（V）所需的 Service Ticket。TGS 的存在使得系统可以横向扩展：无论添加多少个 V 服务器，Client 只需向同一个 TGS 请求对应的票据，而无需为每个服务重新认证。

TGS 与 AS 不同的是，TGS 不需要知道 Client 的原始密码（Kc），它只需要持有与 AS 共享的密钥 `K_tgs`（用于解密 TGT）和与各 V 服务器共享的密钥 `K_v`（用于加密 Ticket_V）。

## 4.1　内部数据结构

<br/>


```c
// TGS 已知的目标服务器（V）信息（可扩展为多个 V）
typedef struct {
    uint32_t id_v;           // V 服务器的唯一 ID
    uint8_t  k_v[32];        // 与该 V 服务器共享的长期密钥
    char     v_addr[64];     // V 服务器地址（供日志记录使用）
} TGS_ServiceRecord;

// TGS 全局状态
typedef struct {
    uint8_t          k_tgs[32];          // 与 AS 共享的长期密钥（用于解密 TGT）
    TGS_ServiceRecord services[8];       // 已知的 V 服务器（最多 8 个）
    uint32_t          service_count;
    RSA_Key_t         tgs_priv_key;      // TGS 私钥（预留）
    AntiReplay_Ctx    replay_ctx;
    pthread_mutex_t   state_lock;
    // 统计信息
    uint32_t          total_ticket_v_issued;
    uint32_t          total_auth_fail;
} TGS_State;
```

## 4.2　核心处理函数

<br/>


### 4.2.1　`krb_handle_tgs_req()` — 主处理函数

<br/>


```c
int32_t krb_handle_tgs_req(int client_fd, uint32_t client_ip, TGS_State* state);
```

**执行步骤详解**：

1. **接收并解析报文**：收首部，校验 `msg_type == 0x03`，收 Payload，防重放检查。

2. **解析 TGS_REQ Payload**：从 Payload 依次读取：
   - `ID_V`（4 字节大端）
   - `Ticket_Len`（4 字节大端）→ 读取 `Ticket_Len` 字节的 `Ticket_TGS` 密文
   - `Auth_Len`（4 字节大端）→ 读取 `Auth_Len` 字节的 `Authenticator_c` 密文

3. **解密 Ticket_TGS**：调用 `aes256_cbc_decrypt(ticket_cipher, ticket_len, K_tgs, ticket_plain, &plain_len)`，将明文解析为 `Ticket_TGS` 结构体。解密失败返回 `ERR_TICKET_INVALID`，并记录 SECURITY 日志。

4. **验证 Ticket 有效期**：`ticket.ts2 + ticket.lifetime > (uint32_t)time(NULL)`，若已过期返回 `ERR_TICKET_EXPIRED`。

5. **解密 Authenticator_c**：用从 Ticket 中恢复出的 `K_c_tgs` 解密 `Authenticator_c`，解析得到 `{ID_Client, AD_c, TS3}`。

6. **比对 ID_Client**：`auth.id_client` 必须等于 `ticket.id_client`，否则返回 `ERR_AUTH_MISMATCH`。

7. **比对 AD_c**：`auth.ad_c` 必须等于 `ticket.ad_c` 且等于当前连接的 `client_ip`，否则返回 `ERR_AD_MISMATCH`。**注意**：这一步骤会阻止中间人转发攻击（即攻击者截获到 TGS_REQ 报文后无法从自己的 IP 重放）。

8. **防重放 TS3**：验证 `TS3` 与当前时间差 ≤ 5s，且 Authenticator 未在窗口内出现过。

9. **查找目标服务记录**：根据 `req.id_v` 在 `state->services` 中查找对应的 `K_v`。

10. **生成 K_c, v**：调用 `krb_rand_bytes(k_cv, 32)` 生成新的 Session Key。

11. **构造 Ticket_V 明文并加密**：与 AS 构造 Ticket_TGS 的逻辑完全对称，只是使用 `K_v` 加密，内容为 `{K_c_v, ID_Client, AD_c, ID_V, TS4=now(), Lifetime}`。

12. **构造 TGS_REP_Inner 并整体加密**：拼装 `TGS_REP_Inner || Ticket_V_Len || Ticket_V_cipher`，用 `K_c,tgs`（从 Ticket 中获取）加密为 `Enc_Part`。

13. **封包发送 TGS_REP**，记录日志。

## 4.3　WebUI API 接口

<br/>


| 路径 | 方法 | 说明 | 返回关键字段 |
|------|------|------|-------------|
| `GET /api/status` | GET | TGS 节点状态 | `{node_id, uptime_s, total_ticket_v_issued, total_auth_fail}` |
| `GET /api/tgs_log?limit=100` | GET | TGS 请求日志 | `{logs: [{ts, client_id, id_v, result, k_cv_sha256}]}` |
| `GET /api/services` | GET | 已知 V 服务器列表 | `{services: [{id_v, addr}]}` |

---

# 第五章　V（应用服务器）模块设计

<br/>


## 5.0　模块职责概述

<br/>


V 是最终向用户提供业务服务的节点，同时也是安全防线的最后一道关卡。V 的设计体现了 "零信任"（Zero Trust）理念：不因为一个 Client 已经通过了 AP 认证就完全信任其后续的每条消息，而是对 **每一条 CLI 指令** 都进行 HMAC 完整性验证和 RSA 不可否认性验证。

这种 "一次授权，动态验签" 的设计意味着：
- 即使攻击者截获了 AP 认证完成后的 Session Key，也无法伪造新的 CLI 指令（因为没有 Client 的 RSA 私钥）
- 即使 Client 的 Session Key 泄露，Client 也无法否认自己签名过的指令（RSA 私钥保证不可否认性）

## 5.1　内部数据结构

<br/>


```c
// 每个 Client 对应的 Session（AP 认证完成后建立）
typedef struct {
    uint64_t  id_client;
    uint8_t   k_cv[32];          // 由 Ticket_V 中恢复的 Session Key
    uint32_t  ticket_expire;     // Ticket_V 的过期时间（Unix 时间戳）
    Cert_t    client_cert;       // Client 的证书（含公钥，用于 RSA 验签）
    uint32_t  client_ip;         // Client 的 IP（来自 AP_REQ 的 socket 层）
    AntiReplay_Ctx replay_ctx;   // 每个 Session 独立的防重放上下文（业务消息用）
    // 业务统计
    uint32_t  total_cmds_received;
    uint32_t  total_cmds_accepted;
    time_t    session_start_time;
    time_t    last_cmd_time;
    // 活跃标志
    int       is_active;         // 0 = 未使用，1 = 活跃
    pthread_mutex_t sess_lock;   // 每个 Session 独立的互斥锁
} V_Session;

// V 全局状态
typedef struct {
    uint8_t   k_v[32];           // 与 TGS 共享的长期密钥（用于解密 Ticket_V）
    RSA_Key_t v_priv_key;        // V 自身 RSA 私钥（用于 AP_REP 签名）
    Cert_t    v_cert;
    V_Session sessions[16];      // 最多同时支持 16 个活跃 Session
    AntiReplay_Ctx ap_replay_ctx; // AP_REQ 阶段的防重放上下文
    pthread_mutex_t sessions_lock;
    // 命令日志（环形缓冲）
    char      cmd_log[1024][256]; // 最近 1024 条命令记录
    uint32_t  cmd_log_head;
    pthread_mutex_t cmd_log_lock;
} V_State;
```

## 5.2　AP 认证处理函数

<br/>


### 5.2.1　`krb_handle_ap_req()` — AP 认证主处理函数

<br/>


```c
int32_t krb_handle_ap_req(int client_fd, uint32_t client_ip, V_State* state);
```

**执行步骤详解**：

1. **收包、防重放**：同前述各节点逻辑，校验 `msg_type == 0x05`。

2. **解析 AP_REQ Payload**：依次读取：
   - `Ticket_Len` + `Ticket_V`（密文）
   - `Auth_Len` + `Authenticator_c`（密文）
   - `Sig_Len` + `Signature_c`（RSA 签名）

3. **解密 Ticket_V**：用 `K_v` 解密，得到 `{K_c_v, ID_Client, AD_c, ID_V, TS4, Lifetime}`。失败记录 SECURITY 日志。

4. **验证 Ticket 有效期**：`TS4 + Lifetime > now()`。

5. **解密 Authenticator_c**：用 Ticket 中的 `K_c_v` 解密，得到 `{ID_Client, AD_c, TS5}`。

6. **比对字段**：`auth.ID_Client == ticket.ID_Client`，`auth.AD_c == client_ip`，TS5 防重放。

7. **RSA 验签**（核心不可否认步骤）：
   - 调用 `sha256(authenticator_c_cipher, auth_cipher_len, msg_hash)`（对 Authenticator_c **密文** 求哈希，而非明文）
   - 调用 `cert_find_by_id(id_client, ...)` 获取 Client 证书
   - 调用 `rsa_verify(msg_hash, 32, &client_pub_key, signature_c, sig_len)`
   - 若返回 `ERR_RSA_VERIFY_FAIL`，记录 SECURITY 日志（含 client_ip、client_id、时间戳），**立即拒绝请求**，不建立 Session

8. **建立 Session**：找到空闲的 `V_Session` 槽位（`is_active == 0`），填入 `K_c_v`、`ticket_expire`、`client_cert`、`client_ip`，设置 `is_active = 1`，初始化 Session 级别的防重放上下文。

9. **构造 AP_REP**：
   - 构造 `AP_REP_Inner = {TS5 + 1}`（证明 V 正确解密了 Authenticator，且不是重放）
   - 用 `K_c_v` AES 加密得到 `Enc_Part`
   - 计算 `SHA256(Enc_Part)` 得到 `ap_rep_hash`
   - 用 V 自身 RSA 私钥签名：`Signature_v = RSA_Sign(ap_rep_hash, V_priv_key)`
   - 拼装 Payload：`Cipher_Len || Enc_Part || Sig_Len || Signature_v`

10. **封包发送 AP_REP**，记录 INFO 日志。

### 5.2.2　`krb_handle_business_msg()` — 业务消息处理函数

<br/>


AP 认证完成后，TCP 连接保持长连接。Client 后续发来的业务消息（`msg_type == 0x07`）由此函数处理：

```c
int32_t krb_handle_business_msg(int client_fd, uint32_t client_ip, V_State* state);
```

业务消息 Payload 格式（详见第七章）：

```
Auth_Len(4B) || Authenticator_c_cipher(变长)
Cipher_Cmd_Len(4B) || Cipher_Cmd(变长)
Sig_Len(4B) || Signature_c(变长)
MAC_Len(4B) || MAC(32B)
```

**处理步骤**：

1. **定位 Session**：根据 socket 的 `client_ip` 和解密后的 Authenticator 中的 `ID_Client` 找到对应的 `V_Session`。

2. **验证 Session 有效期**：`session.ticket_expire > now()`，若过期则要求 Client 重新认证。

3. **HMAC 验证（完整性检查）**：
   - 计算 `HMAC-SHA256(K_c_v, Authenticator_cipher || Cipher_Cmd)`
   - 与报文中的 `MAC` 字段比对（时序安全比较）
   - 失败时返回 `ERR_HMAC_MISMATCH`，记录 SECURITY 日志

4. **RSA 验签（不可否认性验证）**：
   - 计算 `SHA256(Cipher_Cmd)`（对指令密文求哈希）
   - 调用 `rsa_verify(hash, 32, &session->client_cert.pub_key, Signature_c, sig_len)`
   - 失败时返回 `ERR_RSA_VERIFY_FAIL`，记录 SECURITY 日志，**不执行任何操作**

5. **解密 Cipher_Cmd**：用 `K_c_v` AES 解密得到 CLI 指令明文。

6. **CLI 白名单校验**：

   | 允许的指令 | 说明 |
   |-----------|------|
   | `echo <message>` | 回显消息，最大长度 256 字节 |
   | `status` | 返回 V 服务器当前状态（在线用户数、系统时间等）|
   | `list_sessions` | 列出当前所有活跃 Session 的 Client ID |
   | `ping` | 返回 `pong`，用于测试连通性 |
   | `get_time` | 返回服务器当前 Unix 时间戳 |

   任何不在白名单中的指令一律拒绝，记录 SECURITY 日志（含指令内容的 SHA-256 哈希）。

7. **执行指令并构造响应**：执行白名单内的指令逻辑（无需 fork/exec，全部在进程内实现），将响应字符串 AES 加密后附 HMAC 发回 Client。

## 5.3　WebUI API 接口

<br/>


| 路径 | 方法 | 说明 | 返回关键字段 |
|------|------|------|-------------|
| `GET /api/status` | GET | V 节点状态 | `{node_id, uptime_s, active_sessions, total_cmds, total_rejected_cmds}` |
| `GET /api/auth_log?limit=100` | GET | AP 认证日志 | `{logs: [{ts, client_id, client_ip, result, rsa_verify_result}]}` |
| `GET /api/cmd_log?limit=100` | GET | 命令执行日志 | `{logs: [{ts, client_id, cmd_hash, cmd_plain, hmac_ok, rsa_ok, result}]}` |
| `GET /api/sessions` | GET | 活跃 Session 列表 | `{sessions: [{client_id, client_ip, k_cv_sha256, expire_at, last_cmd_ts, total_cmds}]}` |
| `GET /api/cert/:id` | GET | 客户端证书 | `{id, public_key:{n,e}, expire, sign}` |
| `POST /api/verify_cert` | POST | 手动验证证书（调试用）| `{id, result:"ok"/"fail", reason}` |

---

# 第六章　Client 客户端模块设计

<br/>


## 6.0　模块职责概述

<br/>


Client 是用户与整个 Kerberos 安全系统交互的入口。它封装了 Kerberos 三阶段认证的完整流程，并在认证完成后提供安全的 CLI 指令发送能力。Client 对用户屏蔽了底层的加密、签名、封包等复杂细节，提供简洁的 WebUI 界面进行操作。

Client 持有最敏感的材料是自己的 RSA 私钥，这个私钥必须严格保存在本地，不能通过网络传输，也不能在日志中暴露（即使是哈希值也不建议记录）。

## 6.1　客户端状态机

<br/>


Client 的生命周期是一个严格的状态机：

```
STATE_INIT
    │── (用户点击登录) → client_do_as()
    ↓
STATE_AS_DONE (持有 TGT 和 K_c,tgs)
    │── client_do_tgs()
    ↓
STATE_TGS_DONE (持有 Ticket_V 和 K_c,v)
    │── client_do_ap()
    ↓
STATE_V_CONNECTED (Session 建立，可发送业务消息)
    │── client_send_cmd() (可反复调用)
    │
    ├── (Ticket_V 过期) ──→ STATE_TGS_DONE (重走 TGS + AP)
    ├── (TGT 过期)     ──→ STATE_INIT     (重走全流程)
    └── (网络断开)     ──→ STATE_INIT     (重新连接并认证)

STATE_ERROR (任何不可恢复错误) ──→ 展示错误信息，等待用户重新登录
```

## 6.2　内部数据结构

<br/>


```c
typedef enum {
    STATE_INIT = 0,
    STATE_AS_DONE,
    STATE_TGS_DONE,
    STATE_V_CONNECTED,
    STATE_ERROR,
} ClientFSMState;

typedef struct {
    // 身份信息
    uint64_t       id_client;        // 本 Client 的唯一 ID（与证书中 id 字段对应）
    uint8_t        kc[32];           // 与 AS 共享的长期对称密钥（离线配置）
    RSA_Key_t      client_priv_key;  // 本 Client 的 RSA 私钥
    Cert_t         client_cert;      // 本 Client 的证书

    // 状态机
    ClientFSMState state;

    // 阶段一结果（AS 阶段获得）
    uint8_t        k_c_tgs[32];      // Session Key（与 TGS 共享）
    uint8_t        ticket_tgs[512];  // Ticket_TGS 密文（原样保存，透传给 TGS）
    uint32_t       ticket_tgs_len;
    uint32_t       tgt_expire;       // TGT 过期时间（TS2 + Lifetime）

    // 阶段二结果（TGS 阶段获得）
    uint8_t        k_c_v[32];        // Session Key（与 V 共享）
    uint8_t        ticket_v[512];    // Ticket_V 密文（原样保存，透传给 V）
    uint32_t       ticket_v_len;
    uint32_t       ticket_v_expire;  // Ticket_V 过期时间（TS4 + Lifetime）

    // 序列号管理
    uint32_t       seq_num;          // 单调递增，每发一个报文自增

    // 通信日志（用于 WebUI 展示，环形缓冲）
    CommLogEntry   comm_log[200];
    uint32_t       comm_log_head;
    pthread_mutex_t log_lock;
} Client_Ctx;
```

## 6.3　核心流程函数

<br/>


### 6.3.1　`client_do_as()` — AS 阶段

<br/>


```c
int32_t client_do_as(Client_Ctx* ctx, const char* as_host, uint16_t as_port);
```

1. TCP 连接到 AS
2. 构造 AS_REQ Payload：`{ID_Client(8B大端) || ID_TGS(4B大端) || TS1=now()(4B大端)}`
3. `krb_pack(0x01, ctx->seq_num++, time(NULL), payload, payload_len, ...)` → `send()`
4. 接收 AS_REP：收首部，校验 `msg_type == 0x02`，收 Payload
5. 读取 `Cipher_Len(4B大端)`，读取 `Enc_Part`
6. `aes256_cbc_decrypt(Enc_Part, cipher_len, Kc=ctx->kc, inner_plain, &inner_len)`
7. 从 `inner_plain` 解析：前 40 字节为 `AS_REP_Inner`（含 K_c, tgs），之后 4 字节为 `Ticket_Len`，之后 `Ticket_Len` 字节为 `Ticket_TGS` 密文
8. 保存 `K_c,tgs` 到 `ctx->k_c_tgs`，保存 `Ticket_TGS` 密文到 `ctx->ticket_tgs`，计算 `ctx->tgt_expire = AS_REP_Inner.ts2 + AS_REP_Inner.lifetime`
9. 设置 `ctx->state = STATE_AS_DONE`
10. 关闭 TCP 连接，记录通信日志（明文 / 密文 Hex / 时间戳）

### 6.3.2　`client_do_tgs()` — TGS 阶段

<br/>


```c
int32_t client_do_tgs(Client_Ctx* ctx, const char* tgs_host, uint16_t tgs_port, uint32_t id_v);
```

1. TCP 连接到 TGS
2. 生成随机 IV，构造 `Authenticator_c` 明文：`{ID_Client || AD_c=local_ip || TS3=now()}`
3. `aes256_cbc_encrypt(auth_plain, 16, K_c_tgs, auth_cipher, &auth_cipher_len)`
4. 拼装 TGS_REQ Payload：`ID_V(4B) || Ticket_Len(4B) || Ticket_TGS(密文) || Auth_Len(4B) || Authenticator_cipher`
5. 封包、发送
6. 接收 TGS_REP，读取 `Cipher_Len`，读取 `Enc_Part`
7. `aes256_cbc_decrypt(Enc_Part, K_c_tgs, inner_plain, ...)` → 解析 `TGS_REP_Inner`（含 K_c, v）和 `Ticket_V` 密文
8. 保存 `K_c,v` 和 `Ticket_V` 密文，计算 `ticket_v_expire`
9. 设置 `ctx->state = STATE_TGS_DONE`

### 6.3.3　`client_do_ap()` — AP 阶段（含 RSA 签名）

<br/>


```c
int32_t client_do_ap(Client_Ctx* ctx, const char* v_host, uint16_t v_port);
```

1. TCP 连接到 V（此连接保持长连接，用于后续业务消息）
2. 构造 `Authenticator_c` 明文：`{ID_Client || AD_c || TS5=now()}`，用 `K_c,v` 加密得 `auth_cipher`
3. **RSA 签名**：`sha256(auth_cipher, auth_cipher_len, hash)` → `rsa_sign(hash, 32, ctx->client_priv_key, sig, &sig_len)`
4. 拼装 AP_REQ Payload：`Ticket_V_Len || Ticket_V || Auth_Len || auth_cipher || Sig_Len || sig`
5. 封包、发送
6. 接收 AP_REP，读取 `Cipher_Len`，读取 `Enc_Part`，读取 `Sig_Len`，读取 `Signature_v`
7. **验证 V 的 RSA 签名**：`sha256(Enc_Part, ..., hash)` → `rsa_verify(hash, V_pub_key, Signature_v, sig_len)`，失败返回错误
8. 解密 `Enc_Part`：得到 `{TS5_plus_1}`，验证 `TS5 + 1 == TS5_plus_1`（证明 V 真正解密成功）
9. 双向认证完成，设置 `ctx->state = STATE_V_CONNECTED`，保存 V 的 TCP 连接 fd

### 6.3.4　`client_send_cmd()` — 发送业务消息

<br/>


```c
int32_t client_send_cmd(
    Client_Ctx* ctx,
    const char* cmd,          // 明文 CLI 指令字符串
    char*       resp_buf,     // 响应输出缓冲区（调用方分配）
    uint32_t*   resp_len      // 响应字节数
);
```

1. 验证 `ctx->state == STATE_V_CONNECTED`，检查 Session 未过期
2. 构造新的 `Authenticator_c`（含当前时间戳，防止指令重放）并加密
3. `aes256_cbc_encrypt(cmd, strlen(cmd), K_c_v, cipher_cmd, &cipher_cmd_len)` — 加密指令
4. **RSA 签名指令密文**：`sha256(cipher_cmd, ..., hash)` → `rsa_sign(hash, ctx->client_priv_key, sig, ...)`
5. **计算 HMAC**：`hmac_sha256(K_c_v, auth_cipher || cipher_cmd, mac)`
6. 拼装业务消息 Payload，封包发送
7. 接收响应，解密，返回明文响应
8. 更新通信日志（明文指令、密文 Hex、签名 Hex、响应）

## 6.4　SSO 复用逻辑

<br/>


```c
// 在发送每条业务消息前调用，决定是否需要重认证
int32_t client_ensure_session(Client_Ctx* ctx, const char* tgs_host, uint16_t tgs_port,
                               const char* v_host, uint16_t v_port, uint32_t id_v) {
    uint32_t now = (uint32_t)time(NULL);
    if (ctx->state == STATE_V_CONNECTED && ctx->ticket_v_expire > now + 60) {
        return KRB_OK;  // Session 仍有效，直接使用
    }
    if (ctx->state >= STATE_AS_DONE && ctx->tgt_expire > now + 60) {
        // TGT 仍有效，只需重走 TGS + AP
        client_do_tgs(ctx, tgs_host, tgs_port, id_v);
        client_do_ap(ctx, v_host, v_port);
        return KRB_OK;
    }
    // TGT 也过期，需要重新登录（提示用户输入密码重新走 AS 阶段）
    return ERR_TICKET_EXPIRED;
}
```

## 6.5　WebUI API 接口（Client）

<br/>


| 路径 | 方法 | 说明 | 请求/返回 |
|------|------|------|-----------|
| `POST /api/login` | POST | 触发 AS → TGS → AP 三阶段认证 | 请求：`{username}` 返回：`{state, tgt_expire, tv_expire}` |
| `GET /api/state` | GET | 当前 Client 状态 | `{state, k_ctgs_sha256, k_cv_sha256, tgt_expire, tv_expire, seq_num}` |
| `POST /api/send_cmd` | POST | 发送 CLI 指令 | 请求：`{cmd}` 返回：`{cmd_plain, cipher_hex, sig_hex, mac_hex, response, verify_result}` |
| `GET /api/cert` | GET | 本 Client 证书 | `{id, public_key:{n,e}, expire, sign}` |
| `GET /api/comm_log?limit=50` | GET | 通信记录（最近 N 条）| `{logs: [{ts, type, plain, cipher_hex, sig_hex, verify_result, rsa_ok}]}` |

---

# 第七章　封包与拆包详细设计

<br/>


## 7.1　TCP 粘包问题与解决方案

<br/>


TCP 是字节流协议，不保证每次 `recv()` 调用能收到完整的应用层消息。例如，一次 `send(2000 bytes)` 可能导致接收方两次 `recv()` 分别收到 1000 字节。这种现象称为 "TCP 粘包"（更准确地说是 "TCP 截包"）

本协议通过 **两步接收** 解决此问题：
1. **第一步**：`krb_recv_full(fd, buf, 20)` — 确保收满 20 字节的固定长度首部
2. **第二步**：解析首部得到 `total_len`，然后 `krb_recv_full(fd, payload_buf, total_len)` — 确保收满完整 Payload

`krb_recv_full()` 内部循环调用 `recv()`，保证读满指定字节数：

```c
int32_t krb_recv_full(int fd, uint8_t* buf, uint32_t need) {
    uint32_t received = 0;
    while (received < need) {
        int n = recv(fd, buf + received, need - received, 0);
        if (n <= 0) {
            // n == 0: 对端正常关闭连接
            // n < 0: 系统错误（EINTR、ECONNRESET 等）
            return ERR_SOCKET_RECV;
        }
        received += (uint32_t)n;
    }
    return KRB_OK;
}
```

## 7.2　完整封包流程

<br/>


```c
// 以发送 AP_REQ 为例：

// 1. 构造 Payload（业务层负责）
uint8_t payload[4096];
uint32_t payload_len = 0;

// 写入 Ticket_Len（4 字节大端）
WRITE_U32_BE(payload + payload_len, ticket_v_len);  payload_len += 4;
// 写入 Ticket_V（密文，原样拷贝）
memcpy(payload + payload_len, ticket_v, ticket_v_len);  payload_len += ticket_v_len;
// 写入 Auth_Len
WRITE_U32_BE(payload + payload_len, auth_cipher_len);  payload_len += 4;
// 写入 Authenticator_c 密文
memcpy(payload + payload_len, auth_cipher, auth_cipher_len);  payload_len += auth_cipher_len;
// 写入 Sig_Len
WRITE_U32_BE(payload + payload_len, sig_len);  payload_len += 4;
// 写入 Signature_c
memcpy(payload + payload_len, sig, sig_len);  payload_len += sig_len;

// 2. 封包（添加首部）
uint8_t out_buf[5000];
uint32_t out_len = 0;
krb_pack(0x05, ctx->seq_num++, (uint32_t)time(NULL), payload, payload_len, out_buf, &out_len);

// 3. 发送
send(fd, out_buf, out_len, 0);
```

## 7.3　完整拆包流程

<br/>


```c
// 通用接收逻辑（所有节点的 Worker 线程使用）：

uint8_t header_buf[20];
Ker_Header hdr;

// Step 1: 收首部
if (krb_recv_full(fd, header_buf, 20) != KRB_OK) { /* 关闭连接 */ }

// Step 2: 解析首部（字节序转换在内部完成）
if (krb_unpack(header_buf, 20, &hdr) != KRB_OK) { /* 丢弃 */ }

// Step 3: 防止超大 Payload 攻击
if (hdr.total_len > MAX_PAYLOAD_LEN /* 64KB */) { return ERR_PAYLOAD_TOO_LARGE; }

// Step 4: 分配并收取 Payload
uint8_t* payload = malloc(hdr.total_len);
if (krb_recv_full(fd, payload, hdr.total_len) != KRB_OK) { free(payload); /* 关闭连接 */ }

// Step 5: 防重放（时间戳和序列号检查）
if (krb_antireplay_check(hdr.timestamp, hdr.seq_num, &node_replay_ctx) != KRB_OK) {
    free(payload);
    // 可选：发送错误响应
    return; 
}

// Step 6: 根据 msg_type 分发处理
switch (hdr.msg_type) {
    case 0x01: handle_as_req(fd, payload, hdr.total_len, state); break;
    case 0x03: handle_tgs_req(fd, payload, hdr.total_len, state); break;
    // ...
}
free(payload);
```

## 7.5　字节序转换宏定义

<br/>


```c
/* 大端序写入宏（向 buf 指针指向的位置写入整数，buf 类型为 uint8_t* ）*/
#define WRITE_U8_BE(buf, val)   ((buf)[0] = (uint8_t)(val))
#define WRITE_U16_BE(buf, val)  ((buf)[0] = (uint8_t)((val) >> 8), \
                                 (buf)[1] = (uint8_t)((val) & 0xFF))
#define WRITE_U32_BE(buf, val)  ((buf)[0] = (uint8_t)((val) >> 24), \
                                 (buf)[1] = (uint8_t)((val) >> 16), \
                                 (buf)[2] = (uint8_t)((val) >> 8),  \
                                 (buf)[3] = (uint8_t)((val) & 0xFF))
#define WRITE_U64_BE(buf, val)  /* 类推 8 字节，从最高字节到最低字节依次写入 */

/* 大端序读取宏（从 buf 读取整数，返回主机序整数值）*/
#define READ_U8_BE(buf)   ((uint8_t)(buf)[0])
#define READ_U16_BE(buf)  (((uint16_t)(buf)[0] << 8) | (uint16_t)(buf)[1])
#define READ_U32_BE(buf)  (((uint32_t)(buf)[0] << 24) | ((uint32_t)(buf)[1] << 16) | \
                           ((uint32_t)(buf)[2] <<  8) |  (uint32_t)(buf)[3])
#define READ_U64_BE(buf)  /* 类推 8 字节 */
```

---

# 第八章　自定义证书设计

<br/>


## 8.1　证书的作用

<br/>


在本项目中，证书（Certificate）是绑定 "身份 ID" 与 "RSA 公钥" 的凭证，类似于现实中的身份证。

证书解决了这样一个问题：V 服务器需要知道 "用哪个公钥来验签"——而公钥由 AS 颁发的证书提供，V 通过查询 AS 的证书接口获取 Client 的公钥。

证书的可信度来自 **自签名**：证书中的 `sign` 字段是主体用自己的 RSA 私钥对证书核心内容（id + issuer + public_key + expire）的签名。这意味着只有持有对应私钥的一方才能生成有效证书，任何第三方篡改证书内容后 `sign` 字段将无法通过验证。

> **注意**：本项目的证书是 "自签名" 的简化版证书，不是 X.509 证书体系
>
> 在真实场景中，证书应由受信任的第三方 CA（证书颁发机构）签发；课设中由课程组织者统一离线生成分发

## 8.2　证书 JSON 格式

<br/>


以下是使用 json 进行简易证书封装，证书结构示例：

```json
{
  "id": "CLIENT_1",
  "issuer": "MY_ROOT_CA",
  "public_key": {
    "n": "00c4d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1...",
    "e": "010001"
  },
  "expire": "2026-12-31",
  "sign": "3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3..."
}
```

**字段说明**：
- `id`：主体唯一标识。Client 使用 `CLIENT_1`~`CLIENT_4`，V 服务器使用 `verify_server`
- `issuer`：签发者字段，CA 机构的标识符，作为证书签名的机构背书
- `public_key.n`：RSA 模数，2048 位，十六进制字符串（512 个十六进制字符）
- `public_key.e`：RSA 公钥指数，通常为 `010001`（十进制 65537）
- `expire`：证书有效期，格式 `YYYY-MM-DD`，课设中设置为足够长的期限（如 `2027-12-31`）
- `sign`：主体对字符串 `id + issuer + json(public_key) + expire` 的 SHA-256 哈希的 RSA 签名，Base64 编码

## 8.4　证书生成脚本（离线，Python 参考实现）

<br/>


证书 **生成** 是离线一次性操作，可以使用库辅助生成（仅用于初始化阶段，不含在提交的系统代码中）：

```python

```

---

# 第九章　完整通信时序规范及报文格式

<br/>


本章以教材 PPT 的三阶段划分为基础，给出每个消息的完整字段说明、加密密钥和处理逻辑，供开发人员直接参考实现。

## 数据类型别名定义

<br/>


为以下协议要用到的数据类型定义别名，防止歧义：

| **类型名称**   |                    **描述 (Description)**                    |
| -------------- | :----------------------------------------------------------: |
| **uint8/byte** |                 8 位无符号整数 / 字节 (Byte)                  |
| **uint16**     |            16 位无符号整数，大端序 (用于长度前缀)             |
| **uint32**     |      32 位无符号整数，大端序 (用于时间戳、长度、序列号)       |
| **uint64**     |                    64 位无符号整数，大端序                    |
| **int32**      |               32 位有符号整数，大端序（错误码）               |
| **Kstring**    | 变长字符串结构：由 `uint16` (长度) 后跟 `N` 字节 UTF-8 字符组成，物理布局:(string_len(uint16)\|\|string_data))（c/c++实现时注意：其中 string_data 不包含终止符'\0'） |

## 通用协议报文首部（Protocol Header）

<br/>


所有协议通用的首部：

- 在解析封包中，先尝试解析固定 **20 字节** 的首部，首先匹配 Magic Number 是否合法
- 根据报文类型选择相应的结构体解析
- 根据 TotalLength 作为读取的 PayLoad 字节长度，防止 TCP“截包”

**下面的首部包括 PayLoad 的内存布局应严格对齐**，**不允许编译器隐式 Padding：**

![image.png](https://cdn.nlark.com/yuque/0/2026/png/55005423/1776349296508-e01d3ff2-a158-4ad5-9a69-c00416e47484.png?x-oss-process=image%2Fformat%2Cwebp)

```cpp
#pragma pack(push, 1)
struct Ker_Header {
    uint16_t magic;      // 固定值 0x4B45，标识 Kerberos 协议报文
    uint8_t  version;    // 协议版本，当前固定为 0x01
    uint8_t  msg_type;   // 报文类型（见下表）
    uint32_t total_len;  // Payload 字节数（不含首部的 20 字节本身）
    uint32_t seq_num;    // 序列号，发送方维护，单调递增，用于防重放
    uint32_t timestamp;  // 发送方当前 Unix 时间戳，用于时钟同步和防重放
    uint32_t addition;   // 保留字段，当前全填 0x00000000，用于后续版本扩展
};
#pragma pack(pop)
// sizeof(Ker_Header) 必须恰好等于 20 字节，请在编译期用 static_assert 验证
```

| `msg_type` 值 | 含义                           |
| :-----------: | ------------------------------ |
|    `0x01`     | AS_REQ（Client → AS）          |
|    `0x02`     | AS_REP（AS → Client）          |
|    `0x03`     | TGS_REQ（Client → TGS）        |
|    `0x04`     | TGS_REP（TGS → Client）        |
|    `0x05`     | AP_REQ（Client → V）           |
|    `0x06`     | AP_REP（V → Client）           |
|    `0x07`     | 业务消息（Client → V，认证后） |
|    `0xff`     | 错误响应（任意节点发出）       |

## 9.1　阶段一：Client ↔ AS（消息 1 和 2）

<br/>


**目的**：Client 向 AS 证明自己知道长期密钥 Kc，获取 TGT 和 Session Key K_c, tgs。

---

### 消息 1（AS_REQ）：Client → AS

<br/>


> 注意该 Layout 视图包含以后的部分只包括 PayLoad 布局，简省了 Protocol Header(20 字节)
>
> 也即是以下部分的起始 Offset（偏移）为 0x20

| **相对偏移 (Relative Offset)** | **数据类型 (Type)** | **字段名 (Field Name)** | **说明 (Comment)**                                           |
| ------------------------------ | ------------------- | ----------------------- | ------------------------------------------------------------ |
| +0                             | **Kstring**         | **ID_Client**           | 客户端身份标识。包含 2 字节长度前缀 + 变长 UTF-8 字符串。    |
| + (2 + Len_Client)             | **Kstring**         | **ID_TGS**              | 目标 TGS 服务标识。包含 2 字节长度前缀 + 变长 UTF-8 字符串。 |
| + (4 + Len_Client + Len_TGS)   | **uint32**          | **TS1**                 | 客户端发送请求时的 Unix 时间戳（大端序）。                   |

```
0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   ID_Client_Len (uint16)      |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
|         ID_Client_Data (Kstring 的字符串内容部分)                |
|           (例如: "Alice" 或 "client_admin_01")                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     ID_TGS_Len (uint16)       |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
|          ID_TGS_Data (Kstring 的字符串内容部分)                 |
|           (例如: "TGS_Hubei_Region" 或 "TGS_1")               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      TS1 (Client Unix TS)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

AS 收到后：验证报文合法性 → 查找 ID_Client 对应记录 → 生成 K_c, tgs（随机 32 字节）→ 构造 Ticket_TGS → 用 Kc 加密整体响应内容

---

### 消息 2（AS_REP）：AS → Client

<br/>


此处有嵌套加密块，分三层讨论：

**第一层：外层传输布局：**

这是直接从 TCP 流中解出来的 Payload 部分，包含一个巨大的加密块。

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Cipher_Len                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  Enc_Part (AES-256-CBC 密文)                   |
|          (解密密钥: Kc)                                         |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

------

#### 第二层：Enc_Part 解密后的明文结构 (inner_plain)

<br/>


这是客户端用自己的密钥 `Kc` 解密后看到的布局。

| **相对偏移**         | **数据类型**  | **字段名**     | **说明 (Comment)**                            |
| -------------------- | ------------- | -------------- | --------------------------------------------- |
| +0                   | **uint8 [32]** | **Key_c_tgs**  | AS 分配给 C 和 TGS 的会话密钥 (Session Key)。 |
| +32                  | **Kstring**   | **ID_TGS**     | 目标 TGS 的身份标识（变长字符串）。           |
| + (32 + 2 + Len_TGS) | **uint32**    | **TS2**        | Ticket 的签发时间戳。                         |
| + (36 + 2 + Len_TGS) | **uint32**    | **Lifetime**   | Ticket 的有效期（秒）。                       |
| + (40 + 2 + Len_TGS) | **uint32**    | **Ticket_Len** | 后续 Ticket_TGS 密文块的字节数。              |
| + (44 + 2 + Len_TGS) | **uint8 []**   | **Ticket_TGS** | 由 $K_{tgs}$ 加密的密文块（客户端视作黑盒）。 |

```plain
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  Key_c_tgs (32字节 Session Key)                |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       ID_TGS_Len (uint16)     |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         ID_TGS_String         |
|             (变长，AS 告知客户端当前 TGS 的身份)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      TS2 (Ticket 签发时间)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Lifetime (有效期，秒)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Ticket_Len                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  Ticket_TGS (由 K_tgs 加密的密文)               |
|            (客户端不解密，直接原样透传给 TGS)                   |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

------

#### 第三层：Ticket_TGS 的内部结构 (由 TGS 服务器解析)

<br/>


如果 TGS 服务器拿到并解密了上面的 `Ticket_TGS`，它看到的布局如下：

| **相对偏移**             | **数据类型**  | **字段名**    | **说明 (Comment)**                     |
| ------------------------ | ------------- | ------------- | -------------------------------------- |
| +0                       | **uint8 [32]** | **Key_c_tgs** | Session Key，需与外层解出的一致。      |
| +32                      | **Kstring**   | **ID_Client** | **变长**：持票客户端的真实身份字符串。 |
| + (32 + 2 + Len_C)       | **uint32**    | **AD_c**      | 客户端网络地址或权限掩码。             |
| + (36 + 2 + Len_C)       | **Kstring**   | **ID_TGS**    | **变长**：校验该票据是否发给本 TGS。   |
| + (38 + Len_C + Len_TGS) | **uint32**    | **TS2**       | 签发时间戳，用于计算是否过期。         |
| + (42 + Len_C + Len_TGS) | **uint32**    | **Lifetime**  | 票据生命周期。                         |

```plain
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  Key_c_tgs (32字节 Session Key)                |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      ID_Client_Len (uint16)   |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+        ID_Client_String       |
|             (变长，告诉 TGS 持票人的身份)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           AD_c (4字节，用户网络地址或权限 Mask)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       ID_TGS_Len (uint16)     |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         ID_TGS_String         |
|             (变长，校验该票据是否发给本 TGS)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      TS2 (Ticket 签发时间)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Lifetime (有效期，秒)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 9.2　阶段二：Client ↔ TGS（消息 3 和 4）

<br/>


**目的**：Client 凭 TGT 向 TGS 请求访问 V 的票据，无需再次提供密码。

### 消息 3（TGS_REQ）：Client → TGS

<br/>


| **相对偏移 (Relative Offset)** | **数据类型 (Type)** | **字段名 (Field Name)** | **说明 (Comment)**                                          |
| ------------------------------ | ------------------- | ----------------------- | ----------------------------------------------------------- |
| +0                             | **Kstring**         | **ID_V**                | 客户端请求访问的目标业务服务器标识（变长字符串）。          |
| + (2 + Len_V)                  | **uint32**          | **Ticket_Len**          | 后续 `Ticket_TGS` 密文块的字节长度。                        |
| + (6 + Len_V)                  | **uint8 []**         | **Ticket_TGS**          | 从 AS 获取的票据，包含 Session Key 等信息，客户端原样透传。 |
| + (6 + Len_V + Ticket_Len)     | **uint32**          | **Auth_Len**            | 后续 `Authenticator_c` 密文块的字节长度。                   |
| + (10 + Len_V + Ticket_Len)    | **uint8 []**         | **Authenticator_c**     | 使用 $K_{c,tgs}$ 加密的验证器，证明客户端当前持有该密钥。   |

**Authenticator_c 内部明文布局表 (由 K_c_tgs 加密)**

当 TGS 服务器解开 Authenticator 时，看到的物理结构如下：

| **相对偏移**  | **数据类型** | **字段名**    | **说明 (Comment)**                                   |
| ------------- | ------------ | ------------- | ---------------------------------------------------- |
| +0            | **Kstring**  | **ID_Client** | 客户端身份字符串。**必须与 Ticket 内部记录的一致。** |
| + (2 + Len_C) | **uint32**   | **AD_c**      | 客户端网络地址（IPV4）                               |
| + (6 + Len_C) | **uint32**   | **TS3**       | 客户端发起该请求的当前 Unix 时间戳（防重放核心）。   |

```
0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       ID_V_Len (uint16)       |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+           ID_V_Data           |
|            (变长字符串，目标业务服务器的名称，如 "FileServer")      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Ticket_Len                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  Ticket_TGS (由 K_tgs 加密的密文)               |
|            (由 AS 签发，包含 Session Key 和客户信息               |
|                     获取于Message2,原样发送)                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Auth_Len                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|             Authenticator_c (由 K_c_tgs 加密的密文)             |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

TGS 收到后：用 K_tgs 解密 TGT → 获得 K_c, tgs → 用 K_c, tgs 解密 Authenticator → 字段比对校验 → 生成 K_c, v → 构造 Ticket_V → 加密响应

---

### 消息 4（TGS_REP）：TGS → Client

<br/>


在此阶段，TGS 服务器验证了客户端的请求，并向客户端发放访问业务服务器（ID_V）的 **服务票据（Service Ticket）**

**第一层：外层传输布局**

这是 TGS 回复给客户端的报文，包含一个由 `K_c_tgs`（客户端与 TGS 的会话密钥）加密的块。

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Cipher_Len                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  Enc_Part (AES-256-CBC 密文)                   |
|                        (解密密钥: K_c_tgs)                      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

------

#### 第二层：Enc_Part 解密后的明文结构 (inner_plain)

<br/>


客户端解开后，将获得与业务服务器通信的 `Key_c_v`。

| **相对偏移 (Relative Offset)** | **数据类型 (Type)** | **字段名 (Field Name)** | **说明 (Comment)**                                           |
| ------------------------------ | ------------------- | ----------------------- | ------------------------------------------------------------ |
| +0                             | **uint8 [32]**       | **Key_c_v**             | 客户端与业务服务器 V 通信的会话密钥 (Session Key)。          |
| +32                            | **Kstring**         | **ID_V**                | 业务服务器身份标识。包含 2 字节长度前缀 + 变长 UTF-8 字符串。 |
| + (32 + 2 + Len_V)             | **uint32**          | **TS4**                 | TGS 签发该票据的 Unix 时间戳（大端序）。                     |
| + (36 + 2 + Len_V)             | **uint32**          | **Lifetime**            | 该票据的有效时长（秒）。                                     |
| + (40 + 2 + Len_V)             | **uint32**          | **Ticket_V_Len**        | 后续 `Ticket_V` 密文块的字节长度。                           |
| + (44 + 2 + Len_V)             | **uint8 []**         | **Ticket_V**            | 由 $K_v$ 加密的密文块，客户端将其视为黑盒，后续在 AP_REQ 中透传。 |

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  Key_c_v (32字节 Session Key)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        ID_V_Len (uint16)      |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+           ID_V_String         |
|             (变长，确认该票据准入的服务目标)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      TS4 (Ticket 签发时间)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Lifetime (有效期，秒)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Ticket_V_Len                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                   Ticket_V (由 K_v 加密的密文)                 |
|            (客户端不解密，直接原样透传给 Server V)               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

------

#### 第三层：Ticket_V 的内部结构 (由业务服务器 V 解密)

<br/>


当业务服务器 V 收到此票据并用自己的密钥 `K_v` 解密后，看到的布局（和 Message2 中相同）：

| **相对偏移**           | **数据类型**  | **字段名**    | **说明 (Comment)**                                  |
| ---------------------- | ------------- | ------------- | --------------------------------------------------- |
| +0                     | **uint8 [32]** | **Key_c_v**   | Session Key。服务器将使用此密钥解密客户端的验证器。 |
| +32                    | **Kstring**   | **ID_Client** | **变长**：持票客户端的真实身份字符串。              |
| + (32 + 2 + Len_C)     | **uint32**    | **AD_c**      | 客户端网络地址或权限掩码。                          |
| + (36 + 2 + Len_C)     | **Kstring**   | **ID_V**      | **变长**：校验该票据是否确实是发给本服务器。        |
| + (38 + Len_C + Len_V) | **uint32**    | **TS4**       | 签发时间戳。                                        |
| + (42 + Len_C + Len_V) | **uint32**    | **Lifetime**  | 票据生命周期。                                      |

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  Key_c_v (32字节 Session Key)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      ID_Client_Len (uint16)   |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+        ID_Client_String       |
|             (变长，告知 Server 访客的真实身份)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           AD_c (4字节，用户网络地址或权限 Mask)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        ID_V_Len (uint16)      |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+           ID_V_String         |
|             (变长，校验该票据是否确实是发给本 Server)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      TS4 (Ticket 签发时间)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Lifetime (有效期，秒)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 9.3　阶段三：Client ↔ V（消息 5、6 以及后续业务消息）

<br/>


**目的**：Client 向 V 出示票据完成双向认证，建立 Session

### 消息 5（AP_REQ）：Client → V

<br/>


| **相对偏移 (Relative Offset)** | **数据类型 (Type)** | **字段名 (Field Name)** | **说明 (Comment)**                                           |
| ------------------------------ | ------------------- | ----------------------- | ------------------------------------------------------------ |
| +0                             | **uint32**          | **Ticket_V_Len**        | 后续 `Ticket_V` 密文块的字节长度。                           |
| +4                             | **uint8 []**         | **Ticket_V**            | 从 TGS_REP 获取的服务票据，客户端原样透传。                  |
| + (4 + Ticket_V_Len)           | **uint32**          | **Auth_Len**            | 后续 `Authenticator_c` 密文块的字节长度。                    |
| + (8 + Ticket_V_Len)           | **uint8 []**         | **Authenticator_c**     | **动态生成**：使用 $K_{c,v}$ 加密的验证器，包含最新的时间戳 TS5。 |

**Authenticator_c 内部明文布局表 (由 Key_c_v 加密)**

布局无改变，仅更新时间戳：

| **相对偏移 (Relative Offset)** | **数据类型 (Type)** | **字段名 (Field Name)** | **说明 (Comment)**                                     |
| ------------------------------ | ------------------- | ----------------------- | ------------------------------------------------------ |
| +0                             | **Kstring**         | **ID_Client**           | 客户端身份字符串。必须与 Ticket 内部封装的 ID 一致。   |
| + (2 + Len_C)                  | **uint32**          | **AD_c**                | 客户端网络地址或权限 Mask。                            |
| + (6 + Len_C)                  | **uint32**          | **TS5**                 | **关键更新**：客户端发起此 AP 请求的当前 Unix 时间戳。 |

```
0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Ticket_V_Len                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|           Ticket_V (从 TGS_REP 拿到的原样数据，含 TS4)           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Auth_Len                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|        Authenticator_c (密文部分，由 Key_c_v 加密，含 TS5)      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

V 收到后：用 K_v 解密 Ticket_V → 用 K_c, v 解密 Authenticator 

### 消息 6（AP_REP）：V → Client

<br/>


```
0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Cipher_Len                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  Enc_Part (AES-256-CBC 密文)                   |
|         (解密密钥: K_c_v)                                       |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

此处的 Enc_Part 只包括一个 uint32 数据，即 `TS5+1`：

Client 收到后：解密 Enc_Part → 验证 `TS5+1 == TS5 + 1` → 双向认证完成

至此，如果上述协议全部正常，**Kerberos 认证体系结束**

**注意：**

- Client 持久化保存 Ticket_v 在内存或者磁盘中
- 如果连接断开，重连时需要重新进行 message5/6 握手
- 如果 Ticket_v 验证过期，则服务器拒绝连接，Client 需重新 Kerberos 认证获取新的 Ticket
- V Server 在通过验证后，在内存中建立 `sessionContext` 以存储 Client_ID 和 Key_C_V 的映射关系

---

## 后续业务消息（MsgType = 0x07）

<br/>


由于 Client 和 V 之间已经有了共享的 Key_c_v，后续传输加密使用它进行对称钥加密即可

### APP_REQ（C-> V）

<br/>


| **相对偏移**   | **类型**    | **字段名**      | **说明**                                                   |
| -------------- | ----------- | --------------- | ---------------------------------------------------------- |
| +0             | **Kstring** | **ID_Client**   | **路由标识**：Server 根据它找到对应的 `SK_cv` 和 `Pub_c`。 |
| + (2 + Len_ID) | **uint16**  | **Cipher_Len**  | 后续加密部分的长度。                                       |
| + (4 + Len_ID) | **bytes**   | **Cipher_Data** | **核心密文**：由 `Key_c_v` 加密。                          |

**Cipher_Data 解密后明文结构：**

| **类型**       | **字段名**   | **说明**                                                     |
| -------------- | ------------ | ------------------------------------------------------------ |
| **Kstring**    | **Command**  | **业务指令**：用户写入的命令行字符串                         |
| **bytes(256)** | **RSA_Sign** | **不可否认凭证**：Client 私钥对 `Command + Seq_Num` 的签名。 |

```plaintext
0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |      ID_Client_Len (uint16)   |                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+        ID_Client              |
 |              (用于 Server 在内存中检索 Session)                 |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |     Cipher_Len (uint16)       |                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
 |                                                               |
 |    Cipher_Data (AES 加密部分) --------------------.             |
 |                                                 |             |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+             |
                                                   |             |
          .----------------------------------------'             |
          |  [ 解密后的明文布局 ]                                   |
          |  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                   |
          |  |    Command_Len (uint16)       |                   |
          |  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                   |
          |  |         Command (CLI)          |                  |
          |  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                   |
          |  |         RSA_Signature         |                   |
          |  |    (证明 Client 确实下达了此指令)   |                |
          |  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                   |
          '------------------------------------------------------'
```

**签名生成（Client 端）**

Client 在发送 `Command` 前，先从协议 Header 中提取当前的 `Seq_Num`，执行以下逻辑：

$$M = \text{Seq\_Num} \parallel \text{Command}$$

$$\text{Sig\_SK}_c = \text{Sign}_{\text{SK}_c}(\text{SHA256}(M))$$

- **$M$**：待签名的消息载荷（逻辑拼接）
- **$\text{SK}_c$**：Client 的 RSA 私钥
- **$\text{Sig\_SK}_c$**：生成的 **定长 256 字节** 签名

**签名验证（Server 端）**

Server 收到包并 AES 解密后，拿到 `Command` 和 `Sig_SK_c`，同时从解密前的 Header 中提取 `Seq_Num`：

1. **重组待验数据**：$M' = \text{Seq\_Num} \parallel \text{Command}$
2. **解密签名**：$H_{\text{dec}} = \text{Ver}_{\text{PK}_c}(\text{Sig\_SK}_c)$
3. **比对哈希**：检验 $H_{\text{dec}} \stackrel{?}{=} \text{SHA256}(M')$

- **$\text{PK}_c$**：从初始化阶段拿到的 **证书** 中提取出 Client 公钥
- **验证通过**：证明该指令确实由 $\text{ID\_Client}$ 发出，且 `Seq_Num` 未被篡改

### APP_REP（V-> C）

<br/>


| **相对偏移** | **类型**   | **字段名**      | **说明**                                                  |
| ------------ | ---------- | --------------- | --------------------------------------------------------- |
| +0           | **uint32** | **Seq_Num**     | **响应序号**：对应请求包的 `Seq_Num`，确保请求/响应配对。 |
| +4           | **uint16** | **Cipher_Len**  | 后续加密部分的长度。                                      |
| +6           | **bytes**  | **Cipher_Data** | **核心密文**：由 `Key_c_v` 加密。                         |

**Cipher_Data 解密后明文结构 (业务回执层)**

| **类型**       | **字段名**     | **说明**                                                  |
| -------------- | -------------- | --------------------------------------------------------- |
| **int32**      | **Exit_Code**  | **执行状态**：子进程的退出状态码（如 0 为成功）。         |
| **Kstring**    | **Response**   | **执行结果**：`spawn` 捕获的输出字符串（stdout/stderr）。 |
| **bytes(256)** | **RSA_Sign_v** | **不可否认凭证**：V 私钥对 `Response + Seq_Num` 的签名。  |

```
 0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                        Seq_Num (uint32)                       |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |      Cipher_Len (uint16)      |                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
 |                                                               |
 |    Cipher_Data (AES 加密部分) --------------------.             |
 |                                                 |             |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+             |
                                                   |             |
          .----------------------------------------'             |
          |  [ 解密后的明文布局 ]                                   |
          |  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
          |  |             Exit_Code (int32, 大端)               | |
          |  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
          |  |      Response_Len (uint16)    |                   | |
          |  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                   | |
          |  |         Response (Output String)                  | |
          |  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
          |  |                                                   | |
          |  |         RSA_Signature_v (256 Bytes)               | |
          |  |    (证明 Server 确实执行并返回了此结果)             | |
          |  |                                                   | |
          |  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
          '------------------------------------------------------'
```

**签名生成（Server 端）**

Server 在 `spawn` 执行完毕并准备构建 **APP_REP** 前，执行以下逻辑：

1. **待签名消息载荷 (M)**：

   $$M = \text{Seq\_Num} \parallel \text{Exit\_Code} \parallel \text{Response}$$

   - **Seq_Num**：响应包 `Header` 中拿到 `Seq_num`
   - **Exit_Code**：子进程退出状态码
   - **Response**：执行结果字符串

2. **签名计算**：

   $$\text{Sig\_SK}_v = \text{Sign}_{\text{SK}_v}(\text{SHA256}(M))$$

   - **$\text{SK}_v$**：Server (V) 的 RSA 私钥。
   - **$\text{Sig\_SK}_v$**：生成的定长 **256 字节** 签名，填入 `Cipher_Data` 的末尾

**签名验证（Client 端）**

Client 收到 **APP_REP** 并完成 AES 解密后，执行以下逻辑：

1. **重组待验数据 (M')**：

   从解密后的明文提取 `Exit_Code` 和 `Response`，并结合报文头部的 `Seq_Num`：

   $$M' = \text{Seq\_Num} \parallel \text{Exit\_Code} \parallel \text{Response}$$

2. **解密签名**：

   $$H_{\text{dec}} = \text{Ver}_{\text{PK}_v}(\text{Sig\_SK}_v)$$

   - **$\text{PK}_v$**：从初始化阶段预留的 **证书** 中提取的 Server 公钥。

3. **比对哈希**：

   检验

   $$H_{\text{dec}} \stackrel{?}{=} \text{SHA256}(M')$$

# 第十章　测试用例清单

<br/>


## 10.1　功能测试用例

<br/>


| 用例 ID | 用例名称 | 前置条件 | 测试步骤 | 预期结果 | 验收项 |
|---------|---------|---------|---------|---------|--------|
| **FT-001** | AS 认证正常流程 | AS 已启动，CLIENT_1 已注册 | 1. CLIENT_1 发送 AS_REQ（含合法 ID_Client、ID_TGS、TS1）2. 等待 AS_REP | 返回 KRB_OK，Client 成功解密得到 K_c, tgs 和 Ticket_TGS，客户端状态变为 STATE_AS_DONE | Kerberos 认证验收 |
| **FT-002** | TGS 正常请求 | CLIENT_1 已完成 AS 认证 | 1. 构造 TGS_REQ（含 TGT + 新 Authenticator）2. 发送到 TGS 3. 等待 TGS_REP | 返回 KRB_OK，Client 成功解密得到 K_c, v 和 Ticket_V，状态变为 STATE_TGS_DONE | Kerberos 认证验收 |
| **FT-003** | AP 双向认证 + RSA 验签 | CLIENT_1 已完成 TGS 阶段 | 1. 构造 AP_REQ（含 Ticket_V + Authenticator + RSA 签名）2. V 验签后返回 AP_REP 3. Client 验证 V 的签名 | 双向 RSA 验签均通过，Session 成功建立，状态变为 STATE_V_CONNECTED | 加密验收 + 安全验收 |
| **FT-004** | CLI 指令 echo 执行 | Client 已建立 Session | 发送 `echo hello world` 指令 | V 返回 `hello world`，HMAC 和 RSA 验签均通过，响应正确展示在 WebUI 上 | 业务验收 |
| **FT-005** | CLI 指令 status 执行 | Client 已建立 Session | 发送 `status` 指令 | V 返回包含在线用户数和时间的状态字符串 | 业务验收 |
| **FT-006** | 4 Client 并发登录 | AS、TGS、V 均已启动 | 4 个 Client 同时发起 AS_REQ | 全部返回 KRB_OK，无错误，无 Session 混淆，每个 Client 得到各自独立的密钥 | 多线程验收 |
| **FT-007** | 4 Client 并发发送指令 | 4 个 Client 均已建立 Session | 4 个 Client 同时发送 `ping` 指令 | 全部在 1s 内收到 `pong` 响应，无报文串包或混淆 | 多线程验收 |
| **FT-008** | Ticket_V 过期后 SSO 重认证 | Client 建立 Session 后，等待 Ticket 过期 | 等待 Ticket_V 过期后发送任意指令 | 系统自动触发 TGS + AP 重认证，无需用户重新输入密码，指令正常发送 | 架构验收 |
| **FT-009** | 未注册客户端被拒绝 | AS 已启动 | 发送 AS_REQ，ID_Client 使用未注册值（如 99999）| AS 返回错误响应，错误码为 ERR_CLIENT_NOT_FOUND，不泄露具体原因，记录 WARN 日志 | 安全验收 |
| **FT-010** | RSA 签名验证失败 | AP 认证阶段 | CLIENT_1 使用 CLIENT_2 的私钥对 Authenticator 签名，发送给 V | V 返回 ERR_RSA_VERIFY_FAIL，不建立 Session，SECURITY 日志记录该事件（含 client_ip）| 安全验收 |
| **FT-011** | HMAC 验证失败（消息篡改）| 业务消息阶段 | 手动修改业务消息中 Cipher_Cmd 的某个字节后发送 | V 检测到 HMAC 不匹配，返回 ERR_HMAC_MISMATCH，不执行指令，SECURITY 日志告警 | 安全验收 |
| **FT-012** | 白名单外指令被拒绝 | Client 已建立 Session | 发送 `rm -rf /tmp` 指令 | V 拒绝执行，返回 "指令不在白名单" 的错误响应，SECURITY 日志记录指令哈希 | 业务验收 |
| **FT-013** | WebUI 实时信息展示 | Client 已建立 Session | 通过 WebUI 发送 `echo test`，观察 WebUI | WebUI 实时展示：明文指令、密文 Hex、RSA 签名 Hex、HMAC Hex、验签结果（✓/✗）、服务端响应 | UI 验收 |
| **FT-014** | Wireshark 抓包验证 | 系统正常运行 | 在发送业务消息的同时用 Wireshark 抓包，过滤 Client→V 的 TCP 流 | 抓包数据中只能看到密文字节流，无法直接读出 CLI 指令明文，Magic Number `0x4B45` 可辨识 | 调试验收 |
| **FT-015** | AES 加解密往返验证 | 单元测试环境 | 对随机生成的 1KB 明文执行 `encrypt → decrypt` | 解密结果与原始明文逐字节完全一致，无任何错误 | 加密验收 |
| **FT-016** | 证书有效性校验 | V 的 WebUI | 提交 expire 早于当前日期的证书 | V 拒绝通信，返回 ERR_CERT_EXPIRED，WebUI 显示证书过期告警 | 安全验收 |
| **FT-017** | 连续 30 分钟稳定运行 | 系统全部启动 | 4 个 Client 每隔 10 秒发送一条指令，持续 30 分钟 | 无崩溃、无内存泄漏（可用 valgrind 检查）、无连接中断、所有响应正确 | 稳定性验收 |

## 10.2　性能测试用例

<br/>


| 用例 ID | 用例名称 | 测试方法 | 通过标准 | 工具 |
|---------|---------|---------|---------|------|
| **PT-001** | AES-256 加密耗时 | 对 1KB 随机明文执行 `aes256_cbc_encrypt()`，计时 1000 次取平均 | 平均 ≤ 30ms | 代码内 `clock()` 计时 |
| **PT-002** | AES-256 解密耗时 | 对 1KB 密文执行 `aes256_cbc_decrypt()`，计时 1000 次取平均 | 平均 ≤ 30ms | 同上 |
| **PT-003** | SHA-256 哈希耗时 | 对 4KB 数据执行 `sha256()`，计时 1000 次取平均 | 平均 ≤ 10ms | 同上 |
| **PT-004** | RSA-2048 签名耗时 | 对 32 字节 Hash 执行 `rsa_sign()`，计时 100 次取平均 | 平均 ≤ 500ms（不用 CRT）或 ≤ 150ms（用 CRT）| 同上 |
| **PT-005** | RSA-2048 验签耗时 | 对 32 字节 Hash 执行 `rsa_verify()`，计时 100 次取平均 | 平均 ≤ 200ms | 同上 |
| **PT-006** | 单条消息端到端延迟 | Client 发送 `echo test` 到收到响应，计时 100 次 | P95 ≤ 1000ms（局域网内，含 RSA 签名/验签） | 代码计时或 Wireshark 时间戳 |
| **PT-007** | 4 Client 并发 AS 认证总耗时 | 4 个 Client 同时发 AS_REQ，计算全部完成的总时间 | ≤ 5s（考虑 RSA 密钥加载时间）| 外部 time 命令 |
| **PT-008** | 服务端并发处理 QPS | 4 个 Client 尽快连续发送指令，统计 V 服务器的处理速率 | ≥ 4 条/秒（即每条 ≤ 250ms 服务端处理时间）| 代码内统计 |

## 10.3　安全测试用例

<br/>


| 用例 ID | 用例名称 | 攻击方式 | 预期防御结果 | 验证方法 |
|---------|---------|---------|------------|---------|
| **ST-001** | 时间戳重放攻击 | 截获一条合法报文，等待 6 秒后重发 | ERR_REPLAY_TIMESTAMP，WARN 日志记录时间差值 | 直接用 send() 重发截获的字节流 |
| **ST-002** | 序列号重放攻击 | 截获一条合法报文，立即使用相同 SEQ_NUM 重发另一条 | ERR_REPLAY_SEQ，拒绝并记录 WARN 日志 | 修改消息内容但保持 SEQ_NUM 不变 |
| **ST-003** | 伪造 TGT | 手工构造一个 Ticket_TGS 明文，用随机密钥 "加密" 后发给 TGS | TGS 用 K_tgs 解密后得到乱码，PKCS7 校验失败，ERR_TICKET_INVALID，SECURITY 日志 | 构造随机字节充当 Ticket_TGS |
| **ST-004** | 伪造 Authenticator（身份冒充）| 截获 CLIENT_1 的 TGT，用 CLIENT_2 的 Authenticator 发 TGS_REQ | TGS 检测到 ID_Client 不匹配，ERR_AUTH_MISMATCH，SECURITY 日志（记录可疑 IP） | 替换 Authenticator 中的 ID_Client 字段后重加密 |
| **ST-005** | 中间人篡改密文 | 修改业务消息报文中 Cipher_Cmd 的第 20 个字节 | HMAC 验证失败，ERR_HMAC_MISMATCH，V 拒绝执行，SECURITY 日志告警 | 用十六进制编辑器修改抓包的字节流后重放 |
| **ST-006** | RSA 签名伪造 | 用 CLIENT_2 的私钥为 CLIENT_1 的消息签名，发给 V | ERR_RSA_VERIFY_FAIL，V 拒绝，SECURITY 日志记录（含双方 ID、时间戳、client_ip） | 替换 AP_REQ 中的签名字节 |
| **ST-007** | 密文可见性验证（抗明文泄露）| Wireshark 全量抓包业务消息 | 报文中只有密文，Magic Number 可见（`0x4B45`），但 CLI 指令内容不可见 | Wireshark 抓包后 Follow TCP Stream，人工检查 |
| **ST-008** | 证书篡改攻击 | 修改证书 JSON 中的 `public_key.n` 字段（替换为另一个公钥），提交给 V | `cert_verify()` 签名验证失败，ERR_CERT_SIG_INVALID，拒绝通信，SECURITY 日志 | 手动编辑证书文件，通过 WebUI 的验证接口提交 |
| **ST-009** | IP 绑定验证（防票据转移）| CLIENT_1 的 TGT 中绑定了 192.168.1.101，从 192.168.1.199 发 TGS_REQ | TGS 检测到 socket 层 client_ip 与 Ticket 中 AD_c 不匹配，ERR_AD_MISMATCH，SECURITY 日志 | 在另一台机器上重放 TGS_REQ |
| **ST-010** | 日志不含明文密钥验证 | 在所有日志中搜索已知的密钥字节模式 | 所有日志文件中不含任何明文密钥；K_c, tgs 等只以 SHA-256 摘要形式出现 | 用 `grep -rn` 搜索已知密钥的十六进制表示 |

---

# 第十一章　推荐工程目录结构

<br/>


```
kerberos-system/
├── common/                          # 所有节点共用的公共模块
│   ├── crypto/
│   │   ├── aes256.c / aes256.h      # AES-256-CBC 手写实现（含 S-Box、密钥扩展、CBC 模式）
│   │   ├── sha256.c / sha256.h      # SHA-256 手写实现（含流式接口）
│   │   ├── hmac.c / hmac.h          # HMAC-SHA256（基于 sha256 模块）
│   │   ├── rsa.c / rsa.h            # RSA-2048 手写实现（BigInt、模幂、PKCS#1 v1.5）
│   │   └── bigint.c / bigint.h      # 2048 位大整数运算（rsa.c 的依赖）
│   ├── proto/
│   │   ├── packet.c / packet.h      # 封包/拆包（krb_pack, krb_unpack, krb_recv_full）
│   │   └── antireplay.c / antireplay.h  # 防重放（AntiReplay_Ctx, krb_antireplay_check）
│   ├── cert/
│   │   └── cert.c / cert.h          # 证书加载、验证、查询（JSON 解析自行实现或用 cJSON）
│   ├── rand/
│   │   └── rand.c / rand.h          # CSPRNG 封装（krb_rand_bytes，读取 /dev/urandom）
│   └── log/
│       └── logger.c / logger.h      # 统一日志模块（支持 5 个级别，输出到文件 + 控制台）
│
├── as_server/                       # AS 认证服务器
│   ├── main.c                       # 入口：解析配置 → 初始化 → 启动线程池 + WebUI
│   ├── as_state.c / as_state.h      # AS_State 结构体定义和初始化函数
│   ├── as_handler.c / as_handler.h  # krb_handle_as_req() 和辅助函数
│   ├── as_webui.c / as_webui.h      # WebUI HTTP 服务器（轻量实现或 Flask）
│   └── config/
│       └── as_config.json           # AS 节点配置文件（见第一章模板）
│
├── tgs_server/                      # TGS 票据许可服务器
│   ├── main.c
│   ├── tgs_state.c / tgs_state.h
│   ├── tgs_handler.c / tgs_handler.h
│   ├── tgs_webui.c / tgs_webui.h
│   └── config/tgs_config.json
│
├── v_server/                        # V 应用/验证服务器
│   ├── main.c
│   ├── v_state.c / v_state.h
│   ├── v_handler.c / v_handler.h   # 包含 AP 认证处理和业务消息处理
│   ├── v_webui.c / v_webui.h
│   └── config/v_config.json
│
├── client/                          # 客户端（4 个实例共用同一套代码，配置文件区分）
│   ├── main.c                       # WebUI 模式启动
│   ├── client_ctx.c / client_ctx.h  # Client_Ctx 结构体和状态机
│   ├── client_as.c / client_as.h    # client_do_as() 实现
│   ├── client_tgs.c / client_tgs.h  # client_do_tgs() 实现
│   ├── client_ap.c / client_ap.h    # client_do_ap() 实现
│   ├── client_cmd.c / client_cmd.h  # client_send_cmd() 实现
│   ├── client_webui.c / client_webui.h
│   └── config/
│       ├── client1_config.json      # 各自独立配置（ID、密钥路径、服务器地址）
│       ├── client2_config.json
│       ├── client3_config.json
│       └── client4_config.json
│
├── certs/                           # 离线预生成的证书（JSON，版本管理）
│   ├── client1_cert.json
│   ├── client2_cert.json
│   ├── client3_cert.json
│   ├── client4_cert.json
│   └── v_cert.json
│
├── keys/                            # 私钥和长期密钥（.gitignore 忽略，不提交版本控制）
│   ├── client1_priv.json            # CLIENT_1 RSA 私钥
│   ├── client2_priv.json
│   ├── client3_priv.json
│   ├── client4_priv.json
│   ├── v_priv.json                  # V 服务器 RSA 私钥
│   ├── kc_client1.bin               # CLIENT_1 与 AS 的共享长期密钥（32 字节二进制）
│   ├── kc_client2.bin
│   ├── kc_client3.bin
│   ├── kc_client4.bin
│   ├── k_tgs.bin                    # AS 与 TGS 的共享长期密钥
│   └── k_v.bin                      # TGS 与 V 的共享长期密钥
│
├── tools/                           # 工具脚本（Python，仅离线使用）
│   ├── gen_rsa_keys.py              # 生成所有节点的 RSA 密钥对和证书
│   ├── gen_sym_keys.py              # 生成所有对称长期密钥（Kc、K_tgs、K_v）
│   └── verify_cert.py              # 验证证书合法性（调试用）
│
└── tests/                           # 单元测试
    ├── test_aes256.c                # AES-256 正常路径、边界、错误路径（含 NIST 标准测试向量）
    ├── test_sha256.c                # SHA-256（含 NIST 标准测试向量）
    ├── test_hmac.c                  # HMAC-SHA256（含 RFC 4231 测试向量）
    ├── test_rsa.c                   # RSA 签名/验签往返测试
    ├── test_packet.c                # 封包/拆包往返测试，字段正确性验证
    ├── test_antireplay.c            # 时间戳和序列号重放测试
    └── Makefile                     # 测试编译和运行脚本
```

> **Python 版本对应**：将 `.c` 替换为 `.py`，将结构体替换为 `@dataclass`，将 `#pragma pack` 替换为 `struct.pack('>...', ...)` 格式字符串（`>` 表示大端序），将 `pthread_mutex_t` 替换为 `threading.Lock()`。

---

# 第十二章　关键算法伪代码

<br/>


## 12.1　AES-256 密钥扩展

<br/>


```
函数 KeyExpansion(key[32 字节]) → round_keys[15][16 字节]:

    // 将 32 字节密钥转为 8 个 32 位字（大端序读取）
    for i = 0 to 7:
        W[i] = (key[4i] << 24) | (key[4i+1] << 16) | (key[4i+2] << 8) | key[4i+3]

    // 生成剩余 52 个字（共 60 个字 = 15 组轮密钥）
    for i = 8 to 59:
        temp = W[i-1]
        if i mod 8 == 0:
            temp = SubWord(RotWord(temp)) XOR Rcon[i/8]
            // RotWord: 字节循环左移 [a,b,c,d] → [b,c,d,a]
            // SubWord: 对每个字节查 S-Box 替换
            // Rcon[j] = (xtime^(j-1)(0x01) << 24)（GF(2^8) 中 2 的幂次）
        else if i mod 8 == 4:
            temp = SubWord(temp)
        W[i] = W[i-8] XOR temp

    // 将 W[0..59] 按每 4 个字分组为 15 组轮密钥（每组 16 字节）
    for r = 0 to 14:
        for j = 0 to 3:
            round_keys[r][4j..4j+3] = 大端序写入 W[4r + j]
```

## 12.2　AES-256 CBC 加密完整流程

<br/>


```
函数 aes256_cbc_encrypt(plain, plain_len, key, iv) → cipher, cipher_len:

    // Step 1: PKCS7 填充
    pad_len = 16 - (plain_len mod 16)   // 注意：若 plain_len 是 16 的倍数，pad_len = 16
    padded = plain + 字节数组([pad_len] * pad_len)
    padded_len = plain_len + pad_len    // padded_len 必然是 16 的倍数

    // Step 2: 密钥扩展
    round_keys = KeyExpansion(key)

    // Step 3: 前置 IV（IV 明文发送）
    cipher = iv                          // 将 16 字节 IV 放在密文最前面

    // Step 4: CBC 模式加密（逐块处理）
    prev_block = iv                      // 初始化链式变量
    for i = 0 to (padded_len / 16 - 1):
        block = padded[i*16 .. i*16+15]
        xor_block = block XOR prev_block    // CBC 核心：与前一密文块 XOR
        cipher_block = AES_Encrypt_Block(xor_block, round_keys)   // 14 轮 AES 加密
        cipher += cipher_block
        prev_block = cipher_block

    cipher_len = 16 + padded_len         // IV(16) + 加密后的填充明文
```

## 12.3　PKCS7 填充与去除

<br/>


```
函数 pkcs7_pad(data, block_size=16) → padded_data:
    pad_len = block_size - (len(data) % block_size)
    // 当 len(data) 是 block_size 的倍数时，pad_len = block_size（添加一整块填充）
    // 这保证了去除填充时不会歧义
    return data + bytes([pad_len] * pad_len)

函数 pkcs7_unpad(data) → original_data:
    if len(data) == 0 or len(data) % 16 != 0:
        raise ERR_AES_DECRYPT_FAIL    // 密文长度必须是块大小的倍数
    pad_len = data[-1]                // 最后一个字节就是填充长度
    if pad_len < 1 or pad_len > 16:
        raise ERR_AES_DECRYPT_FAIL    // 填充长度非法
    for i = len(data)-pad_len to len(data)-1:
        if data[i] != pad_len:
            raise ERR_AES_DECRYPT_FAIL    // 填充内容不一致
    return data[0 : len(data) - pad_len]
```

## 12.4　SHA-256 压缩函数

<br/>


```
函数 sha256_compress(H[0..7], block[64 字节]):
    // 扩展消息调度：将 64 字节块扩展为 64 个 32 位字
    W[0..15] = 从 block 按大端序读取 16 个 uint32
    for i = 16 to 63:
        s0 = ROTR(7, W[i-15]) XOR ROTR(18, W[i-15]) XOR SHR(3, W[i-15])
        s1 = ROTR(17, W[i-2]) XOR ROTR(19, W[i-2]) XOR SHR(10, W[i-2])
        W[i] = (W[i-16] + s0 + W[i-7] + s1) mod 2^32

    // 初始化工作变量
    a,b,c,d,e,f,g,h = H[0],H[1],H[2],H[3],H[4],H[5],H[6],H[7]

    // 64 轮压缩
    for i = 0 to 63:
        S1  = ROTR(6,e) XOR ROTR(11,e) XOR ROTR(25,e)
        ch  = (e AND f) XOR ((NOT e) AND g)
        temp1 = (h + S1 + ch + K[i] + W[i]) mod 2^32
        S0  = ROTR(2,a) XOR ROTR(13,a) XOR ROTR(22,a)
        maj = (a AND b) XOR (a AND c) XOR (b AND c)
        temp2 = (S0 + maj) mod 2^32

        h=g; g=f; f=e; e=(d+temp1) mod 2^32
        d=c; c=b; b=a; a=(temp1+temp2) mod 2^32

    // 更新哈希状态
    H[0..7] = (H[0]+a, H[1]+b, ..., H[7]+h) 各自 mod 2^32
```

## 12.5　RSA 签名（PKCS#1 v1.5）

<br/>


```
函数 rsa_sign(msg, priv_key) → sig[256 字节]:

    // Step 1: 计算消息哈希
    h = sha256(msg)      // 32 字节

    // Step 2: EMSA-PKCS1-v1_5 编码（填充到 256 字节）
    //   DigestInfo 前缀（SHA-256 对应的 DER 编码，固定 19 字节）：
    T = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
         0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20] + h
    //   T 的总长度 = 19 + 32 = 51 字节
    ps_len = 256 - 3 - len(T)   // 填充字节数 = 256 - 3 - 51 = 202 字节
    EM = [0x00, 0x01] + [0xFF] * ps_len + [0x00] + T
    //   EM 长度恰好为 256 字节

    // Step 3: 将 256 字节 EM 解读为大整数 m
    m = 大整数从大端字节序构造(EM)

    // Step 4: 模幂运算（RSA 核心）
    s = rsa_modexp(m, priv_key.d, priv_key.n)

    // Step 5: 将结果转为 256 字节（高位补零）
    sig = 大整数转大端字节序(s, 256 字节)
    return sig
```

## 12.6　RSA 验签

<br/>


```
函数 rsa_verify(msg, pub_key, sig[256 字节]) → bool:

    // Step 1: 将签名字节序列解读为大整数 s
    s = 大整数从大端字节序构造(sig)

    // Step 2: 公钥模幂：恢复 EM
    m = rsa_modexp(s, pub_key.e, pub_key.n)
    EM_recovered = 大整数转大端字节序(m, 256 字节)

    // Step 3: 校验 EM 格式
    if EM_recovered[0] != 0x00: raise ERR_RSA_VERIFY_FAIL
    if EM_recovered[1] != 0x01: raise ERR_RSA_VERIFY_FAIL
    // 找到第一个非 0xFF 字节（应为 0x00 分隔符）
    i = 2
    while EM_recovered[i] == 0xFF: i += 1
    if EM_recovered[i] != 0x00: raise ERR_RSA_VERIFY_FAIL
    i += 1  // 跳过 0x00 分隔符

    // Step 4: 验证 DigestInfo 前缀
    expected_prefix = [0x30, 0x31, 0x30, 0x0d, ...]  // 同签名时的 T 前缀（19字节）
    if EM_recovered[i:i+19] != expected_prefix: raise ERR_RSA_VERIFY_FAIL
    i += 19

    // Step 5: 提取哈希值并与消息哈希比对
    hash_in_sig = EM_recovered[i:i+32]
    hash_of_msg = sha256(msg)
    if hash_in_sig != hash_of_msg: raise ERR_RSA_VERIFY_FAIL   // 时序安全比较
    return True
```

## 12.7　大整数模幂（左到右二进制快速幂）

<br/>


```
函数 rsa_modexp(base, exp, mod) → result:
    // Left-to-Right Binary Exponentiation（从高位到低位扫描指数）
    result = BigInt(1)          // 初始值为 1（任何数的 0 次幂）
    base = base mod mod         // 规范化底数

    // 从 exp 的最高有效位开始向低位扫描（2048 位，共扫描 2048 次）
    for bit_pos = 2047 downto 0:
        result = (result * result) mod mod    // 平方步
        if bit(exp, bit_pos) == 1:
            result = (result * base) mod mod  // 乘法步（当前位为 1 时）

    return result

// 注意：大整数乘法和取模是性能瓶颈，2048 位 * 2048 位 = 4096 位中间结果
// 实现时可以将 bigint_mul 和 bigint_mod 合并为 bigint_mul_mod 避免中间大整数存储
```

## 12.8　防重放滑动窗口算法

<br/>


```
函数 krb_antireplay_check(timestamp, seq_num, ctx):

    // Step 1: 时间戳检查（误差阈值 5 秒）
    now = 当前 Unix 时间戳
    if |timestamp - now| > 5:
        return ERR_REPLAY_TIMESTAMP

    // Step 2: 序列号去重（环形窗口，大小 1024）
    加锁 ctx.lock

    // 在已见序列号窗口中线性扫描
    for i = 0 to ctx.window_count - 1:
        if ctx.window[(ctx.window_head - 1 - i + 1024) % 1024] == seq_num:
            解锁 ctx.lock
            return ERR_REPLAY_SEQ    // 序列号重复

    // 未见过，将新序列号写入窗口
    ctx.window[ctx.window_head] = seq_num
    ctx.window_head = (ctx.window_head + 1) % 1024
    if ctx.window_count < 1024:
        ctx.window_count += 1

    解锁 ctx.lock
    return KRB_OK
```

---

*文档结束。版本 V1.0，如有疑问请参考本文档对应章节，或联系架构组负责人。*
