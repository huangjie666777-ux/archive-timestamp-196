# RFC 3161 Time-Stamp Authority

一个可离线核验的时间戳签发服务：Python 3.10 + FastAPI 0.115.12，
CMS 签名由 `cryptography` 完成，ASN.1 结构由 `asn1crypto` 严格解析，
回执持久化于 SQLite。签发的令牌可用 `openssl ts -verify` 独立核验。

## 快速开始

```bash
.venv/bin/uvicorn tsa_server.app:app --host 127.0.0.1 --port 8316
bash scripts/demo.sh            # 端到端演示（签发/核验/篡改拒绝/回执检索）
.venv/bin/python -m pytest tests/ -q
```

首次启动时若数据目录为空，自动生成演示根 CA（RSA-3072）与 TSA 证书
（RSA-2048，EKU 仅含 critical 的 timeStamping）；重启复用现有材料。
私钥文件权限 0600，任何 HTTP 接口均不暴露私钥。若 `tsa.key` 缺失或与
`tsa.crt` 不匹配，服务拒绝启动。

## 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/tsa` | 收 `application/timestamp-query`，返回 `application/timestamp-reply`（DER） |
| GET | `/tsa/cert` | PEM 证书链（TSA 证书 + 根 CA），可公开 |
| GET | `/tsa/receipt/{serial}` | 按序列号取回原始回执 DER，未知序列号 404 |

## 协议行为

- 仅接受版本 1；摘要算法仅 SHA-256 / SHA-384，并校验 hashedMessage 长度。
- 请求必须是完整 DER：非规范编码或尾随字节一律拒绝（`bad_data_format`）。
- 策略 OID 可配（`TSA_POLICY_OID`）；请求省略策略时使用默认值，
  携带未知策略返回 `unaccepted_policy`；任何扩展均拒绝（`bad_request`）。
- TSTInfo 保留请求摘要、策略与可选 nonce（无 nonce 同样合法）。
- `certReq` 为真时 CMS 携带 TSA 证书与根证书；签名属性含
  ESS signing-certificate-v2 证书绑定。
- 所有失败返回对应 `PKIStatusInfo`（status=rejection + failInfo），
  不附带令牌；HTTP 层错误（413/415/503）按语义返回。

## 持久化与并发

- SQLite（WAL）存储唯一正序列号、UTC 签发时刻与原始回执，重启保留。
- 序列号在 `BEGIN IMMEDIATE` 事务内分配，签名与记录同事务提交：
  签名失败即回滚，不会留下“成功”记录；崩溃残留的未提交行启动时清除。
- 若系统时钟早于最近一次成功签发时刻，拒绝签发（HTTP 503），绝不伪造时间。
- 限制项：请求体上限 `TSA_MAX_REQUEST_BYTES`（默认 16384），
  并发上限 `TSA_MAX_CONCURRENCY`（默认 4，超限 503），
  签名时限 `TSA_SIGN_TIMEOUT` 秒（默认 5，超时 503）。
  签名全部在内存中完成，不产生临时文件。

## 配置（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `TSA_DATA_DIR` | `data` | 证书、密钥与 receipts.db 所在目录 |
| `TSA_POLICY_OID` | `1.3.6.1.4.1.55555.1.1` | 默认（且唯一接受的）策略 OID |
| `TSA_MAX_REQUEST_BYTES` | `16384` | 请求体上限 |
| `TSA_MAX_CONCURRENCY` | `4` | 并发签发上限 |
| `TSA_SIGN_TIMEOUT` | `5` | 单次签发时限（秒） |
| `TSA_ACCURACY_SECONDS` | `1` | TSTInfo accuracy 字段 |

## 信任范围

- 演示根 CA 自签，仅用于本地验证；生产使用应替换 `tsa.crt/tsa.key`
  为受信 CA 签发的 TSA 证书（保留 EKU=critical timeStamping），
  并用对应 CA 作为 `-CAfile` 核验。
- 时间来源为服务器系统时钟（UTC，秒级精度）；本服务不对外提供
  时间源可信保证，核验方需自行信任该 TSA 证书与策略 OID。
- 私钥不出数据目录；`/tsa/cert` 仅公开证书。

## 代码结构

- `tsa_server/rfc3161.py` — 请求解析、TSTInfo 构造、CMS 签名、PKIStatusInfo
- `tsa_server/store.py` — SQLite 序列号分配与回执存取（事务保证）
- `tsa_server/pki.py` — 演示 CA/TSA 证书生成、加载与一致性校验
- `tsa_server/app.py` — FastAPI HTTP 层、限流与超时
- `tsa_server/config.py` — 环境变量配置
- `tests/test_tsa.py` — 18 项 pytest 自测
- `scripts/demo.sh` — openssl ts + curl 端到端演示

