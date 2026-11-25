# GeoServer 五 CVE 预认证 RCE —— pcap 按 TCP stream / 按 CVE 拆包索引

源文件：`~/Downloads/CVE-2026-129243-all.pcap`（209 帧 / 22.1 秒，未改动）
生成命令模板：

```bash
tshark -r <源> -Y "<显示过滤器>" -w <输出>.pcap
```

## 原始流量构成

| tcp.stream | 五元组 | 帧号 | 内容 |
|---|---|---|---|
| 0–4 | 192.168.100.1:3473 → .52:32768 | 1–10 | 只有 SYN/ACK，无载荷（端口探测） |
| 5 | .1:57846 → .52:22 | 11–12 | SSH banner 探测 |
| 6 | .1:3516 → .52:32769 | 15–25 | **CVE-2026-129244** GET 超长 storedQuery_id |
| 7 | .1:3517 → .52:32769 | 26–39 | **CVE-2026-129244** POST XML 超长 id |
| 8 | .1:3518 → .52:32769 | 40–130 | 主链：129243 → 120705 → 129245 → 129242（keep-alive 复用） |
| 9 | .1:3521 → .52:32769 | 131–198 | 回显读取 + 清理 + 登出 |
| 10–11 | .52 ↔ 198.18.0.17:443 | 199–209 | 无关 TLS 外联 |

**关键结论**：整条攻击链发生在 **stream 8 + stream 9** 两条连接里。stream 8 有 91 帧承载了从创建 stored query 到触发反序列化的全部动作，因此"按 stream 拆"粒度太粗，必须再按帧号切段。

## 文件清单

### 按 CVE（5 个主文件）

| 文件 | 帧数 | 帧号区间 | 判据 |
|---|---|---|---|
| `01_CVE-2026-129244_超长ID泄露数据目录.pcap` | 25 | stream 6,7 | 响应体含 `java.nio.file.FileSystemException: /opt/geoserver_data/wfs/query/AAAA...xml: File name too long` |
| `02_CVE-2026-129243_service=xWFS权限绕过.pcap` | 12 | 40–47, 54–57 | `service=x%2FWFS` 的 CreateStoredQuery 返回 **200**（正常应为 401/403）；随后 DropStoredQuery 也 200 |
| `03_CVE-2026-120705_XInclude读本地文件.pcap` | 14 | 40–53 | DescribeStoredQueries 响应里出现 `<wfs:userRegistry xml:base="file:///opt/geoserver_data/security/usergroup/default/users.xml">` 与 `<wfs:key>geoserver</wfs:key>` |
| `04_CVE-2026-129245_伪造remember-me提权.pcap` | 13 | 58–70 | 请求头带 `Cookie: remember-me=YWRtaW4lNDBkZWZhdWx0...`，响应 `302 → StatusPage?0`，随后 `200` 拿到 JSESSIONID |
| `05_CVE-2026-129242_JDBC反序列化RCE.pcap` | 128 | 71–130 + stream 9 | POST `usergroupservices` 注册 HSQLDB 服务返回 200，`user/PWN/groups` 返回 **500 + `object serialization failure`**，result.txt 回读 `uid=0(root) gid=0(root) groups=0(root)` |

### 129242 分步（便于逐帧对照 PoC）

| 文件 | 帧数 | 动作 |
|---|---|---|
| `05a_前置探测.pcap` | 15 | GET usergroupservices（列已注册服务）、HEAD 两个 rest resource（探占用） |
| `05b_上传HSQLDB.pcap` | 34 | PUT `payload.properties` / `payload.script`（31KB HSQLDB 脚本）/ `request.txt` |
| `05c_注册服务并触发.pcap` | 11 | POST 注册 `jdbc_geoserver_poc`（`connectURL=jdbc:hsqldb:file:/opt/geoserver_data/gs-rce-<token>/payload;shutdown=true`）→ GET `user/PWN/groups` 触发 |
| `05d_读回显与清理.pcap` | 68 | GET result.txt 取回显；四次轮询 cleanup.txt；DELETE 服务与目录；`j_spring_security_logout` 收尾 |

### 无关流量

- `00a_TCP握手与SSH探测.pcap` —— stream 0–5，SYN/ACK 与 SSH banner
- `00b_TLS外联198.18.0.17.pcap` —— stream 10–11，**与漏洞无关**（198.18.0.0/15 是基准测试保留段，通常是代理/VPN 出口），不要误判为 C2

## 注意

- `02` 与 `03` 有 8 帧重叠（40–47），因为 CVE-2026-129243 的绕过**是** CVE-2026-120705 得以成功的前提，两个 CVE 共用同一条 CreateStoredQuery 请求。要严格不重叠就把 `03` 截到 48–53。
- 用 Wireshark 打开时若看不到 body，是响应走了 gzip（`Content-Encoding: gzip`），需在 `Preferences → Protocols → HTTP → Uncompress entity bodies` 打开，或直接用 `tshark -T fields -e http.file_data`。
- stream 8 里 `payload.script`（31KB）被 TCP 分成多段，拆包后仍完整保留在同一条 stream 内。
