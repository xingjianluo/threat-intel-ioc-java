# 威胁情报指标接入 / 归一 / 匹配链路（本地文件版）

一条完整的威胁情报 IOC（Indicator of Compromise）处理链路：**本地文件接入 → 格式解析 →
统一归一化（含去重与冲突收敛）→ 原子快照刷新 → 等价匹配 → 抑制/白名单优先 → 来源级访问控制**。

全程**只依赖本地文件与工程已有依赖**（Spring Boot Web、Jackson、JUnit 5），不引入任何
外部服务、网络调用或真实凭据体系。

---

## 1. 快速开始

```bash
# 一键运行全部测试（56 个，离线可跑）
mvn -o test

# 启动服务（启动时自动加载 data/ 目录完成首装）
mvn -o spring-boot:run
# 或
mvn -o package -DskipTests
java -jar target/threat-intel-ioc-java-1.0-SNAPSHOT.jar
```

启动后可直接调用：

```bash
# 匹配（type 可省略，按值确定性推断；apiKey 可省略，匿名仅能看公开明细）
curl -s -X POST localhost:8080/api/v1/threat-intel/match \
  -H 'Content-Type: application/json' \
  -d '{"value":"WWW.Evil.Example.COM"}'

# 手动刷新（ANALYST/ADMIN）
curl -s -X POST localhost:8080/api/v1/threat-intel/refresh -H 'X-API-Key: analyst-key'

# 快照状态（含当前代来源健康）
curl -s localhost:8080/api/v1/threat-intel/status

# 代际列表（当前生效代 + 保留的历史代，含每代来源健康）
curl -s localhost:8080/api/v1/threat-intel/generations

# 按代际匹配（generation 可省略，省略即当前生效代）
curl -s -X POST localhost:8080/api/v1/threat-intel/match \
  -H 'Content-Type: application/json' \
  -d '{"value":"evil.example.com","generation":1}'

# 回滚到历史代（ANALYST/ADMIN）
curl -s -X POST 'localhost:8080/api/v1/threat-intel/rollback?version=1' \
  -H 'X-API-Key: analyst-key'

# 指标明细（受限来源 viewer-key 返回 403，analyst-key 返回 200）
curl -s 'localhost:8080/api/v1/threat-intel/indicators?key=DOMAIN:restricted.internal' \
  -H 'X-API-Key: viewer-key'
```

内置演示 apiKey（仅本地演示，非真实凭据，定义在 `data/callers.json`，缺失时回退内置目录）：

| apiKey        | 角色               | 能力                                     |
|---------------|--------------------|------------------------------------------|
| `admin-key`   | ADMIN              | 全部                                     |
| `analyst-key` | ANALYST            | 匹配、受限来源明细、刷新                 |
| `viewer-key`  | RESTRICTED_VIEWER  | 匹配（命中 key 脱敏）、公开来源明细      |

---

## 2. 本地情报文件

目录由 `threatintel.feed-directory` 配置（默认 `data/feeds`）。
**文件名去掉扩展名即来源标识**：`vendorA.jsonl` → 来源 `vendorA`。
文件按文件名升序扫描，保证内容哈希与结果可复现。

### 2.1 支持的两种格式

**JSON Lines（`.jsonl`）**：每行一个 JSON 对象。

```json
{"type": "ip", "value": "192.168.10.10", "severity": "HIGH"}
{"type": "domain", "value": "evil.example.com"}
```

**CSV（`.csv`）**：首行必须为含 `type,value`（`severity` 可选）的表头；
`#` 开头为注释，字段支持双引号与 `""` 转义。

```csv
type,value,severity
ip,"203.0.113.7",HIGH
domain,restricted.internal,CRITICAL
```

**抑制 / 白名单规则**（`threatintel.suppression-file`，JSONL）：

```json
{"id": "SUP-1001", "type": "domain", "pattern": "safe.example.com", "reason": "known false positive domain"}
{"id": "SUP-1002", "type": "ipv4", "pattern": "10.0.0.0/8", "reason": "internal network allowlist"}
```

类型别名（大小写不敏感）：`ip/ipv4/ipv4-addr/addr`、`domain/domain-name/fqdn/hostname`、
`url/uri`、`md5`、`sha1`、`sha256`、`email/email-addr`。

---

## 3. 统一指标模型

所有格式、别名与等价写法最终都归一为不可变记录 `Indicator`：

| 字段           | 含义                                                                 |
|----------------|----------------------------------------------------------------------|
| `type`         | 统一类型：`IPV4 / DOMAIN / URL / HASH_MD5 / HASH_SHA1 / HASH_SHA256 / EMAIL` |
| `value`        | 规范值（唯一去重键的一部分）                                         |
| `display`      | 首次导入的原始展示值                                                 |
| `sources`      | 来源集合（同一指标跨文件导入按集合合并，幂等）                       |
| `severity`     | 收敛后的严重度 `UNKNOWN/LOW/MEDIUM/HIGH/CRITICAL`                    |
| `firstSeen` / `updatedAt` | 时间戳                                                     |
| `conflictNote` | 非空表示发生过定义冲突并已按确定规则收敛（可解释留痕）               |

指标去重键：`type + ":" + 规范value`。

### 3.1 规范值（等价）规则

- **IPv4**：统一点分十进制。等价支持
  - 段进制混淆：十六进制（`0xC0`）、八进制（`0250`）、十进制；
  - 位宽合并写法：`a.b.c.d`、`a.b.cd`（末段16位）、`a.bcd`（末段24位）、`abcd`（32位整数）、`0xC0A80A0A`；
  - 末尾 `:port`、`[ip]:port` 方括号；
  - **CIDR**：主机位清零并校验 `/0../32`，例如 `10.5.6.7/8 → 10.0.0.0/8`；
  - 手写解析，**不触发任何 DNS 查询**。
- **DOMAIN**：小写、去根点 `.`、去前导通配 `*.`，标签合法性与"至少含一个点"校验；
  看起来像 IP 的值不会被当域名。
- **URL**：补默认 scheme、主机小写、剥离默认端口 `80/443` 与 fragment，保留非默认端口。
- **HASH**：小写十六进制，按长度区分 MD5(32)/SHA1(40)/SHA256(64)。
- **EMAIL**：小写、去空白。

### 3.2 匹配等价规则

- IPv4 精确相等；指标为 CIDR 时，查询 IP 落在网段内即命中（网段索引按前缀长度排序）。
- 域名精确相等，或**查询域是指标域的子域**（`a.b.evil.com` 命中 `evil.com`；`notevil.com` 不命中）。
- URL 精确匹配，并按主机与 DOMAIN/IPV4 指标**交叉匹配**（查主机命中等价于查 URL 指标）。
- HASH / EMAIL：规范值精确相等。
- 调用方不传 type 时按值做**确定性类型推断**；无法推断返回 400（`MALFORMED_FORMAT`）。

---

## 4. 冲突与拒绝：不静默丢弃

条目问题一律给出**可区分的原因码**（`RejectionCode`），随 `RefreshOutcome.failures`
逐条返回，并打印 WARN 日志（含来源、原始片段、行号、原因）：

| 原因码               | 触发场景                                       |
|----------------------|------------------------------------------------|
| `MALFORMED_FORMAT`   | 坏 JSON 行、CSV 列数不符/引号未闭合、缺字段等  |
| `UNSUPPORTED_TYPE`   | 类型别名无法识别（如 `quantum-ioc`）           |
| `INVALID_VALUE`      | 类型可识别但值不合法（如 `not-an-ip`、坏 hash）|
| `PARSE_IO_ERROR`     | 文件不可读、目录不可扫描等 IO 问题             |
| `CONFLICT_REJECTED`  | 保留给"定义不可收敛"的冲突（当前实现为收敛）   |

**确定的冲突收敛规则**（同一去重键、不同严重度）：

- 严重度取**最高**（`LOW` 与 `CRITICAL` → `CRITICAL`）；
- 来源取**并集**；
- 在 `conflictNote` 中记录被保留/丢弃的值。
- 完全相同的重复内容：不产生任何变化，计入 `report.duplicates`。

导入统计 `ImportReport`：`totalRaw / accepted / duplicates / mergedConflicts / rejected`。

---

## 5. 刷新一致性保证（并发安全）

- 刷新在 `ReentrantLock.tryLock()` 下**串行执行**；进行期间到达的并发刷新**立即**
  返回 `ALREADY_RUNNING`（不排队、不重试），**不重复计数、不损坏状态**。
- 匹配查询**从不获取刷新锁**，只读一个 `volatile ThreatSnapshot` 引用；
  `ThreatSnapshot` 是**不可变**对象（指标列表、抑制规则、来源计数全部定长不可变），
  因此任一匹配要么基于**完整的新快照**，要么基于**上一份已知良好快照**，
  绝不可能看到部分加载数据。
- **FAIL_CLOSED（默认）**：存在任何文件级或条目级失败 → 整批丢弃、保留旧快照，
  结论为 `REJECTED_PRESERVED`（首装无旧快照时为 `REJECTED_NO_PREVIOUS_STATE`，
  进入空快照）。
- **ACCEPT_PARTIAL**：坏条目逐条记录原因，好条目照常生效。
- **来源级读取失败是硬边界（两种策略一致）**：某个来源文件不可读或文件级解析失败时，
  无论哪种策略本次刷新都不生效——**读取异常绝不会被当成一份合法的空情报**。
  匹配继续按上一份完整可用的代际判定，刷新结论明确为失败并逐来源给出原因。

### 5.1 来源健康：每代可追溯

每次刷新（无论是否生效）都形成一份**逐来源健康留痕** `SourceHealth`，
随 `RefreshOutcome.sourceHealth` 返回；生效代的留痕同时保存在快照上，
可从 `/status` 与 `/generations` 查看：

| 状态                 | 含义                                                     |
|----------------------|----------------------------------------------------------|
| `ADOPTED`            | 来源正常读取并采用                                       |
| `SKIPPED_EMPTY`      | 来源正常读取但**合法地**不含任何条目（合法空情报）       |
| `SKIPPED_UNREADABLE` | 来源这次**没能正常读到**（IO/文件级解析失败），不是空情报 |

### 5.2 刷新代际、按代查询与回滚

- **每一次成功刷新形成一代**（版本号单调递增），可追溯该代用了哪些来源、
  每个来源的采用状态。
- **按代查询**：匹配请求可带 `generation` 指定历史代；缺省看当前生效代。
  指定当前代与缺省结果一致。
- **回滚**：`POST /rollback?version=N` 把当前生效结果切回某个历史代；
  被替换的当前代重新进入历史（回滚本身也是可追溯的代际切换）。
  回滚到当前代返回 `ALREADY_CURRENT`（无操作）。
- **容量上限**：历史代际默认保留最近 **5** 代（`threatintel.history-capacity` 可配）。
  容量超限从最旧端淘汰；**淘汰只影响历史查询/回滚，绝不影响当前生效代**。
  已被淘汰的代不可查询、不可回滚：返回 `GENERATION_EVICTED`（与从未存在的
  `GENERATION_NOT_FOUND` 可区分）。初始空快照（v0）不占历史位。
- **并发一致性**：当前代 + 历史代 + 淘汰水位是一个**不可变整体视图**
  （`volatile` 引用，写者持锁整体替换）。回滚/刷新与查询并发时，
  任一查询只会看到**完整的一代**，绝不出现半新半旧；回滚与刷新共用同一把
  `tryLock`，并发回滚/刷新的第二调用方立即得到 `ALREADY_RUNNING`。
- **相同内容重复刷新**：对目录内文件字节做 SHA-256 哈希（文件名排序后逐个更新），
  哈希相同且已装载 → 返回 `APPLIED_UNCHANGED`，**版本不递增、无漂移、无重复**。
- 版本号单调递增；`firstSeen` 在跨刷新间保留。

刷新结论枚举：`APPLIED / APPLIED_PARTIAL / APPLIED_UNCHANGED / ALREADY_RUNNING /
REJECTED_PRESERVED / REJECTED_NO_PREVIOUS_STATE`。

---

## 6. 抑制/白名单优先级与可解释判定

- 最终结论 `decision ∈ HIT / SUPPRESSED / COVERED / CLEAN`。
- **抑制优先于命中**：先算指标命中；只要存在覆盖该等价集合的规则，结论即 `SUPPRESSED`。
- **覆盖解释（COVERED）**：被抑制/白名单规则圈住、但本身**没有命中任何指标**的查询，
  结论为 `COVERED`——它明确体现"在规则覆盖范围内"，但**不是真正的命中**
  （`matched=false`、`matchedKeys` 为空）。响应同时给出 `covered` 与
  `coveringRuleIds`，`reasons` 中逐条列出覆盖规则及"无指标命中"的说明。
  覆盖判定与命中判定相互独立，且**不因调用方权限不足而改变**。
  未命中且未被覆盖的查询仍为 `CLEAN`（`covered=false`）。
- 规则覆盖语义与指标一致：域名规则覆盖其**子域**；IPv4 规则支持精确与 **CIDR 网段包含**；
  URL 查询按主机做跨类型覆盖判定。
- 响应 `reasons`（并同步打印日志）按顺序给出：
  原始输入 → 类型 → 规范值 → 命中键/网段依据 → 抑制规则 id 与原因。
  结论完全可复核，例如：

```text
input='012.1.2.3' type=IPV4 normalized='10.1.2.3'
exact ipv4 match: 10.1.2.3
suppressed by rule SUP-1002 (pattern='10.0.0.0/8', reason=internal network allowlist)
```

---

## 7. 访问控制权限边界

- 受限来源由 `threatintel.restricted-sources` 配置（演示中 `vendorB` 为受限来源）。
- **匹配接口 `/match` 对所有人开放（含匿名）**：`HIT/SUPPRESSED/CLEAN` 判定、
  `reasons` 与 `matchedKeys` 对所有调用方**完全一致**——权限不足**绝不改变命中本身**。
  区别仅在响应的 `visibleMatchedKeys`：无权调用方看到 `REDACTED[restricted source]`。
- **明细接口 `/indicators` 才做强制鉴权**：
  - 无/未知 apiKey → `401 UNAUTHORIZED`；
  - RESTRICTED_VIEWER/匿名访问受限来源 → `403 ACCESS_DENIED`（响应带来源与调用方）；
  - ANALYST/ADMIN → `200` 返回完整明细。
- 一个指标若同时来自公开与受限来源，无权调用方对该 key 整体被拒绝（不泄露部分明细）。
- 刷新接口仅 ANALYST/ADMIN 可触发。

---

## 8. HTTP 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/threat-intel/match` | body `{type?, value, apiKey?, generation?}`，返回判定 + 覆盖解释 + 脱敏后可见 key；`generation` 指定历史代 |
| GET  | `/api/v1/threat-intel/indicators?key=TYPE:value` | 明细，`X-API-Key` 鉴权，受限来源 403 |
| POST | `/api/v1/threat-intel/refresh?policy=FAIL_CLOSED|ACCEPT_PARTIAL` | 手动刷新（ANALYST/ADMIN），结论含逐来源健康 |
| POST | `/api/v1/threat-intel/rollback?version=N` | 回滚当前生效结果到历史代（ANALYST/ADMIN） |
| GET  | `/api/v1/threat-intel/generations` | 代际列表：当前生效代 + 历史代，含每代来源健康 |
| GET  | `/api/v1/threat-intel/status` | 版本、哈希、指标/抑制数、来源计数、受限来源、当前代来源健康 |

错误响应可区分：`400 INVALID_INDICATOR`（带 `reasonCode`）、`401 UNAUTHORIZED`、
`403 ACCESS_DENIED`、`404 GENERATION_UNAVAILABLE`（`reason` 为
`GENERATION_EVICTED` / `GENERATION_NOT_FOUND`）。

---

## 9. 配置项（`application.properties`）

```properties
threatintel.feed-directory=data/feeds
threatintel.suppression-file=data/suppressions.jsonl
threatintel.caller-file=data/callers.json
threatintel.restricted-sources[0]=vendorB
threatintel.refresh-policy=FAIL_CLOSED
threatintel.history-capacity=5
```

情报目录不存在不阻断启动（进入空快照并告警）。测试资源目录
`src/test/resources/` 下另有 `malformed-feeds/`、`conflict-feeds/` 等专用数据集。

---

## 10. 测试与本地验证

```bash
mvn -o test
```

| 测试类 | 覆盖内容 |
|--------|----------|
| `NormalizerTest` | 大小写、进制/位宽混淆、CIDR 清零、域名根点/通配/子域、URL 默认端口、hash/email、类型推断与可区分拒绝码 |
| `FeedParserTest` | 两种格式好行解析、坏行逐行拒绝、坏 CSV 表头文件级错误 |
| `ThreatIntelIngestionTest` | 双格式导入计数、FAIL_CLOSED 保留旧状态、首装失败、ACCEPT_PARTIAL、严重度冲突最高收敛+留痕、重复刷新幂等 |
| `ConcurrentRefreshMatchTest` | 12 线程并发刷新（恰好 1 个执行，其余 ALREADY_RUNNING，版本/计数不损坏）、8 查询线程 × 30 刷新并发下每判定都落在完整快照上 |
| `SuppressionAndAccessTest` | 抑制优先、网段/子域覆盖、403 与 200、**拒绝访问不改变命中**、匿名判定一致+key 脱敏 |
| `MatchExplainabilityTest` | Logback 捕获断言日志含输入/归一值/结论/规则 id，拒绝日志含可区分原因码 |
| `ThreatIntelApiIntegrationTest` | `@SpringBootTest + MockMvc` 端到端：HIT/SUPPRESSED、400/401/403、脱敏、刷新角色、状态 |
| `SourceHealthRefreshTest` | 每代来源健康留痕；合法空来源 vs 读取失败可区分；来源不可读时两种策略都整批不生效、匹配按上一代判定 |
| `GenerationHistoryRollbackTest` | 按代查询、回滚切换与可追溯、容量淘汰（`GENERATION_EVICTED`/`GENERATION_NOT_FOUND`）、回滚与查询并发只见完整代 |
| `CoverageExplanationTest` | 被规则圈住但未命中 -> `COVERED`（非命中）；命中且抑制 -> `SUPPRESSED`；权限不足不改变覆盖/命中判定 |
| `GenerationApiIntegrationTest` | 端到端：`/generations` 代际与健康、按代匹配、回滚角色与结论、`COVERED` 响应、404 可区分 |

结果稳定可复现：文件按名排序、规范值与快照确定、并发结论可枚举；
判定依据在响应 `reasons` 与 INFO/WARN 日志中均可追溯。

---

## 11. 代码结构

```
model/        统一模型：Indicator / ThreatSnapshot / Verdict / SuppressionRule / 原因码
normalize/    Normalizer（类型与值归一、IPv4 手写解析、CIDR、类型推断）
ingest/       FeedParser 接口 + JsonlFeedParser / CsvFeedParser（逐行拒绝）
source/       LocalFeedRepository（本地目录扫描、解析分发、内容哈希）
refresh/      ThreatIntelService（锁与不可变代际注册表、冲突收敛、刷新策略、回滚）
match/        MatchEngine（等价匹配、跨类型匹配、抑制覆盖、快照索引）
access/       CallerDirectory / AccessControlService / AccessDeniedException
web/          REST 控制器、DTO、全局异常处理
config/       ThreatIntelProperties
bootstrap/    FeedStartupLoader（启动首装）
```
