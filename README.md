# 威胁情报 IOC 接入 / 归一 / 匹配链路

纯本地实现：从工程目录下的本地文件读取两种以上格式的情报指标，归一到统一模型，
在并发刷新下提供一致、可解释的匹配判定，并对受限来源的指标明细做角色访问控制。
**不依赖任何外部服务、数据库或凭据**，仅使用工程已有的 Spring Boot Web / Test 与
JDK 自带能力（Jackson 随 spring-boot-starter-web 引入）。

## 1. 构建与一次性本地验证

```bash
mvn test          # 编译 + 运行全部 36 个测试（单元 + Spring/MockMvc 集成）
mvn spring-boot:run   # 启动后自动刷新 intel-data/，默认端口 8080
```

启动后示例：

```bash
# 匹配（大小写/混淆写法/网段/子域等价；判定不受 X-Roles 影响）
curl "http://localhost:8080/api/match?value=0x7f000001&type=ip"
curl -G "http://localhost:8080/api/match" --data-urlencode "value=http://bad.example.com/path?z=1&a=2"

# 手动刷新（串行，返回完整结论；重复内容返回 UNCHANGED）
curl -X POST http://localhost:8080/api/admin/refresh

# 指标明细（受限来源需带角色）
curl -H "X-Roles: restricted-intel:reader" \
     http://localhost:8080/api/indicators/ip/172.16.5.5

curl http://localhost:8080/api/health
```

日志（`logging.level...threatinteliocjava=INFO`）会打印每次匹配的**输入、归一值、
状态、判定依据、调用方角色**，以及刷新时每条**拒绝条目的文件/行号/原因/原始输入**
与每条冲突的收敛规则。

## 2. 本地情报源（仅文件）

配置见 `src/main/resources/application.properties`：

| 配置 | 含义 |
| --- | --- |
| `intel.directory` | 情报目录（默认 `intel-data`，相对工作目录），只扫描普通文件、按文件名排序 |
| `intel.restricted-sources` | 受限来源文件名列表（明细查询需要角色） |
| `intel.source-roles.<文件名>` | 该来源明细所需角色，逗号分隔；缺省为 `restricted-intel:reader` |
| `intel.refresh-on-startup` | 启动后是否自动刷新一次 |

支持的格式：

1. **JSON**（`*.json`，由 `JsonIntelParser` 处理）：顶层为指标数组，或
   `{"indicators":[...], "suppressions":[...]}` 对象。
   条目字段：`type,value,severity,confidence,description`；
   抑制规则：`id,type,value,reason`。
2. **CSV**（`*.csv`，由 `CsvIntelParser` 处理）：必须有表头，必需列
   `type,value`，可选列 `severity,confidence,description`；支持 `#` 注释、
   空行、`"..."` 引号与 `""` 转义。
3. **抑制/白名单**（固定文件名 `suppressions.csv`，`SuppressionListParser`）：
   表头 `id,type,value,reason`。

未识别扩展名的文件被跳过并记录日志，不影响刷新。

## 3. 统一指标模型

`model/IocIndicator`（不可变 record）：

```
type            统一类型枚举：IP / CIDR / DOMAIN / URL / HASH
canonicalValue  归一后的规范值（匹配键）
displayValue    首次见到的原始写法（用于可解释展示）
severity        UNKNOWN / LOW / MEDIUM / HIGH / CRITICAL（空或未知收敛为 UNKNOWN）
confidence      0-100；缺省 50；非整数或越界条目被拒绝
description     描述
sources         收敛到该指标的全部来源文件名（有序、去重），用于溯源与权限
requiredRoles   查看明细所需角色集合（空=不限制；刷新时按来源配置填充）
```

类型代码在解析时做宽松映射（如 `ipv4/address→IP`、`hostname→DOMAIN`、
`uri→URL`、`md5/sha256→HASH`），映射不到的代码**不是静默丢弃**，而是以
`UNSUPPORTED_INDICATOR_TYPE` 拒绝。

### 3.1 错误不静默：拒绝原因（`RejectionReason`）可区分

- `UNSUPPORTED_INDICATOR_TYPE` 类型代码不在支持范围
- `MISSING_REQUIRED_FIELD` 缺 type / value / 抑制规则必填字段
- `MALFORMED_VALUE` IP/网段/哈希/域名/URL/置信度非法
- `MALFORMED_LINE` CSV 列数与表头不符、引号未闭合、JSON 条目不是对象
- `MALFORMED_SUPPRESSION_RULE` 抑制规则缺字段或同 id 定义冲突
- `PARSE_ERROR` 文件级致命错误（JSON 整体损坏、CSV 缺必需列表头等）

每条拒绝都带 `sourceFile / line / rawContent / reason / detail`，
进入刷新报告的 `rejections`，并逐条打印日志。

### 3.2 重复与冲突的确定规则（无状态漂移）

解析按**文件名排序**进行，同一“类型 + 规范值”：

- 若 `severity / confidence / description` 完全一致（仅大小写或写法不同）→
  **重复合并**：只保留一条，来源并入 `sources`，计入 `duplicateMerged`；
- 否则视为**同一指标定义冲突**，按确定性优先级收敛并写 `conflicts`：
  1. `confidence` 高者胜；
  2. 相同则 `severity` 级别高者胜；
  3. 再相同则按来源文件名、再按原始写法字典序。
  选中/忽略双方及规则都保存在 `ConflictRecord`。

抑制规则按 `id` 去重：同 id 同定义去重；同 id 不同定义按
`MALFORMED_SUPPRESSION_RULE` 拒绝（不静默覆盖）。

## 4. 等价归一规则（`normalize/IocNormalizer`）

全程**不做 DNS 查询**，主机名不会被当作 IP：

- **IP**：点分十进制；混淆写法 `2130706433`（32 位十进制整数）、
  `0x7F000001`（十六进制整数）与 `127.0.0.1` 等价；IPv6 统一压缩写法，
  支持内嵌 IPv4（`::ffff:1.2.3.4`）。
- **CIDR**：主机位清零后比较（`192.168.1.50/24 ≡ 192.168.1.0/24`），
  IPv4/IPv6 网段都支持包含判定。
- **DOMAIN**：小写；去末尾点；全角点 `．`/中文句号 `。` 视为点；
  Unicode 域名经 IDN 转 ASCII（`bücher.example ≡ xn--bcher-kva.example`）；
  校验标签字符/长度/连字符/TLD。
- **URL**（仅 http/https）：scheme/host 小写；host 走 IP/域名归一；
  去掉 `:80/:443` 默认端口；空路径归一为 `/`；查询参数按名再按值排序；
  去 fragment 与 userinfo。
- **HASH**：转小写十六进制，长度必须为 32/40/64（md5/sha1/sha256）。

## 5. 匹配语义与优先级（`service/MatcherService`）

输入显式带 `type` 时按该类型归一，否则自动检测；归一失败 →
`INVALID_INPUT`（原因可区分）。匹配等价形式：

- IP：精确相等 **或** 被某网段包含（取前缀最长/最具体的网段）；
- DOMAIN：本身或为指标域的子域（取最长/最具体指标；如
  `a.b.example.com` 命中指标域 `example.com`）；
- URL / HASH / CIDR：规范值精确相等。

**抑制/白名单优先于命中**：用同一套等价语义（含网段包含、子域）查找
`SuppressionRule`。命中且命中被抑制 → `SUPPRESSED`，结论同时给出命中指标
与抑制规则及原因（如“命中指标 X，但抑制规则 WL 优先：原因 …”）。
判定状态只有 `HIT / SUPPRESSED / NO_HIT / INVALID_INPUT`，都附
`reason`（判定依据）与 `normalizedValue`。

## 6. 刷新一致性保证（`service/RefreshService` + `IntelSnapshot`）

- 所有匹配查询只读 `IntelRegistry` 中一个 **AtomicReference 指向的不可变
  快照**（`IntelSnapshot` 的索引在构建后不可修改）。刷新时全部解析、归一、
  去重、冲突收敛都在临时结构中完成，**成功后才原子发布**。
  ⇒ 任一查询要么看到完整旧快照、要么看到完整新快照，**绝不会看到部分加载**。
- 刷新之间用 `ReentrantLock` **串行**：并发刷新只会真正执行一次加载，其余复用
  结果；不会重复计数或损坏状态（见
  `RefreshServiceTest.concurrentRefreshesAreSerializedAndStable` 与
  `ConcurrentRefreshQueryIntegrationTest`）。
- **整体失败保留旧状态**：目录缺失/I/O 异常/任一文件文件级致命错误 →
  返回 `success=false, status=FAILED, failureReason=...`，**不清空、不替换**
  当前快照，查询继续基于上一份已知良好结果。
- **部分失败不阻断**：条目级拒绝/冲突 → 正常发布新快照但 `status=PARTIAL`，
  明细在 `rejections/conflicts` 中可查。
- **幂等**：对“归一后指标 + 抑制规则 + 拒绝明细”的规范渲染取 SHA-256 内容哈希；
  内容未变时返回 `status=UNCHANGED` 且不重新发布，重复导入不产生重复或漂移。

## 7. 权限边界（`service/AccessControlService`）

- 调用方角色来自请求头 `X-Roles`（逗号分隔，统一小写）；缺省为匿名空集。
- 权限**只作用于明细接口** `GET /api/indicators/{type}/{value}`：
  - 指标来源包含受限来源且调用方不具备全部所需角色 → **403 ACCESS_DENIED**；
  - 不存在 → 404 NOT_FOUND；类型/取值非法 → 400 BAD_REQUEST。
- **匹配判定与权限完全解耦**：匿名调用方对受限指标的 `/api/match` 判定与
  有权限调用方逐字段一致（见 `permissionDoesNotChangeVerdict`）。
  匹配结论只回传命中所需的最小字段，完整描述仅在明细接口通过鉴权后给出。

## 8. HTTP 接口

| 方法路径 | 说明 |
| --- | --- |
| `GET /api/match?value=&type=` | 匹配判定；`type` 可省略（自动检测）；`X-Roles` 仅审计 |
| `GET /api/indicators/{type}/{value}` | 指标明细；受限来源 403/404/400 |
| `POST /api/admin/refresh` | 手动刷新，返回 `RefreshReport` |
| `GET /api/health` | 是否已加载、构建时间、指标/抑制数、上次刷新状态 |

`RefreshReport` 字段：`success,status(OK/PARTIAL/UNCHANGED/FAILED),
refreshedAt,contentHash,filesScanned,acceptedEntries,duplicateMerged,
conflictConverged,totalIndicators,suppressionRules,rejections[],conflicts[],
failureReason`。

## 9. 代码结构

```
model/      统一模型、枚举、拒绝原因、刷新报告、判定结论（不可变 record）
normalize/  IocNormalizer（归一）、Cidr（网段解析/包含）、NormalizationException
ingest/     两种格式解析器 + suppressions.csv + 目录扫描分派
service/    IntelSnapshot/IntelRegistry（不可变快照与原子持有）、
            RefreshService（串行刷新/幂等/失败保留）、MatcherService、
            AccessControlService 及业务异常
config/     IntelProperties、启动刷新
web/        IntelController、统一异常处理
```

## 10. 测试覆盖（`mvn test`，结果稳定可复现）

- `IocNormalizerTest`：IP 混淆、IPv6、CIDR、域名/IDN、URL 参数排序、哈希、检测；
- `IntelParserTest`：JSON/CSV/抑制表的文件级致命 vs 条目级拒绝、行号与引号；
- `RefreshServiceTest`：拒绝原因区分、重复幂等、冲突确定收敛、
  **致命失败保留旧快照**、16 线程并发刷新不重复计数；
- `MatcherServiceTest`：等价命中、网段/子域、**抑制优先级**、
  **无权限不改变命中**、明细 403/404/400、空快照；
- `ConcurrentRefreshQueryIntegrationTest`：12 线程并发刷新×查询，
  断言每个判定自洽（HIT 必带 match、SUPPRESSED 必带规则）、HTTP 层角色边界；
- `RefreshFailureRetentionIntegrationTest`：破坏文件后刷新 FAILED，
  旧快照仍提供命中。
