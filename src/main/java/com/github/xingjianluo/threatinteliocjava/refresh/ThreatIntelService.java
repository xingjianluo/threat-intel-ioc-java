package com.github.xingjianluo.threatinteliocjava.refresh;

import com.github.xingjianluo.threatinteliocjava.access.AccessControlService;
import com.github.xingjianluo.threatinteliocjava.access.AccessDeniedException;
import com.github.xingjianluo.threatinteliocjava.access.Caller;
import com.github.xingjianluo.threatinteliocjava.ingest.ImportReport;
import com.github.xingjianluo.threatinteliocjava.ingest.RawEntry;
import com.github.xingjianluo.threatinteliocjava.model.ConflictNote;
import com.github.xingjianluo.threatinteliocjava.model.Indicator;
import com.github.xingjianluo.threatinteliocjava.model.IndicatorType;
import com.github.xingjianluo.threatinteliocjava.model.RejectedEntry;
import com.github.xingjianluo.threatinteliocjava.model.RejectionCode;
import com.github.xingjianluo.threatinteliocjava.model.Severity;
import com.github.xingjianluo.threatinteliocjava.model.SuppressionRule;
import com.github.xingjianluo.threatinteliocjava.model.ThreatSnapshot;
import com.github.xingjianluo.threatinteliocjava.model.Verdict;
import com.github.xingjianluo.threatinteliocjava.match.MatchEngine;
import com.github.xingjianluo.threatinteliocjava.normalize.NormalizationException;
import com.github.xingjianluo.threatinteliocjava.normalize.NormalizedRaw;
import com.github.xingjianluo.threatinteliocjava.normalize.Normalizer;
import com.github.xingjianluo.threatinteliocjava.source.LocalFeedRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 情报核心服务。
 *
 * <p>一致性保证：
 * <ul>
 *   <li>刷新在 {@link ReentrantLock} + CAS 标志位保护下串行执行，
 *       并发刷新的第二调用方立即得到 {@code ALREADY_RUNNING}，状态不变、不重复计数。</li>
 *   <li>匹配读取 {@code volatile} 引用指向的不可变 {@link ThreatSnapshot}，
 *       因此每次查询要么基于完整的新快照，要么基于上一份已知良好快照，
 *       绝不可能看到部分加载数据。</li>
 *   <li>FAIL_CLOSED（默认）：任何文件级或条目级失败都会整批拒绝、保留旧快照
 *       （首装无旧快照时结论为 REJECTED_NO_PREVIOUS_STATE，进入空快照）；
 *       ACCEPT_PARTIAL：逐条拒绝并记录原因，其余好条目照常生效（首装同样适用）。</li>
 *   <li>相同内容（按文件字节哈希判定）重复刷新返回 {@code APPLIED_UNCHANGED}，
 *       版本不递增、不产生重复或漂移。</li>
 * </ul>
 */
@Service
public class ThreatIntelService {

    private static final Logger log = LoggerFactory.getLogger(ThreatIntelService.class);

    private final LocalFeedRepository repository;
    private final Normalizer normalizer;
    private final MatchEngine matchEngine;
    private final AccessControlService accessControl;
    private final int historyCapacity;

    private final ReentrantLock refreshLock = new ReentrantLock();
    /**
     * 当前生效代 + 历史代 + 淘汰水位的不可变整体视图。
     * 写者（刷新/回滚）持锁整体替换该引用；读者一次读取即得到一致视图，
     * 因此并发回滚与查询只会看到完整的一代，绝不出现半新半旧。
     */
    private volatile GenerationRegistry registry = GenerationRegistry.initial();

    /** 代际注册表（不可变）：当前生效代、历史代（旧 -> 新）、已淘汰最高版本。 */
    private record GenerationRegistry(
            ThreatSnapshot current,
            List<ThreatSnapshot> history,
            long maxEvictedVersion) {

        static GenerationRegistry initial() {
            return new GenerationRegistry(ThreatSnapshot.empty(), List.of(), 0L);
        }
    }

    /**
     * Spring 装配构造器：历史容量来自配置 {@code threatintel.history-capacity}。
     */
    @org.springframework.beans.factory.annotation.Autowired
    public ThreatIntelService(LocalFeedRepository repository,
                              Normalizer normalizer,
                              MatchEngine matchEngine,
                              AccessControlService accessControl,
                              com.github.xingjianluo.threatinteliocjava.config.ThreatIntelProperties properties) {
        this(repository, normalizer, matchEngine, accessControl, properties.getHistoryCapacity());
    }

    /** 测试/手工装配构造器：默认保留最近 5 代历史。 */
    public ThreatIntelService(LocalFeedRepository repository,
                              Normalizer normalizer,
                              MatchEngine matchEngine,
                              AccessControlService accessControl) {
        this(repository, normalizer, matchEngine, accessControl, 5);
    }

    public ThreatIntelService(LocalFeedRepository repository,
                              Normalizer normalizer,
                              MatchEngine matchEngine,
                              AccessControlService accessControl,
                              int historyCapacity) {
        this.repository = repository;
        this.normalizer = normalizer;
        this.matchEngine = matchEngine;
        this.accessControl = accessControl;
        this.historyCapacity = Math.max(0, historyCapacity);
    }

    public ThreatSnapshot currentSnapshot() {
        return registry.current();
    }

    /**
     * 从本地目录执行一次刷新。
     *
     * <p>并发语义：整个装载流程（含文件哈希与读取）在 {@link ReentrantLock#tryLock()}
     * 保护下串行执行；任何在另一刷新进行期间到达的调用立即得到 {@code ALREADY_RUNNING}
     * （不排队、不重试），状态保持不变、不重复计数。匹配查询从不获取该锁，
     * 只读取 volatile 的不可变快照，因此刷新期间查询完全不受阻塞。
     */
    public RefreshOutcome refresh(String directory,
                                  String suppressionFile,
                                  Set<String> configuredRestrictedSources,
                                  RefreshPolicy policy) {
        if (!refreshLock.tryLock()) {
            return alreadyRunning();
        }
        try {
            return doRefresh(directory, suppressionFile, configuredRestrictedSources, policy);
        } finally {
            refreshLock.unlock();
        }
    }

    private RefreshOutcome alreadyRunning() {
        ThreatSnapshot current = registry.current();
        log.warn("refresh skipped: another refresh is already running (snapshot v{} retained)",
                current.version());
        return new RefreshOutcome("ALREADY_RUNNING", current.version(),
                zeroReport(), List.of(),
                "refresh already in progress; existing snapshot retained");
    }

    private RefreshOutcome doRefresh(String directory,
                                     String suppressionFile,
                                     Set<String> configuredRestrictedSources,
                                     RefreshPolicy policy) {
        ThreatSnapshot previous = registry.current();
        long start = System.currentTimeMillis();
        log.info("refresh started: directory={} policy={} fromVersion={}",
                directory, policy, previous.version());

        // 1) 相同内容短路：无版本递增、无状态漂移（在刷新锁内，判定确定）
        String hash;
        try {
            hash = repository.contentHash(directory);
        } catch (RuntimeException e) {
            return rejectWithPrevious(previous, policy, List.of(),
                    new RejectedEntry(null, directory, RejectionCode.PARSE_IO_ERROR,
                            "hash failure: " + e.getMessage()),
                    "refresh failed during hashing; existing snapshot retained");
        }
        if (hash.equals(previous.contentHash()) && previous.version() > 0) {
            log.info("refresh content unchanged (hash={}), keeping snapshot v{}",
                    hash, previous.version());
            return new RefreshOutcome("APPLIED_UNCHANGED", previous.version(),
                    zeroReport(), List.of(),
                    "feed content unchanged; snapshot v" + previous.version() + " retained");
        }

        // 2) 读取并解析全部文件
        LocalFeedRepository.LoadedDirectory loaded;
        try {
            loaded = repository.load(directory);
        } catch (RuntimeException e) {
            return rejectWithPrevious(previous, policy, List.of(),
                    new RejectedEntry(null, directory, RejectionCode.PARSE_IO_ERROR,
                            "load failure: " + e.getMessage()),
                    "refresh failed while reading files; existing snapshot retained");
        }

        // 2a) 来源健康留痕：正常采用 / 合法为空 / 读取失败，三者可区分
        List<com.github.xingjianluo.threatinteliocjava.model.SourceHealth> sourceHealth =
                deriveSourceHealth(loaded);

        // 2b) 来源级读取失败（文件不可读/文件级解析错误）绝不能被当成合法空情报：
        //     无论 FAIL_CLOSED 还是 ACCEPT_PARTIAL，本次刷新都不生效，
        //     匹配继续按上一份完整可用的代际判定。
        if (!loaded.fileFailures().isEmpty()) {
            List<RejectedEntry> sourceFailures = new ArrayList<>(loaded.fileFailures());
            sourceFailures.forEach(f -> log.error(
                    "source unreadable: source={} file={} code={} detail={}",
                    f.source(), f.rawLine(), f.code(), f.detail()));
            String outcome = previous.version() == 0L
                    ? "REJECTED_NO_PREVIOUS_STATE" : "REJECTED_PRESERVED";
            String message = "refresh failed: " + sourceFailures.size()
                    + " source(s) unreadable (an unreadable source is never treated as"
                    + " legitimately empty); snapshot v" + previous.version() + " retained";
            log.error("{} (policy={})", message, policy);
            return new RefreshOutcome(outcome, previous.version(), zeroReport(),
                    List.copyOf(sourceFailures), message, sourceHealth);
        }

        // 3) 归一化每条记录；逐行拒绝（含解析阶段已发现的坏行）
        List<RejectedEntry> rejected = new ArrayList<>(loaded.fileFailures());
        // key -> 刷新内累积的规范条目（含冲突收敛后的严重度与留痕）
        Map<String, NormalizedRaw> normalizedByKey = new LinkedHashMap<>();
        // key -> 该指标出现过的来源集合
        Map<String, TreeSet<String>> sourcesByKey = new LinkedHashMap<>();
        for (LocalFeedRepository.FeedBatch batch : loaded.batches()) {
            for (RejectedEntry r : batch.batch().rejected()) {
                rejected.add(new RejectedEntry(batch.source(), r.rawLine(), r.code(), r.detail()));
            }
        }
        int acceptedRaw = 0;
        for (LocalFeedRepository.FeedBatch batch : loaded.batches()) {
            String source = batch.source();
            for (RawEntry entry : batch.batch().entries()) {
                try {
                    NormalizedRaw nr = normalizer.normalize(
                            entry.rawType(), entry.rawValue(), entry.severity());
                    String key = nr.type() + ":" + nr.value();
                    acceptedRaw++;
                    sourcesByKey.computeIfAbsent(key, k -> new TreeSet<>()).add(source);
                    NormalizedRaw existing = normalizedByKey.get(key);
                    if (existing == null) {
                        normalizedByKey.put(key, nr);
                    } else if (existing.severity() == nr.severity()
                            && existing.conflictNote() == null) {
                        // 完全重复内容：无任何状态变化
                    } else if (existing.severity() == nr.severity()) {
                        // 曾冲突过、本次值一致：保留既有留痕
                        normalizedByKey.put(key, existing);
                    } else {
                        // 严重度冲突：确定性收敛为最高，并在条目上留痕
                        Severity higher = existing.severity().ordinal() >= nr.severity().ordinal()
                                ? existing.severity() : nr.severity();
                        String previousNote = existing.conflictNote() == null ? ""
                                : existing.conflictNote() + "; ";
                        String note = previousNote + new ConflictNote("severity",
                                higher.name(), existing.severity() + "/" + nr.severity())
                                .describe();
                        normalizedByKey.put(key, new NormalizedRaw(nr.type(), nr.value(),
                                existing.display(), higher, note));
                        log.warn("conflicting severity for {}: {} vs {} -> kept {}",
                                key, existing.severity(), nr.severity(), higher);
                    }
                } catch (NormalizationException e) {
                    rejected.add(new RejectedEntry(source,
                            "L" + entry.line() + ": " + truncate(entry.rawType()
                                    + "," + entry.rawValue()),
                            e.code(), e.getMessage()));
                }
            }
        }

        // 4) 抑制规则（本地文件，缺失即空；坏行逐条拒绝）
        List<RejectedEntry> suppressionFailures = new ArrayList<>();
        List<SuppressionRule> suppressions = loadSuppressions(suppressionFile, suppressionFailures);
        rejected.addAll(suppressionFailures);

        int duplicateRawLines = acceptedRaw - normalizedByKey.size();
        long mergedConflicts = normalizedByKey.values().stream()
                .filter(n -> n.conflictNote() != null).count();
        ImportReport report = new ImportReport(
                acceptedRaw,
                normalizedByKey.size(),
                Math.max(0, duplicateRawLines),
                (int) mergedConflicts,
                List.copyOf(rejected));

        // 5) 策略判定
        boolean hasFailure = !rejected.isEmpty();
        if (hasFailure && policy == RefreshPolicy.FAIL_CLOSED) {
            String why = "FAIL_CLOSED policy: " + rejected.size()
                    + " rejected entry/file; batch discarded";
            log.warn("refresh rejected, snapshot v{} preserved: {}", previous.version(), why);
            rejected.forEach(r -> log.warn("rejected item: source={} item={} code={} detail={}",
                    r.source(), r.rawLine(), r.code(), r.detail()));
            String outcome = previous.version() == 0L
                    ? "REJECTED_NO_PREVIOUS_STATE" : "REJECTED_PRESERVED";
            return new RefreshOutcome(outcome, previous.version(), report,
                    List.copyOf(rejected), why, sourceHealth);
        }
        if (hasFailure) {
            log.warn("ACCEPT_PARTIAL: applying {} indicators, {} rejected items recorded",
                    normalizedByKey.size(), rejected.size());
            rejected.forEach(r -> log.warn("rejected item (recorded): source={} item={} code={} detail={}",
                    r.source(), r.rawLine(), r.code(), r.detail()));
        }

        // 6) 构建并原子切换新快照
        long now = System.currentTimeMillis();
        Map<String, Indicator> merged = new TreeMap<>();
        for (NormalizedRaw nr : normalizedByKey.values()) {
            String key = nr.type() + ":" + nr.value();
            TreeSet<String> sources = new TreeSet<>(
                    sourcesByKey.getOrDefault(key, new TreeSet<>()));
            Indicator existing = previous.indicators().stream()
                    .filter(i -> i.key().equals(key)).findFirst().orElse(null);
            long firstSeen = existing != null ? existing.firstSeen() : now;
            merged.put(key, new Indicator(nr.type(), nr.value(), nr.display(),
                    Set.copyOf(sources), nr.severity(), firstSeen, now, nr.conflictNote()));
        }
        ThreatSnapshot newSnapshot = buildSnapshot(previous.version(), hash, merged,
                suppressions, sourceHealth);
        this.registry = advance(registry, newSnapshot);
        accessControl.updateRestrictedSources(configuredRestrictedSources);
        log.info("refresh applied: version={} indicators={} suppressions={} rejected={} in {}ms",
                newSnapshot.version(), newSnapshot.indicators().size(),
                suppressions.size(), rejected.size(), System.currentTimeMillis() - start);
        return new RefreshOutcome(hasFailure ? "APPLIED_PARTIAL" : "APPLIED",
                newSnapshot.version(), report, List.copyOf(rejected),
                hasFailure ? "applied with " + rejected.size() + " rejected items recorded"
                        : "refresh applied cleanly",
                sourceHealth);
    }

    /**
     * 从目录装载结果推导每个来源的健康状态（按来源名排序，确定可复现）。
     * 文件级失败 -> SKIPPED_UNREADABLE；解析成功但无任何条目 -> SKIPPED_EMPTY；
     * 其余 -> ADOPTED。
     */
    private List<com.github.xingjianluo.threatinteliocjava.model.SourceHealth> deriveSourceHealth(
            LocalFeedRepository.LoadedDirectory loaded) {
        Map<String, com.github.xingjianluo.threatinteliocjava.model.SourceHealth> bySource =
                new TreeMap<>();
        for (LocalFeedRepository.FeedBatch batch : loaded.batches()) {
            boolean empty = batch.batch().entries().isEmpty();
            bySource.put(batch.source(), empty
                    ? new com.github.xingjianluo.threatinteliocjava.model.SourceHealth(
                            batch.source(),
                            com.github.xingjianluo.threatinteliocjava.model.SourceStatus.SKIPPED_EMPTY,
                            "source parsed successfully but contained no entries"
                                    + " (legitimately empty)")
                    : new com.github.xingjianluo.threatinteliocjava.model.SourceHealth(
                            batch.source(),
                            com.github.xingjianluo.threatinteliocjava.model.SourceStatus.ADOPTED,
                            "source read and adopted"));
        }
        for (RejectedEntry failure : loaded.fileFailures()) {
            String source = failure.source() == null ? "<unknown>" : failure.source();
            bySource.put(source, new com.github.xingjianluo.threatinteliocjava.model.SourceHealth(
                    source,
                    com.github.xingjianluo.threatinteliocjava.model.SourceStatus.SKIPPED_UNREADABLE,
                    failure.code() + ": " + failure.detail()));
        }
        return List.copyOf(bySource.values());
    }

    /**
     * 生成"切换到 next 为当前生效代"的新注册表（刷新锁内调用）：
     * 被替换的当前代压入历史（v0 空快照不占位），容量超限时从最旧端淘汰。
     * 淘汰只影响历史查询/回滚，绝不影响当前生效代。
     */
    private GenerationRegistry advance(GenerationRegistry reg, ThreatSnapshot next) {
        List<ThreatSnapshot> hist = new ArrayList<>(reg.history());
        if (reg.current().version() > 0L) {
            hist.add(reg.current());
        }
        long maxEvicted = evictOverflow(hist, reg.maxEvictedVersion());
        return new GenerationRegistry(next, List.copyOf(hist), maxEvicted);
    }

    /** 容量超限从最旧端淘汰，返回新的淘汰水位。 */
    private long evictOverflow(List<ThreatSnapshot> hist, long maxEvicted) {
        while (hist.size() > historyCapacity) {
            ThreatSnapshot evicted = hist.remove(0);
            maxEvicted = Math.max(maxEvicted, evicted.version());
            log.info("generation v{} evicted from history (capacity={})",
                    evicted.version(), historyCapacity);
        }
        return maxEvicted;
    }

    private List<SuppressionRule> loadSuppressions(String file, List<RejectedEntry> failures) {        String content;
        try {
            content = repository.readTextFile(file);
        } catch (RuntimeException e) {
            failures.add(new RejectedEntry("suppressions", file,
                    RejectionCode.PARSE_IO_ERROR, e.getMessage()));
            return List.of();
        }
        if (content == null) {
            return List.of();
        }
        List<SuppressionRule> rules = new ArrayList<>();
        String[] lines = content.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            try {
                var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                var node = mapper.readTree(line);
                String id = node.path("id").asText(null);
                String typeText = node.path("type").asText(null);
                String rawPattern = node.path("pattern").asText(null);
                String reason = node.path("reason").asText("manual suppression");
                if (id == null || typeText == null || rawPattern == null) {
                    throw new IllegalArgumentException("fields id/type/pattern are required");
                }
                IndicatorType type = normalizer.normalizeType(typeText);
                String pattern = normalizer.normalizeValue(type, rawPattern);
                rules.add(new SuppressionRule(id, type, pattern, reason));
            } catch (Exception e) {
                RejectionCode code = e instanceof NormalizationException ne
                        ? ne.code() : RejectionCode.MALFORMED_FORMAT;
                failures.add(new RejectedEntry("suppressions",
                        "L" + (i + 1) + ": " + truncate(line), code,
                        "invalid suppression rule: " + e.getMessage()));
            }
        }
        rules.sort(Comparator.comparing(SuppressionRule::id));
        return List.copyOf(rules);
    }

    private RefreshOutcome rejectWithPrevious(ThreatSnapshot previous, RefreshPolicy policy,
                                              List<RejectedEntry> more, RejectedEntry failure,
                                              String message) {
        List<RejectedEntry> all = new ArrayList<>(more);
        all.add(failure);
        log.error("{} (snapshot v{} preserved)", message, previous.version());
        String outcome = previous.version() == 0L
                ? "REJECTED_NO_PREVIOUS_STATE" : "REJECTED_PRESERVED";
        return new RefreshOutcome(outcome, previous.version(), zeroReport(),
                List.copyOf(all), message);
    }

    /** 匹配查询：始终基于某一份完整快照，访问控制不影响命中结论。 */
    public Verdict match(String typeHint, String input, Caller caller) {
        return match(typeHint, input, caller, null);
    }

    /**
     * 按代际匹配查询：generation 为 null 时看当前生效代；指定版本时看该代历史结果。
     * 无论看哪一代，判定都基于一份完整不可变快照，绝不出现半新半旧。
     */
    public Verdict match(String typeHint, String input, Caller caller, Long generation) {
        ThreatSnapshot read = resolveGeneration(generation);
        log.info("match request: caller={} typeHint='{}' input='{}' onSnapshotV{}",
                caller == null ? "<anonymous>" : caller.id() + "(" + caller.role() + ")",
                typeHint, input, read.version());
        return matchEngine.match(read, typeHint, input);
    }

    /** 解析目标代际：null 或当前版本 -> 当前生效代；否则查历史，缺失抛可区分异常。 */
    private ThreatSnapshot resolveGeneration(Long generation) {
        GenerationRegistry reg = this.registry; // 一次读取，视图一致
        ThreatSnapshot current = reg.current();
        if (generation == null || generation == current.version()) {
            return current;
        }
        for (ThreatSnapshot past : reg.history()) {
            if (past.version() == generation) {
                return past;
            }
        }
        String reason = generation <= reg.maxEvictedVersion() && generation > 0
                ? "GENERATION_EVICTED" : "GENERATION_NOT_FOUND";
        throw new GenerationNotFoundException(generation, reason,
                "generation v" + generation + " is not available (" + reason
                        + "); current=v" + current.version());
    }

    /**
     * 把当前生效结果回滚到某个历史代际。
     *
     * <p>并发语义：与刷新共用同一把 {@link ReentrantLock}，回滚期间到达的刷新/回滚
     * 立即得到 {@code ALREADY_RUNNING}；查询不取锁，要么看到回滚前的完整代，
     * 要么看到回滚后的完整代，绝不出现半新半旧。被替换的当前代会重新进入历史
     * （受容量约束），因此回滚本身也是一次可追溯的代际切换。
     * 已被容量淘汰的代际返回 {@code GENERATION_EVICTED}，不可回滚。
     */
    public RollbackOutcome rollback(long generation) {
        if (!refreshLock.tryLock()) {
            return new RollbackOutcome("ALREADY_RUNNING", registry.current().version(),
                    "another refresh/rollback is in progress; current generation retained");
        }
        try {
            GenerationRegistry reg = this.registry;
            ThreatSnapshot current = reg.current();
            if (generation == current.version()) {
                return new RollbackOutcome("ALREADY_CURRENT", current.version(),
                        "generation v" + generation + " is already the active one");
            }
            ThreatSnapshot target = null;
            for (ThreatSnapshot past : reg.history()) {
                if (past.version() == generation) {
                    target = past;
                    break;
                }
            }
            if (target == null) {
                String reason = generation <= reg.maxEvictedVersion() && generation > 0
                        ? "GENERATION_EVICTED" : "GENERATION_NOT_FOUND";
                log.warn("rollback to v{} rejected: {} (current=v{}, maxEvicted=v{})",
                        generation, reason, current.version(), reg.maxEvictedVersion());
                return new RollbackOutcome(reason, current.version(),
                        "generation v" + generation + " is not available (" + reason
                                + "); current v" + current.version() + " retained");
            }
            // 原子切换：目标代成为当前生效代，被替换的当前代重新进入历史（受容量约束）
            List<ThreatSnapshot> hist = new ArrayList<>(reg.history());
            hist.remove(target);
            if (current.version() > 0L) {
                hist.add(current);
            }
            long maxEvicted = evictOverflow(hist, reg.maxEvictedVersion());
            this.registry = new GenerationRegistry(target, List.copyOf(hist), maxEvicted);
            log.info("rolled back: active generation v{} -> v{} (history size={})",
                    current.version(), target.version(), hist.size());
            return new RollbackOutcome("ROLLED_BACK", target.version(),
                    "active generation rolled back from v" + current.version()
                            + " to v" + target.version());
        } finally {
            refreshLock.unlock();
        }
    }

    /** 当前可见代际列表（当前生效代 + 保留的历史代，按版本升序）。 */
    public List<ThreatSnapshot> generations() {
        GenerationRegistry reg = this.registry;
        List<ThreatSnapshot> all = new ArrayList<>(reg.history());
        all.add(reg.current());
        all.sort(Comparator.comparingLong(ThreatSnapshot::version));
        return List.copyOf(all);
    }

    /**
     * 受限来源明细查询：按 key 查指标，权限不足抛 {@link AccessDeniedException}。
     * 若指标来源于多个来源且其中任一受限，无权调用方整体被拒绝（不泄露部分明细）。
     */
    public List<Indicator> lookupIndicatorsByKey(String indicatorKey, Caller caller) {
        ThreatSnapshot read = registry.current();
        List<Indicator> found = read.indicators().stream()
                .filter(i -> i.key().equals(indicatorKey))
                .toList();
        if (found.isEmpty()) {
            return List.of();
        }
        for (Indicator indicator : found) {
            for (String source : indicator.sources()) {
                accessControl.checkIndicatorDetail(caller, source);
            }
        }
        return found;
    }

    /** 把命中的 key 列表按调用方权限过滤（仅用于响应脱敏，不影响判定）。 */
    public List<String> visibleKeys(List<String> keys, Caller caller) {
        List<String> visible = new ArrayList<>();
        for (String key : keys) {
            List<Indicator> found = currentSnapshot().indicators().stream()
                    .filter(i -> i.key().equals(key)).toList();
            boolean allowed = true;
            for (Indicator ind : found) {
                for (String source : ind.sources()) {
                    if (accessControl.isRestricted(source)
                            && (caller == null || caller.role().name().equals("RESTRICTED_VIEWER"))) {
                        allowed = false;
                    }
                }
            }
            visible.add(allowed ? key : "REDACTED[restricted source]");
        }
        return List.copyOf(visible);
    }

    private ThreatSnapshot buildSnapshot(long previousVersion, String contentHash,
                                         Map<String, Indicator> merged,
                                         List<SuppressionRule> suppressions) {
        return buildSnapshot(previousVersion, contentHash, merged, suppressions, List.of());
    }

    private ThreatSnapshot buildSnapshot(long previousVersion, String contentHash,
                                         Map<String, Indicator> merged,
                                         List<SuppressionRule> suppressions,
                                         List<com.github.xingjianluo.threatinteliocjava.model.SourceHealth> sourceHealth) {
        List<Indicator> indicators = merged.values().stream()
                .sorted(Comparator.comparing(Indicator::key))
                .toList();
        Map<String, Integer> sourceCounts = new TreeMap<>();
        for (Indicator ind : indicators) {
            for (String source : ind.sources()) {
                sourceCounts.merge(source, 1, Integer::sum);
            }
        }
        return new ThreatSnapshot(previousVersion + 1, System.currentTimeMillis(),
                contentHash, indicators, suppressions, Map.copyOf(sourceCounts),
                List.copyOf(sourceHealth));
    }

    private ImportReport zeroReport() {
        return new ImportReport(0, 0, 0, 0, List.of());
    }

    private String truncate(String s) {
        return s == null ? "" : (s.length() > 200 ? s.substring(0, 200) + "..." : s);
    }
}
