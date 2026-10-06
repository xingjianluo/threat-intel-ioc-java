package com.github.xingjianluo.threatinteliocjava.refresh;

import com.github.xingjianluo.threatinteliocjava.access.AccessControlService;
import com.github.xingjianluo.threatinteliocjava.access.AccessDeniedException;
import com.github.xingjianluo.threatinteliocjava.access.Caller;
import com.github.xingjianluo.threatinteliocjava.ingest.ImportReport;
import com.github.xingjianluo.threatinteliocjava.ingest.RawEntry;
import com.github.xingjianluo.threatinteliocjava.model.ConflictNote;
import com.github.xingjianluo.threatinteliocjava.model.Generation;
import com.github.xingjianluo.threatinteliocjava.model.Indicator;
import com.github.xingjianluo.threatinteliocjava.model.IndicatorType;
import com.github.xingjianluo.threatinteliocjava.model.RejectedEntry;
import com.github.xingjianluo.threatinteliocjava.model.RejectionCode;
import com.github.xingjianluo.threatinteliocjava.model.Severity;
import com.github.xingjianluo.threatinteliocjava.model.SourceDisposition;
import com.github.xingjianluo.threatinteliocjava.model.SourceHealth;
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
 *   <li>每次刷新成功（APPLIED / APPLIED_PARTIAL）形成一代可追溯结果，
 *       记录每个来源是正常采用、合法为空还是读取失败；读取失败绝不会被
 *       当成合法空情报。历史代际保存在容量有界的 {@link GenerationHistory} 中，
 *       支持按代查询与原子回滚，并发查询只会看到完整的一代。</li>
 * </ul>
 */
@Service
public class ThreatIntelService {

    private static final Logger log = LoggerFactory.getLogger(ThreatIntelService.class);

    private final LocalFeedRepository repository;
    private final Normalizer normalizer;
    private final MatchEngine matchEngine;
    private final AccessControlService accessControl;
    private final GenerationHistory history;

    private final ReentrantLock refreshLock = new ReentrantLock();
    private volatile RefreshOutcome lastRefreshOutcome;

    public ThreatIntelService(LocalFeedRepository repository,
                              Normalizer normalizer,
                              MatchEngine matchEngine,
                              AccessControlService accessControl) {
        this(repository, normalizer, matchEngine, accessControl, new GenerationHistory(5));
    }

    @org.springframework.beans.factory.annotation.Autowired
    public ThreatIntelService(LocalFeedRepository repository,
                              Normalizer normalizer,
                              MatchEngine matchEngine,
                              AccessControlService accessControl,
                              GenerationHistory history) {
        this.repository = repository;
        this.normalizer = normalizer;
        this.matchEngine = matchEngine;
        this.accessControl = accessControl;
        this.history = history;
    }

    /** 当前生效快照（当前代的快照；从未发布过代际时为空快照）。 */
    public ThreatSnapshot currentSnapshot() {
        Generation current = history.current();
        return current == null ? ThreatSnapshot.empty() : current.snapshot();
    }

    /** 当前生效代际；从未发布过时为 null。 */
    public Generation currentGeneration() {
        return history.current();
    }

    /** 保留期内的全部代际（新的在前）。 */
    public List<Generation> generations() {
        return history.list();
    }

    /** 最近一次刷新的确定结论（含未成功的结论）；从未刷新过时为 null。 */
    public RefreshOutcome lastRefresh() {
        return lastRefreshOutcome;
    }

    /** 代际历史保留容量。 */
    public int generationHistoryCapacity() {
        return history.capacity();
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
        RefreshOutcome outcome;
        if (!refreshLock.tryLock()) {
            outcome = alreadyRunning();
        } else {
            try {
                outcome = doRefresh(directory, suppressionFile, configuredRestrictedSources, policy);
            } finally {
                refreshLock.unlock();
            }
        }
        // 无论成功与否都留下可追溯的最近结论，未成功不会被误当成合法空情报
        this.lastRefreshOutcome = outcome;
        return outcome;
    }

    private RefreshOutcome alreadyRunning() {
        log.warn("refresh skipped: another refresh is already running (snapshot v{} retained)",
                currentSnapshot().version());
        return new RefreshOutcome("ALREADY_RUNNING", currentSnapshot().version(),
                zeroReport(), List.of(),
                "refresh already in progress; existing snapshot retained");
    }

    private RefreshOutcome doRefresh(String directory,
                                     String suppressionFile,
                                     Set<String> configuredRestrictedSources,
                                     RefreshPolicy policy) {
        ThreatSnapshot previous = currentSnapshot();
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
                    List.copyOf(rejected), why);
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
        // 版本基数取当前快照与历史最高代际的较大者：回滚后再刷新也不会复用旧编号
        long versionBase = Math.max(previous.version(), history.highestVersion());
        ThreatSnapshot newSnapshot = buildSnapshot(versionBase, hash, merged, suppressions);
        // 6b) 形成一代可追溯结果：记录每个来源的采用状态，并原子切换为当前代
        List<SourceDisposition> dispositions = sourceDispositions(loaded);
        Generation generation = history.publish(newSnapshot, dispositions);
        accessControl.updateRestrictedSources(configuredRestrictedSources);
        log.info("refresh applied: generation={} complete={} indicators={} suppressions={} rejected={} in {}ms",
                generation.id(), generation.complete(), newSnapshot.indicators().size(),
                suppressions.size(), rejected.size(), System.currentTimeMillis() - start);
        return new RefreshOutcome(hasFailure ? "APPLIED_PARTIAL" : "APPLIED",
                newSnapshot.version(), report, List.copyOf(rejected),
                hasFailure ? "applied with " + rejected.size() + " rejected items recorded"
                        : "refresh applied cleanly");
    }

    private List<SuppressionRule> loadSuppressions(String file, List<RejectedEntry> failures) {
        String content;
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

    /**
     * 计算一次成功装载中每个来源的处置：
     * 正常读取且有内容 -> ADOPTED；正常读取但 0 条目 0 坏行 -> SKIPPED_EMPTY（合法空）；
     * 文件级读取/解析失败 -> SKIPPED_UNREADABLE（绝不能当成合法空情报）。
     */
    private List<SourceDisposition> sourceDispositions(LocalFeedRepository.LoadedDirectory loaded) {
        List<SourceDisposition> dispositions = new ArrayList<>();
        for (LocalFeedRepository.FeedBatch batch : loaded.batches()) {
            int entries = batch.batch().entries().size();
            int badLines = batch.batch().rejected().size();
            if (entries == 0 && badLines == 0) {
                dispositions.add(new SourceDisposition(batch.source(),
                        SourceHealth.SKIPPED_EMPTY,
                        "source read successfully but is legitimately empty (0 entries)"));
            } else {
                dispositions.add(new SourceDisposition(batch.source(), SourceHealth.ADOPTED,
                        entries + " entries adopted"
                                + (badLines > 0 ? ", " + badLines + " bad line(s) rejected" : "")));
            }
        }
        for (RejectedEntry failure : loaded.fileFailures()) {
            dispositions.add(new SourceDisposition(failure.source(),
                    SourceHealth.SKIPPED_UNREADABLE,
                    failure.code() + ": " + failure.detail()));
        }
        dispositions.sort(Comparator.comparing(SourceDisposition::source));
        return List.copyOf(dispositions);
    }

    /**
     * 回滚当前生效结果到保留期内的某一代。
     * 原子切换：并发查询只会看到完整的一代；已被淘汰的代际抛
     * {@link GenerationNotFoundException}，不能被当成可用结果回滚。
     */
    public Generation rollback(long generationId) {
        Generation target = history.rollback(generationId);
        log.info("rolled back to generation {} (snapshot v{}, complete={})",
                target.id(), target.snapshot().version(), target.complete());
        return target;
    }

    /** 匹配查询（最新一代）：始终基于某一份完整快照，访问控制不影响命中结论。 */
    public Verdict match(String typeHint, String input, Caller caller) {
        return match(typeHint, input, caller, null);
    }

    /**
     * 匹配查询：默认看最新一代；指定 {@code generationId} 时看该代历史结果。
     * 指定代际不在保留期内时抛 {@link GenerationNotFoundException}。
     */
    public Verdict match(String typeHint, String input, Caller caller, Long generationId) {
        ThreatSnapshot read;
        if (generationId == null) {
            read = currentSnapshot();
        } else {
            read = history.find(generationId)
                    .orElseThrow(() -> new GenerationNotFoundException(generationId,
                            "generation " + generationId
                                    + " is not retained (evicted or never existed)"))
                    .snapshot();
        }
        log.info("match request: caller={} typeHint='{}' input='{}' onSnapshotV{}",
                caller == null ? "<anonymous>" : caller.id() + "(" + caller.role() + ")",
                typeHint, input, read.version());
        return matchEngine.match(read, typeHint, input);
    }

    /**
     * 受限来源明细查询：按 key 查指标，权限不足抛 {@link AccessDeniedException}。
     * 若指标来源于多个来源且其中任一受限，无权调用方整体被拒绝（不泄露部分明细）。
     */
    public List<Indicator> lookupIndicatorsByKey(String indicatorKey, Caller caller) {
        ThreatSnapshot read = currentSnapshot();
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

    private ThreatSnapshot buildSnapshot(long versionBase, String contentHash,
                                         Map<String, Indicator> merged,
                                         List<SuppressionRule> suppressions) {
        List<Indicator> indicators = merged.values().stream()
                .sorted(Comparator.comparing(Indicator::key))
                .toList();
        Map<String, Integer> sourceCounts = new TreeMap<>();
        for (Indicator ind : indicators) {
            for (String source : ind.sources()) {
                sourceCounts.merge(source, 1, Integer::sum);
            }
        }
        return new ThreatSnapshot(versionBase + 1, System.currentTimeMillis(),
                contentHash, indicators, suppressions, Map.copyOf(sourceCounts));
    }

    private ImportReport zeroReport() {
        return new ImportReport(0, 0, 0, 0, List.of());
    }

    private String truncate(String s) {
        return s == null ? "" : (s.length() > 200 ? s.substring(0, 200) + "..." : s);
    }
}
