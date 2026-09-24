package com.github.xingjianluo.threatinteliocjava.service;

import com.github.xingjianluo.threatinteliocjava.config.IntelProperties;
import com.github.xingjianluo.threatinteliocjava.ingest.IntelFileLoader;
import com.github.xingjianluo.threatinteliocjava.ingest.ParseResult;
import com.github.xingjianluo.threatinteliocjava.ingest.RawIndicator;
import com.github.xingjianluo.threatinteliocjava.ingest.RawSuppression;
import com.github.xingjianluo.threatinteliocjava.model.ConflictRecord;
import com.github.xingjianluo.threatinteliocjava.model.ImportRejection;
import com.github.xingjianluo.threatinteliocjava.model.IndicatorType;
import com.github.xingjianluo.threatinteliocjava.model.IocIndicator;
import com.github.xingjianluo.threatinteliocjava.model.RefreshReport;
import com.github.xingjianluo.threatinteliocjava.model.RejectionReason;
import com.github.xingjianluo.threatinteliocjava.model.Severity;
import com.github.xingjianluo.threatinteliocjava.model.SuppressionRule;
import com.github.xingjianluo.threatinteliocjava.normalize.NormalizationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

/**
 * 情报刷新服务。
 *
 * <p>一致性保证：
 * <ul>
 *   <li>刷新与刷新之间用 {@link ReentrantLock} 串行，并发刷新只会有一个在执行，
 *       其余等待并复用刚完成的结果，不会造成重复计数或状态损坏；</li>
 *   <li>匹配查询完全无锁，只读 {@link IntelRegistry} 中的不可变快照，
 *       任一查询要么看到完整旧快照，要么看到完整新快照，绝不会看到部分加载的数据；</li>
 *   <li>全部解析/归一/收敛都在临时结构中完成，只有整体成功才原子发布；
 *       文件级致命错误或异常时保留原快照不动并给出 FAILED 结论；</li>
 *   <li>条目级畸形/不支持/冲突不阻断发布，状态为 PARTIAL，拒绝与冲突明细可区分；</li>
 *   <li>内容相同的重复刷新得到相同内容哈希，状态标记 UNCHANGED 且不重新发布，
 *       计数不漂移。</li>
 * </ul>
 */
@Service
public class RefreshService {

    private static final Logger log = LoggerFactory.getLogger(RefreshService.class);

    /** 置信度缺失时的确定默认值。 */
    static final int DEFAULT_CONFIDENCE = 50;

    private final IntelFileLoader loader;
    private final IntelRegistry registry;
    private final IntelProperties properties;
    private final AccessControlService accessControl;
    private final ReentrantLock refreshLock = new ReentrantLock();
    private final AtomicReference<RefreshReport> lastReport = new AtomicReference<>();

    public RefreshService(IntelFileLoader loader, IntelRegistry registry,
                          IntelProperties properties, AccessControlService accessControl) {
        this.loader = loader;
        this.registry = registry;
        this.properties = properties;
        this.accessControl = accessControl;
    }

    public RefreshReport refresh() {
        refreshLock.lock();
        try {
            return doRefresh();
        } finally {
            refreshLock.unlock();
        }
    }

    public RefreshReport lastReport() {
        return lastReport.get();
    }

    private RefreshReport doRefresh() {
        log.info("情报刷新开始: directory={}", properties.directory());
        List<ParseResult> parsed;
        try {
            parsed = loader.loadDirectory(properties.directory());
        } catch (Exception e) {
            RefreshReport failed = failedReport("扫描/读取情报目录失败: " + e.getMessage());
            log.error("情报刷新整体失败，保留旧快照: {}", e.getMessage());
            lastReport.set(failed);
            return failed;
        }

        int filesScanned = parsed.size();
        List<ImportRejection> rejections = new ArrayList<>();
        List<ConflictRecord> conflicts = new ArrayList<>();
        for (ParseResult r : parsed) {
            if (r.fatal()) {
                RefreshReport failed = failedReport(
                        "文件级解析错误: " + r.sourceFile() + " - " + r.fatalError());
                log.error("情报刷新整体失败（{}），保留旧快照", r.sourceFile());
                lastReport.set(failed);
                return failed;
            }
            rejections.addAll(r.rejections());
        }

        // 键 = 类型|规范值，保序累积
        Map<String, MergeState> merged = new LinkedHashMap<>();
        int acceptedEntries = 0;
        int duplicateMerged = 0;

        for (ParseResult r : parsed) {
            for (RawIndicator raw : r.indicators()) {
                String rawContent = raw.value();
                IndicatorType type = IndicatorType.fromCode(raw.rawType());
                if (type == null) {
                    rejections.add(new ImportRejection(raw.sourceFile(), raw.line(), rawContent,
                            RejectionReason.UNSUPPORTED_INDICATOR_TYPE,
                            "不支持的指标类型代码: " + raw.rawType()));
                    continue;
                }
                String canonical;
                try {
                    canonical = loader.getNormalizer().normalize(type, raw.value());
                } catch (NormalizationException e) {
                    rejections.add(new ImportRejection(raw.sourceFile(), raw.line(), rawContent,
                            RejectionReason.MALFORMED_VALUE,
                            "指标值归一失败（" + type + "）: " + e.getMessage()));
                    continue;
                }
                Integer confidence = parseConfidence(raw.confidence(), raw, rejections);
                if (confidence == null) {
                    continue;
                }
                acceptedEntries++;
                Severity severity = Severity.fromCode(raw.severity());
                IocIndicator candidate = new IocIndicator(type, canonical, raw.value().trim(),
                        severity, confidence,
                        raw.description() == null ? null : raw.description().trim(),
                        new ArrayList<>(List.of(raw.sourceFile())),
                        java.util.Set.of());
                String key = type.name() + "|" + canonical;
                MergeState existing = merged.get(key);
                if (existing == null) {
                    merged.put(key, new MergeState(candidate));
                } else {
                    MergeOutcome outcome = existing.merge(candidate);
                    if (outcome.isDuplicate()) {
                        duplicateMerged++;
                        log.info("重复指标收敛(完全相同): {} <- {}", key, raw.sourceFile());
                    } else {
                        conflicts.add(outcome.record);
                        log.info("冲突指标按规则收敛: key={} 规则={} 选中={} 忽略={}",
                                key, outcome.record().resolutionRule(),
                                outcome.record().chosenDescriptor(),
                                outcome.record().ignoredDescriptor());
                    }
                }
            }
        }

        // 抑制规则：归一 + 去重/冲突拒绝
        Map<String, SuppressionRule> suppressionById = new LinkedHashMap<>();
        for (ParseResult r : parsed) {
            for (RawSuppression raw : r.suppressions()) {
                IndicatorType type = IndicatorType.fromCode(raw.rawType());
                if (type == null) {
                    rejections.add(new ImportRejection(raw.sourceFile(), raw.line(),
                            raw.value(), RejectionReason.MALFORMED_SUPPRESSION_RULE,
                            "抑制规则类型不支持: " + raw.rawType()));
                    continue;
                }
                String canonical;
                try {
                    canonical = loader.getNormalizer().normalize(type, raw.value());
                } catch (NormalizationException e) {
                    rejections.add(new ImportRejection(raw.sourceFile(), raw.line(),
                            raw.value(), RejectionReason.MALFORMED_SUPPRESSION_RULE,
                            "抑制规则值归一失败: " + e.getMessage()));
                    continue;
                }
                SuppressionRule rule = new SuppressionRule(raw.id(), type, canonical,
                        raw.value().trim(), raw.reason(), raw.sourceFile());
                SuppressionRule prev = suppressionById.get(raw.id());
                if (prev != null) {
                    if (prev.type() == rule.type() && prev.canonicalValue().equals(rule.canonicalValue())) {
                        log.info("重复抑制规则去重: id={}", raw.id());
                        continue;
                    }
                    rejections.add(new ImportRejection(raw.sourceFile(), raw.line(),
                            raw.value(), RejectionReason.MALFORMED_SUPPRESSION_RULE,
                            "抑制规则 ID 冲突: '" + raw.id() + "' 已定义为 "
                                    + prev.type() + "/" + prev.canonicalValue()
                                    + "，本条为 " + type + "/" + canonical));
                    continue;
                }
                suppressionById.put(raw.id(), rule);
            }
        }

        // 组装不可变指标列表（填充访问角色）
        List<IocIndicator> finalIndicators = merged.values().stream()
                .map(s -> s.withRoles(accessControl))
                .toList();

        String hash = contentHash(finalIndicators, List.copyOf(suppressionById.values()),
                rejections);
        IntelSnapshot current = registry.currentSnapshot().orElse(null);
        if (current != null && hash.equals(current.getContentHash())) {
            RefreshReport unchanged = unchangedReport(current, filesScanned, acceptedEntries,
                    duplicateMerged, conflicts.size(), rejections.size());
            lastReport.set(unchanged);
            log.info("情报内容未变化(hash={})，保持当前快照不重新发布", hash);
            return unchanged;
        }

        Map<String, IocIndicator> exactIndex = new LinkedHashMap<>();
        List<IntelSnapshot.CidrEntry> cidrs = new ArrayList<>();
        List<IocIndicator> domains = new ArrayList<>();
        for (IocIndicator ind : finalIndicators) {
            String key = ind.type().name() + "|" + ind.canonicalValue();
            exactIndex.put(key, ind);
            if (ind.type() == IndicatorType.CIDR) {
                String[] parts = ind.canonicalValue().split("/", 2);
                cidrs.add(new IntelSnapshot.CidrEntry(
                        loader.getNormalizer().cidr(ind.canonicalValue()), ind));
            } else if (ind.type() == IndicatorType.DOMAIN) {
                domains.add(ind);
            }
        }
        List<SuppressionRule> suppressionRules = List.copyOf(suppressionById.values());
        IntelSnapshot snapshot = new IntelSnapshot(exactIndex, cidrs, domains, suppressionRules,
                Instant.now(), hash);
        registry.publish(snapshot);

        boolean partial = !rejections.isEmpty() || !conflicts.isEmpty();
        RefreshReport report = new RefreshReport(true, partial ? "PARTIAL" : "OK",
                snapshot.getBuiltAt(), hash, filesScanned, acceptedEntries, duplicateMerged,
                conflicts.size(), snapshot.indicatorCount(), snapshot.suppressionCount(),
                List.copyOf(rejections), List.copyOf(conflicts),
                partial ? "存在被拒绝条目或冲突收敛，详见 rejections/conflicts" : null);
        lastReport.set(report);
        log.info("情报刷新完成: status={} 文件={} 接受={} 重复合并={} 冲突收敛={} 唯一指标={} 抑制={} 拒绝={}",
                report.status(), filesScanned, acceptedEntries, duplicateMerged,
                conflicts.size(), snapshot.indicatorCount(), suppressionRules.size(),
                rejections.size());
        for (ImportRejection rej : rejections) {
            log.warn("拒绝条目: file={} line={} reason={} detail={} input={}",
                    rej.sourceFile(), rej.line(), rej.reason(), rej.detail(), rej.rawContent());
        }
        return report;
    }

    private Integer parseConfidence(String raw, RawIndicator source,
                                    List<ImportRejection> rejections) {
        if (raw == null || raw.isBlank()) {
            return DEFAULT_CONFIDENCE;
        }
        int v;
        try {
            v = Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            rejections.add(new ImportRejection(source.sourceFile(), source.line(),
                    source.value(), RejectionReason.MALFORMED_VALUE,
                    "confidence 不是整数: " + raw));
            return null;
        }
        if (v < 0 || v > 100) {
            rejections.add(new ImportRejection(source.sourceFile(), source.line(),
                    source.value(), RejectionReason.MALFORMED_VALUE,
                    "confidence 超出 0-100: " + raw));
            return null;
        }
        return v;
    }

    private RefreshReport failedReport(String reason) {
        IntelSnapshot cur = registry.currentSnapshot().orElse(null);
        return new RefreshReport(false, "FAILED", Instant.now(),
                cur == null ? null : cur.getContentHash(), 0, 0, 0, 0,
                cur == null ? 0 : cur.indicatorCount(),
                cur == null ? 0 : cur.suppressionCount(),
                List.of(), List.of(), reason);
    }

    private RefreshReport unchangedReport(IntelSnapshot cur, int files, int accepted,
                                          int duplicates, int conflictsCount, int rejected) {
        return new RefreshReport(true, "UNCHANGED", cur.getBuiltAt(), cur.getContentHash(),
                files, accepted, duplicates, conflictsCount, cur.indicatorCount(),
                cur.suppressionCount(), List.of(), List.of(),
                "内容哈希与当前快照一致，状态未变化（本次扫描拒绝条目数=" + rejected + "）");
    }

    /**
     * 对“归一后的指标 + 抑制规则 + 拒绝明细”的规范渲染取 SHA-256，
     * 任何输入内容变化都会改变哈希；渲染按键排序，保证可复现。
     */
    private String contentHash(List<IocIndicator> indicators, List<SuppressionRule> suppressions,
                               List<ImportRejection> rejections) {
        Map<String, String> lines = new TreeMap<>();
        for (IocIndicator ind : indicators) {
            lines.put("I|" + ind.type() + "|" + ind.canonicalValue(),
                    ind.severity() + "|" + ind.confidence() + "|"
                            + nullToEmpty(ind.description()) + "|" + String.join(",", ind.sources()));
        }
        for (SuppressionRule s : suppressions) {
            lines.put("S|" + s.id(),
                    s.type() + "|" + s.canonicalValue() + "|" + nullToEmpty(s.reason()));
        }
        int[] idx = {0};
        rejections.stream()
                .sorted(Comparator.comparing(ImportRejection::sourceFile)
                        .thenComparing(r -> r.line() == null ? Integer.MAX_VALUE : r.line())
                        .thenComparing(r -> r.reason().name()))
                .forEach(r -> lines.put("R|" + (idx[0]++),
                        r.sourceFile() + "|" + r.line() + "|" + r.reason() + "|"
                                + nullToEmpty(r.detail()) + "|" + nullToEmpty(r.rawContent())));
        String rendered = lines.entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue())
                .collect(Collectors.joining("\n"));
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(rendered.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    /** 同键指标的收敛状态。 */
    private static final class MergeState {
        private IocIndicator winner;

        private MergeState(IocIndicator first) {
            this.winner = first;
        }

        /**
         * 定义完全相同（severity/confidence/description 一致）→ 重复合并；
         * 否则按“置信度高者胜 → 严重级别高者胜 → 来源文件名 → 行号”的确定规则收敛。
         */
        private MergeOutcome merge(IocIndicator incoming) {
            boolean sameDefinition = winner.severity() == incoming.severity()
                    && winner.confidence() == incoming.confidence()
                    && eqDesc(winner.description(), incoming.description());
            if (sameDefinition) {
                mergeSources(incoming);
                return MergeOutcome.duplicate();
            }
            IocIndicator chosen = winner;
            IocIndicator ignored = incoming;
            int cmp = Comparator.comparingInt(IocIndicator::confidence).reversed()
                    .thenComparing((IocIndicator a) -> a.severity().ordinal(),
                            Comparator.reverseOrder())
                    .thenComparing(a -> a.sources().get(0))
                    .thenComparing(IocIndicator::displayValue)
                    .compare(incoming, winner);
            String rule;
            if (incoming.confidence() != winner.confidence()) {
                rule = "冲突收敛: 取置信度更高者";
            } else if (incoming.severity() != winner.severity()) {
                rule = "冲突收敛: 置信度相同取严重级别更高者";
            } else {
                rule = "冲突收敛: 置信度/级别相同，按来源文件名再按原始写法字典序";
            }
            if (cmp < 0) {
                chosen = incoming;
                ignored = winner;
            }
            List<String> mergedSources = new ArrayList<>(winner.sources());
            for (String s : incoming.sources()) {
                if (!mergedSources.contains(s)) {
                    mergedSources.add(s);
                }
            }
            winner = new IocIndicator(chosen.type(), chosen.canonicalValue(),
                    chosen.displayValue(), chosen.severity(), chosen.confidence(),
                    chosen.description(), mergedSources, java.util.Set.of());
            return MergeOutcome.conflict(new ConflictRecord(chosen.type(),
                    chosen.canonicalValue(), rule,
                    descriptor(chosen), descriptor(ignored)));
        }

        private void mergeSources(IocIndicator incoming) {
            List<String> sources = new ArrayList<>(winner.sources());
            for (String s : incoming.sources()) {
                if (!sources.contains(s)) {
                    sources.add(s);
                }
            }
            String description = winner.description() != null
                    ? winner.description() : incoming.description();
            winner = new IocIndicator(winner.type(), winner.canonicalValue(),
                    winner.displayValue(), winner.severity(), winner.confidence(),
                    description, sources, java.util.Set.of());
        }

        private IocIndicator withRoles(AccessControlService access) {
            return new IocIndicator(winner.type(), winner.canonicalValue(),
                    winner.displayValue(), winner.severity(), winner.confidence(),
                    winner.description(), List.copyOf(winner.sources()),
                    java.util.Set.copyOf(access.requiredRolesFor(winner)));
        }

        private static boolean eqDesc(String a, String b) {
            if (a == null || a.isBlank()) {
                return b == null || b.isBlank();
            }
            return a.equals(b);
        }

        private static String descriptor(IocIndicator i) {
            return i.sources().get(0) + "|" + i.displayValue() + "|"
                    + i.severity() + "|confidence=" + i.confidence();
        }
    }

    /** 合并结论：duplicate 表示定义完全相同的重复；record 为冲突收敛明细。 */
    public record MergeOutcome(boolean isDuplicate, ConflictRecord record) {
        static MergeOutcome duplicate() {
            return new MergeOutcome(true, null);
        }

        static MergeOutcome conflict(ConflictRecord record) {
            return new MergeOutcome(false, record);
        }
    }
}
