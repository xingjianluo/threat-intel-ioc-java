package com.github.xingjianluo.threatinteliocjava.service;

import com.github.xingjianluo.threatinteliocjava.model.IocIndicator;
import com.github.xingjianluo.threatinteliocjava.model.SuppressionRule;
import com.github.xingjianluo.threatinteliocjava.normalize.Cidr;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 不可变情报快照：一次完整刷新的全部结果。匹配查询只面对快照，
 * 因而任何查询要么看到旧快照、要么看到新快照，绝不可能看到部分加载的数据。
 *
 * <p>索引：
 * <ul>
 *   <li>exactIndex：IP/DOMAIN/URL/HASH 与 CIDR 规范键的精确查找；</li>
 *   <li>cidrs：网段列表，包含匹配时取前缀最长（最具体）者；</li>
 *   <li>domains：域名指标列表，域/子域匹配时取最长（最具体）者。</li>
 * </ul>
 */
public final class IntelSnapshot {

    private final Map<String, IocIndicator> exactIndex;
    private final List<CidrEntry> cidrs;
    private final List<IocIndicator> domains;
    private final List<SuppressionRule> suppressions;
    private final Instant builtAt;
    private final String contentHash;

    public IntelSnapshot(Map<String, IocIndicator> exactIndex,
                         List<CidrEntry> cidrs,
                         List<IocIndicator> domains,
                         List<SuppressionRule> suppressions,
                         Instant builtAt,
                         String contentHash) {
        this.exactIndex = Map.copyOf(exactIndex);
        this.cidrs = List.copyOf(cidrs);
        this.domains = List.copyOf(domains);
        this.suppressions = List.copyOf(suppressions);
        this.builtAt = builtAt;
        this.contentHash = contentHash;
    }

    public Instant getBuiltAt() {
        return builtAt;
    }

    public String getContentHash() {
        return contentHash;
    }

    public int indicatorCount() {
        return exactIndex.size();
    }

    public int suppressionCount() {
        return suppressions.size();
    }

    public List<IocIndicator> allIndicators() {
        return exactIndex.values().stream()
                .sorted(Comparator.comparing(IocIndicator::canonicalValue)).toList();
    }

    /** 精确键（IP/DOMAIN/URL/HASH/CIDR 规范值）查找。 */
    public Optional<IocIndicator> findExact(String key) {
        return Optional.ofNullable(exactIndex.get(key));
    }

    /** 网段包含查找，返回前缀最长（最具体）的命中。 */
    public Optional<CidrEntry> findContainingCidr(String ip) {
        CidrEntry best = null;
        for (CidrEntry entry : cidrs) {
            if (entry.cidr().contains(ip)
                    && (best == null || entry.cidr().prefixLength() > best.cidr().prefixLength())) {
                best = entry;
            }
        }
        return Optional.ofNullable(best);
    }

    /** 域名查找：指标域是查询域本身或其父域（查询域是指标域或其子域），取最长命中。 */
    public Optional<IocIndicator> findDomain(String canonicalDomain) {
        IocIndicator best = null;
        for (IocIndicator ind : domains) {
            String d = ind.canonicalValue();
            boolean match = canonicalDomain.equals(d) || canonicalDomain.endsWith("." + d);
            if (match && (best == null || d.length() > best.canonicalValue().length())) {
                best = ind;
            }
        }
        return Optional.ofNullable(best);
    }

    public List<SuppressionRule> allSuppressions() {
        return suppressions;
    }

    /** 网段索引条目。 */
    public record CidrEntry(Cidr cidr, IocIndicator indicator) {
    }
}
