package com.github.xingjianluo.threatinteliocjava.match;

import com.github.xingjianluo.threatinteliocjava.model.Indicator;
import com.github.xingjianluo.threatinteliocjava.model.IndicatorType;
import com.github.xingjianluo.threatinteliocjava.model.SuppressionRule;
import com.github.xingjianluo.threatinteliocjava.model.ThreatSnapshot;
import com.github.xingjianluo.threatinteliocjava.model.Verdict;
import com.github.xingjianluo.threatinteliocjava.normalize.Normalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 无状态匹配引擎：对给定不可变快照执行等价匹配，抑制/白名单规则优先于命中。
 *
 * <p>等价规则：
 * <ul>
 *   <li>IPV4：精确相等；指标为 CIDR 网段时包含即命中（各种混淆写法先归一）。</li>
 *   <li>DOMAIN：精确相等或查询域是指标域的子域（大小写/根点/通配前缀先归一）。</li>
 *   <li>URL：精确 URL；并与 DOMAIN/IPV4 指标按主机交叉匹配。</li>
 *   <li>HASH/EMAIL：规范值精确相等（大小写不敏感经归一体现在规范值）。</li>
 * </ul>
 * 抑制规则（可声明为域名或 CIDR）命中同一等价集合时，结论为 SUPPRESSED，
 * 并在 reasons 中给出规则 id 与原因。
 */
@Component
public class MatchEngine {

    private static final Logger log = LoggerFactory.getLogger(MatchEngine.class);

    private final Normalizer normalizer;
    private final Map<Long, SnapshotIndex> indexCache = new ConcurrentHashMap<>();

    public MatchEngine(Normalizer normalizer) {
        this.normalizer = normalizer;
    }

    /**
     * 对一份不可变快照执行匹配。
     *
     * @param snapshot 完整快照（永不部分加载）
     * @param typeHint 调用方声明类型，可空；为空时按值确定性推断
     * @param input    原始查询值
     */
    public Verdict match(ThreatSnapshot snapshot, String typeHint, String input) {
        IndicatorType type = (typeHint == null || typeHint.isBlank())
                ? normalizer.inferType(input)
                : normalizer.normalizeType(typeHint);
        String normalized = normalizer.normalizeValue(type, input);
        List<String> reasons = new ArrayList<>();
        reasons.add("input='" + input + "' type=" + type + " normalized='" + normalized + "'");

        SnapshotIndex index = indexCache.computeIfAbsent(snapshot.version(),
                v -> new SnapshotIndex(normalizer, snapshot));

        List<Indicator> hits = new ArrayList<>();
        findMatches(index, type, normalized, hits, reasons);

        List<String> matchedKeys = hits.stream().map(Indicator::key).distinct().toList();
        boolean matched = !hits.isEmpty();

        // 覆盖判定与命中判定相互独立：无论是否命中，都计算圈住该查询的抑制/白名单规则，
        // 使"被规则覆盖但本身未命中"的查询同样可解释。权限不影响覆盖/命中判定。
        List<SuppressionRule> covering = findCoveringSuppressions(
                snapshot.suppressions(), type, normalized, reasons);
        boolean covered = !covering.isEmpty();
        List<String> coveringRuleIds = covering.stream().map(SuppressionRule::id).toList();
        boolean suppressed = matched && covered;

        if (matched) {
            if (suppressed) {
                for (SuppressionRule rule : covering) {
                    reasons.add("suppressed by rule " + rule.id()
                            + " (pattern='" + rule.pattern() + "', reason=" + rule.reason() + ")");
                }
            }
            for (Indicator ind : hits) {
                reasons.add("hit key=" + ind.key() + " sources=" + ind.sources()
                        + " severity=" + ind.severity()
                        + (ind.conflictNote() == null ? "" : " note=" + ind.conflictNote()));
            }
        } else if (covered) {
            for (SuppressionRule rule : covering) {
                reasons.add("covered by rule " + rule.id()
                        + " (pattern='" + rule.pattern() + "', reason=" + rule.reason()
                        + ") but no indicator matched");
            }
            reasons.add("no indicator matched");
        } else {
            reasons.add("no indicator matched");
        }

        String decision = suppressed ? "SUPPRESSED"
                : matched ? "HIT"
                : covered ? "COVERED" : "CLEAN";
        Verdict verdict = new Verdict(input, normalized, matched, suppressed,
                decision, List.copyOf(reasons), matchedKeys, covered, coveringRuleIds);
        log.info("match verdict: input='{}' normalized='{}' decision={} matchedKeys={} reasons={}",
                input, normalized, decision, matchedKeys, verdict.reasons());
        return verdict;
    }

    // ------------------------------------------------------------------
    // 指标匹配
    // ------------------------------------------------------------------

    private void findMatches(SnapshotIndex index, IndicatorType type, String normalized,
                             List<Indicator> hits, List<String> reasons) {
        switch (type) {
            case IPV4 -> {
                // 查询值可以是地址或 CIDR；按其网络地址执行包含匹配
                String host = stripCidr(normalized);
                long queryIp = normalizer.ipv4ToLong(host);
                matchIpv4(index, queryIp, hits, reasons);
                matchUrlsByHost(index, formatIp(queryIp), hits, reasons);
            }
            case DOMAIN -> {
                matchDomain(index, normalized, hits, reasons);
                matchUrlsByHost(index, normalized, hits, reasons);
            }
            case URL -> {
                Indicator exact = index.urlExact.get(normalized);
                if (exact != null) {
                    hits.add(exact);
                    reasons.add("exact url match");
                }
                String host = normalizer.hostOfUrl(normalized);
                if (normalizer.isCidr(host) || host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                    matchIpv4(index, normalizer.ipv4ToLong(stripCidr(host)), hits, reasons);
                } else {
                    matchDomain(index, host, hits, reasons);
                }
            }
            case HASH_MD5, HASH_SHA1, HASH_SHA256, EMAIL -> {
                Indicator exact = index.exactByType.get(type).get(normalized);
                if (exact != null) {
                    hits.add(exact);
                    reasons.add("exact " + type + " match");
                }
            }
        }
    }

    private void matchIpv4(SnapshotIndex index, long queryIp, List<Indicator> hits,
                           List<String> reasons) {
        Indicator exact = index.ipExact.get(formatIp(queryIp));
        if (exact != null) {
            hits.add(exact);
            reasons.add("exact ipv4 match: " + formatIp(queryIp));
        }
        for (Map.Entry<Indicator, long[]> cidr : index.ipCidrs) {
            long network = cidr.getValue()[0];
            long mask = cidr.getValue()[1];
            if ((queryIp & mask) == network) {
                hits.add(cidr.getKey());
                reasons.add("ipv4 " + formatIp(queryIp) + " contained by CIDR "
                        + cidr.getKey().value());
            }
        }
    }

    private void matchDomain(SnapshotIndex index, String domain, List<Indicator> hits,
                             List<String> reasons) {
        for (Indicator ind : index.domains) {
            if (normalizer.isSubDomainOrSame(domain, ind.value())) {
                hits.add(ind);
                reasons.add("domain '" + domain + "' equals or is subdomain of '"
                        + ind.value() + "'");
            }
        }
    }

    private void matchUrlsByHost(SnapshotIndex index, String canonicalHost,
                                 List<Indicator> hits,
                                 List<String> reasons) {
        for (Indicator urlInd : index.urlsByHost) {
            String urlHost = normalizer.hostOfUrl(urlInd.value());
            if (urlHost.equals(canonicalHost)) {
                hits.add(urlInd);
                reasons.add("url indicator shares host '" + canonicalHost + "': " + urlInd.value());
            }
        }
    }

    // ------------------------------------------------------------------
    // 抑制规则覆盖
    // ------------------------------------------------------------------

    private List<SuppressionRule> findCoveringSuppressions(List<SuppressionRule> rules,
                                                           IndicatorType queryType,
                                                           String normalizedQuery,
                                                           List<String> reasons) {
        List<SuppressionRule> covering = new ArrayList<>();
        String host = queryType == IndicatorType.URL
                ? normalizer.hostOfUrl(normalizedQuery) : null;
        for (SuppressionRule rule : rules) {
            if (suppressionCovers(queryType, normalizedQuery, rule.type(), rule.pattern())) {
                covering.add(rule);
            } else if (host != null && rule.type() == IndicatorType.DOMAIN
                    && !looksLikeIpv4Literal(host)
                    && suppressionCovers(IndicatorType.DOMAIN, host, rule.type(), rule.pattern())) {
                covering.add(rule);
                reasons.add("url host '" + host + "' covered by cross-type rule");
            } else if (host != null && rule.type() == IndicatorType.IPV4
                    && looksLikeIpv4Literal(host)
                    && suppressionCovers(IndicatorType.IPV4, host, rule.type(), rule.pattern())) {
                covering.add(rule);
                reasons.add("url host '" + host + "' covered by cross-type rule");
            }
        }
        return covering;
    }

    /** 抑制模式是否覆盖该指标类型/规范值（域父子域、IP 精确/网段包含，其余精确）。 */
    public boolean suppressionCovers(IndicatorType type, String value,
                                     IndicatorType ruleType, String pattern) {
        if (type == ruleType) {
            return switch (type) {
                case IPV4 -> ipv4CoveredBy(value, pattern);
                case DOMAIN -> normalizer.isSubDomainOrSame(value, pattern);
                default -> value.equals(pattern);
            };
        }
        return false;
    }

    private boolean ipv4CoveredBy(String canonicalValue, String canonicalPattern) {
        long ip = normalizer.ipv4ToLong(stripCidr(canonicalValue));
        if (normalizer.isCidr(canonicalPattern)) {
            int slash = canonicalPattern.indexOf('/');
            long net = normalizer.ipv4ToLong(canonicalPattern.substring(0, slash));
            int prefix = Integer.parseInt(canonicalPattern.substring(slash + 1));
            long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
            return (ip & mask) == net;
        }
        return ip == normalizer.ipv4ToLong(canonicalPattern);
    }

    private String stripCidr(String value) {
        int slash = value.indexOf('/');
        return slash >= 0 ? value.substring(0, slash) : value;
    }

    /** 规范主机是否为点分十进制 IPv4（不含域名）。 */
    private boolean looksLikeIpv4Literal(String host) {
        String[] parts = stripCidr(host).split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String p : parts) {
            if (!p.matches("\\d{1,3}")) {
                return false;
            }
        }
        return true;
    }

    private static String formatIp(long ip) {
        return Normalizer.formatIpv4(ip);
    }

    // ------------------------------------------------------------------
    // 快照不可变索引（按版本缓存，快照本身不可变）
    // ------------------------------------------------------------------

    private static final class SnapshotIndex {
        private final Map<String, Indicator> ipExact = new java.util.HashMap<>();
        private final List<Map.Entry<Indicator, long[]>> ipCidrs = new ArrayList<>();
        private final List<Indicator> domains = new ArrayList<>();
        private final List<Indicator> urlsByHost = new ArrayList<>();
        private final Map<String, Indicator> urlExact = new java.util.HashMap<>();
        private final Map<IndicatorType, Map<String, Indicator>> exactByType = new java.util.EnumMap<>(IndicatorType.class);
        private final Normalizer normalizer;

        private SnapshotIndex(Normalizer normalizer, ThreatSnapshot snapshot) {
            this.normalizer = normalizer;
            for (IndicatorType t : IndicatorType.values()) {
                exactByType.put(t, new java.util.HashMap<>());
            }
            for (Indicator ind : snapshot.indicators()) {
                switch (ind.type()) {
                    case IPV4 -> {
                        if (normalizer.isCidr(ind.value())) {
                            int slash = ind.value().indexOf('/');
                            long net = normalizer.ipv4ToLong(ind.value().substring(0, slash));
                            int prefix = Integer.parseInt(ind.value().substring(slash + 1));
                            long mask = prefix == 0 ? 0L
                                    : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
                            ipCidrs.add(Map.entry(ind, new long[]{net, mask}));
                        } else {
                            ipExact.put(ind.value(), ind);
                        }
                    }
                    case DOMAIN -> domains.add(ind);
                    case URL -> {
                        urlExact.put(ind.value(), ind);
                        urlsByHost.add(ind);
                    }
                    default -> exactByType.get(ind.type()).put(ind.value(), ind);
                }
            }
            ipCidrs.sort((a, b) -> {
                int pa = prefixOf(a.getKey().value());
                int pb = prefixOf(b.getKey().value());
                return Integer.compare(pb, pa); // 更长前缀（更具体）优先
            });
        }

        private int prefixOf(String cidr) {
            return Integer.parseInt(cidr.substring(cidr.indexOf('/') + 1));
        }
    }
}
