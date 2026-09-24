package com.github.xingjianluo.threatinteliocjava.service;

import com.github.xingjianluo.threatinteliocjava.model.IndicatorType;
import com.github.xingjianluo.threatinteliocjava.model.IocIndicator;
import com.github.xingjianluo.threatinteliocjava.model.MatchVerdict;
import com.github.xingjianluo.threatinteliocjava.model.SuppressionRule;
import com.github.xingjianluo.threatinteliocjava.normalize.NormalizationException;
import com.github.xingjianluo.threatinteliocjava.normalize.IocNormalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

/**
 * 匹配查询服务。
 *
 * <p>判定流程（全部针对当前不可变快照执行）：
 * <ol>
 *   <li>确定指标类型（显式 type 参数或自动检测）并归一输入；无法归一 → INVALID_INPUT；</li>
 *   <li>按等价形式查找命中：IP 精确或被网段包含；域名本身或为指标域的子域；
 *       URL/HASH/CIDR 精确归一比较；</li>
 *   <li>无论是否命中，再用相同等价语义查找抑制/白名单规则；
 *       抑制优先于命中 → SUPPRESSED，且结论中同时给出命中与抑制依据；</li>
 *   <li>无快照时给出 NO_HIT 并说明情报尚未加载；</li>
 * </ol>
 * 判定完全不依赖调用方角色：无权限调用方得到与其他人完全一致的判定，
 * 权限只作用于 {@link #detail} 明细查询。
 */
@Service
public class MatcherService {

    private static final Logger log = LoggerFactory.getLogger(MatcherService.class);

    private final IntelRegistry registry;
    private final IocNormalizer normalizer;
    private final AccessControlService accessControl;

    public MatcherService(IntelRegistry registry, IocNormalizer normalizer,
                          AccessControlService accessControl) {
        this.registry = registry;
        this.normalizer = normalizer;
        this.accessControl = accessControl;
    }

    /** 匹配判定。callerRoles 只用于日志审计，不改变判定结果。 */
    public MatchVerdict match(String rawInput, String rawType, Set<String> callerRoles) {
        Instant now = Instant.now();
        if (rawInput == null || rawInput.isBlank()) {
            log.info("匹配输入为空 status=INVALID_INPUT roles={}", callerRoles);
            return new MatchVerdict("INVALID_INPUT", rawInput, null, null, null, null,
                    "输入为空", now);
        }
        IndicatorType type = rawType == null || rawType.isBlank()
                ? normalizer.detectType(rawInput)
                : IndicatorType.fromCode(rawType);
        if (type == null) {
            log.info("匹配拒绝: input='{}' typeHint='{}' status=INVALID_INPUT 原因=类型不支持或无法识别 roles={}",
                    rawInput, rawType, callerRoles);
            return new MatchVerdict("INVALID_INPUT", rawInput, rawType, null, null, null,
                    "类型不支持或无法识别: " + rawType, now);
        }
        String normalized;
        try {
            normalized = normalizer.normalize(type, rawInput);
        } catch (NormalizationException e) {
            log.info("匹配拒绝: input='{}' 判定类型={} status=INVALID_INPUT 原因={} roles={}",
                    rawInput, type, e.getMessage(), callerRoles);
            return new MatchVerdict("INVALID_INPUT", rawInput, type.name(), null, null, null,
                    "输入无法归一为 " + type + ": " + e.getMessage(), now);
        }

        Optional<IntelSnapshot> snapshotOpt = registry.currentSnapshot();
        if (snapshotOpt.isEmpty()) {
            log.info("匹配 input='{}' normalized={} status=NO_HIT 原因=情报尚未加载 roles={}",
                    rawInput, normalized, callerRoles);
            return new MatchVerdict("NO_HIT", rawInput, type.name(), normalized, null, null,
                    "情报尚未加载，无任何指标", now);
        }
        IntelSnapshot snapshot = snapshotOpt.get();
        IocIndicator hit = findIndicator(snapshot, type, normalized).orElse(null);
        SuppressionRule suppressor = findSuppression(snapshot, type, normalized).orElse(null);

        MatchVerdict verdict;
        if (suppressor != null && hit != null) {
            verdict = new MatchVerdict("SUPPRESSED", rawInput, type.name(), normalized,
                    toMatched(hit), toSuppression(suppressor),
                    "命中指标 " + hit.canonicalValue() + "（" + hit.severity()
                            + "/confidence=" + hit.confidence() + "），但抑制/白名单规则 "
                            + suppressor.id() + " 优先：" + suppressorReason(suppressor),
                    now);
        } else if (suppressor != null) {
            verdict = new MatchVerdict("SUPPRESSED", rawInput, type.name(), normalized,
                    null, toSuppression(suppressor),
                    "未命中指标；抑制/白名单规则 " + suppressor.id() + " 匹配："
                            + suppressorReason(suppressor),
                    now);
        } else if (hit != null) {
            String how = explainMatch(type, normalized, hit);
            verdict = new MatchVerdict("HIT", rawInput, type.name(), normalized,
                    toMatched(hit), null,
                    "命中指标 " + hit.canonicalValue() + "（" + hit.severity()
                            + "/confidence=" + hit.confidence() + "），匹配方式=" + how
                            + "，来源=" + hit.sources(), now);
        } else {
            verdict = new MatchVerdict("NO_HIT", rawInput, type.name(), normalized, null, null,
                    "归一值 " + normalized + " 未命中任何指标或网段/父域", now);
        }
        log.info("匹配判定 input='{}' type={} normalized='{}' status={} 依据={} roles={}",
                rawInput, type, normalized, verdict.status(), verdict.reason(), callerRoles);
        return verdict;
    }

    /** 按规范键查询指标完整明细，权限不足抛 {@link AccessDeniedException}。 */
    public IocIndicator detail(String typeCode, String value, Set<String> callerRoles) {
        IndicatorType type = IndicatorType.fromCode(typeCode);
        if (type == null) {
            throw new IllegalArgumentException("不支持的指标类型: " + typeCode);
        }
        String normalized;
        try {
            normalized = normalizer.normalize(type, value);
        } catch (NormalizationException e) {
            throw new IllegalArgumentException("指标值无法归一: " + e.getMessage());
        }
        IntelSnapshot snapshot = registry.currentSnapshot()
                .orElseThrow(() -> new IndicatorNotFoundException("情报尚未加载"));
        IocIndicator indicator = snapshot.findExact(type.name() + "|" + normalized)
                .orElseThrow(() -> new IndicatorNotFoundException(
                        "指标不存在: " + type + "/" + normalized));
        accessControl.checkDetailAccess(indicator, callerRoles);
        log.info("明细查询允许: {}/{} roles={}", type, normalized, callerRoles);
        return indicator;
    }

    private Optional<IocIndicator> findIndicator(IntelSnapshot snapshot, IndicatorType type,
                                                 String normalized) {
        if (type == IndicatorType.IP) {
            Optional<IocIndicator> exact = snapshot.findExact(type.name() + "|" + normalized);
            if (exact.isPresent()) {
                return exact;
            }
            return snapshot.findContainingCidr(normalized).map(IntelSnapshot.CidrEntry::indicator);
        }
        if (type == IndicatorType.DOMAIN) {
            return snapshot.findDomain(normalized);
        }
        return snapshot.findExact(type.name() + "|" + normalized);
    }

    private Optional<SuppressionRule> findSuppression(IntelSnapshot snapshot,
                                                      IndicatorType type, String normalized) {
        SuppressionRule best = null;
        int bestSpecificity = -1;
        for (SuppressionRule rule : snapshot.allSuppressions()) {
            if (rule.type() == type && rule.canonicalValue().equals(normalized)) {
                if (normalized.length() > bestSpecificity) {
                    bestSpecificity = normalized.length();
                    best = rule;
                }
            } else if (type == IndicatorType.IP && rule.type() == IndicatorType.CIDR) {
                try {
                    if (normalizer.cidr(rule.canonicalValue()).contains(normalized)) {
                        int spec = normalizer.cidr(rule.canonicalValue()).prefixLength();
                        if (spec > bestSpecificity) {
                            bestSpecificity = spec;
                            best = rule;
                        }
                    }
                } catch (NormalizationException ignore) {
                    // 规则入库时已归一，理论不会发生
                }
            } else if (type == IndicatorType.DOMAIN && rule.type() == IndicatorType.DOMAIN) {
                String d = rule.canonicalValue();
                boolean match = normalized.equals(d) || normalized.endsWith("." + d);
                if (match && d.length() > bestSpecificity) {
                    bestSpecificity = d.length();
                    best = rule;
                }
            }
        }
        return Optional.ofNullable(best);
    }

    private String explainMatch(IndicatorType queried, String normalized, IocIndicator hit) {
        if (queried == IndicatorType.IP && hit.type() == IndicatorType.CIDR) {
            return "IP 被网段 " + hit.canonicalValue() + " 包含";
        }
        if (queried == IndicatorType.DOMAIN && !normalized.equals(hit.canonicalValue())) {
            return "子域，父域指标为 " + hit.canonicalValue();
        }
        return "归一值精确相等";
    }

    private String suppressorReason(SuppressionRule rule) {
        return rule.reason() == null ? "（未注明原因）" : rule.reason();
    }

    private MatchVerdict.MatchedIndicator toMatched(IocIndicator hit) {
        return new MatchVerdict.MatchedIndicator(hit.canonicalValue(), hit.severity().name(),
                hit.confidence(), hit.sources());
    }

    private MatchVerdict.MatchedSuppression toSuppression(SuppressionRule rule) {
        return new MatchVerdict.MatchedSuppression(rule.id(), rule.reason(), rule.sourceFile());
    }
}
