package com.github.xingjianluo.threatinteliocjava.model;

import java.time.Instant;
import java.util.List;

/**
 * 匹配判定结论，status 取值：
 * HIT 命中；SUPPRESSED 本应命中但被抑制/白名单优先；NO_HIT 未命中；INVALID_INPUT 输入无法归一。
 */
public record MatchVerdict(
        String status,
        String input,
        String indicatorType,
        String normalizedValue,
        MatchedIndicator match,
        MatchedSuppression suppressedBy,
        String reason,
        Instant evaluatedAt
) {
    public record MatchedIndicator(
            String canonicalValue,
            String severity,
            int confidence,
            List<String> sources
    ) {
    }

    public record MatchedSuppression(
            String id,
            String reason,
            String sourceFile
    ) {
    }
}
