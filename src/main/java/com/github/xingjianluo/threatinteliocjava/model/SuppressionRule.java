package com.github.xingjianluo.threatinteliocjava.model;

/**
 * 抑制/白名单规则，与指标使用同一套归一与等价语义，匹配优先级高于命中。
 */
public record SuppressionRule(
        String id,
        IndicatorType type,
        String canonicalValue,
        String displayValue,
        String reason,
        String sourceFile
) {
}
