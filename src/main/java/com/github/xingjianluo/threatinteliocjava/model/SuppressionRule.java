package com.github.xingjianluo.threatinteliocjava.model;

/**
 * 抑制 / 白名单规则（不可变）。
 *
 * @param id       规则标识
 * @param type     适用指标类型
 * @param pattern  规范模式（域名/IP 支持子域与网段包含，其余精确）
 * @param reason   抑制原因（判定解释用）
 */
public record SuppressionRule(
        String id,
        IndicatorType type,
        String pattern,
        String reason) {
}
