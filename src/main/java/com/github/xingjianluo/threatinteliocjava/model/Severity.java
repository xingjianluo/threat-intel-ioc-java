package com.github.xingjianluo.threatinteliocjava.model;

/** 威胁严重级别，顺序即确定性排序所需的声明顺序。 */
public enum Severity {
    UNKNOWN,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    /** 严重级别代码（大小写不敏感）；空或未知一律收敛为 UNKNOWN（确定规则）。 */
    public static Severity fromCode(String code) {
        if (code == null || code.isBlank()) {
            return UNKNOWN;
        }
        return switch (code.trim().toLowerCase()) {
            case "low", "info" -> LOW;
            case "medium", "moderate" -> MEDIUM;
            case "high" -> HIGH;
            case "critical", "severe" -> CRITICAL;
            default -> UNKNOWN;
        };
    }
}
