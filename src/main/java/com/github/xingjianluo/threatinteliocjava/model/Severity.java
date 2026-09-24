package com.github.xingjianluo.threatinteliocjava.model;

/**
 * 威胁严重度；冲突收敛时取 ordinal 更大者。
 */
public enum Severity {
    UNKNOWN,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}
