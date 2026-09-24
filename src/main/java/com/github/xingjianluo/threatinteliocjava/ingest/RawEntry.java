package com.github.xingjianluo.threatinteliocjava.ingest;

/**
 * 从情报文件中解析出的单条原始记录（尚未做类型/值归一）。
 *
 * @param line     文件中的行号（错误定位用）
 * @param rawType  原始类型字段
 * @param rawValue 原始指标值
 * @param severity 原始严重度字段（可空）
 */
public record RawEntry(
        int line,
        String rawType,
        String rawValue,
        String severity) {
}
