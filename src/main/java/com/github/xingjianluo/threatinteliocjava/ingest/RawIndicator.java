package com.github.xingjianluo.threatinteliocjava.ingest;

/**
 * 解析后、归一前的原始指标条目。
 *
 * @param sourceFile 来源文件名（用于溯源与明细权限判定）
 * @param line       所在行（CSV/规则表）；JSON 条目可为 null
 */
public record RawIndicator(
        String sourceFile,
        Integer line,
        String rawType,
        String value,
        String severity,
        String confidence,
        String description
) {
}
