package com.github.xingjianluo.threatinteliocjava.ingest;

/** 解析后的原始抑制/白名单规则。 */
public record RawSuppression(
        String sourceFile,
        Integer line,
        String id,
        String rawType,
        String value,
        String reason
) {
}
