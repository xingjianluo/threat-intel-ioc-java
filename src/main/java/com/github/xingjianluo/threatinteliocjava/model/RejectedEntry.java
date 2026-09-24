package com.github.xingjianluo.threatinteliocjava.model;

/**
 * 被拒绝条目：记录原始内容片段与可区分原因，绝不静默丢弃。
 */
public record RejectedEntry(
        String source,
        String rawLine,
        RejectionCode code,
        String detail) {
}
