package com.github.xingjianluo.threatinteliocjava.model;

/**
 * 一条被拒绝导入的原始条目及其原因，保证错误条目不被静默丢弃。
 */
public record ImportRejection(
        String sourceFile,
        Integer line,
        String rawContent,
        RejectionReason reason,
        String detail
) {
}
