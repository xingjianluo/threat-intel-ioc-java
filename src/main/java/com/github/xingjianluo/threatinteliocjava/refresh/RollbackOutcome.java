package com.github.xingjianluo.threatinteliocjava.refresh;

/**
 * 一次回滚请求的确定结论。
 *
 * @param outcome ROLLED_BACK / ALREADY_CURRENT / GENERATION_EVICTED /
 *                GENERATION_NOT_FOUND / ALREADY_RUNNING
 * @param version 请求生效后的当前版本（未生效时为当前版本）
 * @param message 人类可读结论
 */
public record RollbackOutcome(
        String outcome,
        long version,
        String message) {
}
