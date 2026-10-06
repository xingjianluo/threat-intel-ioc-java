package com.github.xingjianluo.threatinteliocjava.model;

/**
 * 一代刷新中单个来源的健康留痕（不可变）。
 *
 * @param source 来源标识（文件名去扩展名）
 * @param status 采用状态（正常采用 / 合法为空 / 读取失败）
 * @param detail 人类可读细节（如失败原因码与说明）
 */
public record SourceHealth(
        String source,
        SourceStatus status,
        String detail) {
}
