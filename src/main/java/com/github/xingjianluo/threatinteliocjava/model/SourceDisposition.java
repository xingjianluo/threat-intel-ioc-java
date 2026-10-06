package com.github.xingjianluo.threatinteliocjava.model;

/**
 * 一代刷新中单个来源的处置记录。
 *
 * @param source 来源标识（文件名去扩展名）
 * @param health 采用状态
 * @param detail 人类可读细节（跳过原因、条目数等）
 */
public record SourceDisposition(String source, SourceHealth health, String detail) {
}
