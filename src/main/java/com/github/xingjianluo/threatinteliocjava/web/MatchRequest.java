package com.github.xingjianluo.threatinteliocjava.web;

/**
 * 匹配查询请求体。apiKey 可为空（匿名仅能查询，且明细全部脱敏）。
 * generation 可为空：为空看最新一代，指定则看该代历史结果。
 */
public record MatchRequest(String type, String value, String apiKey, Long generation) {
}
