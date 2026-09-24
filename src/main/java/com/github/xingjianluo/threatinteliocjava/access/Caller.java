package com.github.xingjianluo.threatinteliocjava.access;

/**
 * 调用方主体（无外部凭据体系，由本地调用方目录映射）。
 */
public record Caller(String id, Role role) {
}
