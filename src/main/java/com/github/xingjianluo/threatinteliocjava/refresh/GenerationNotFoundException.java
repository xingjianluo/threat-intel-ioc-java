package com.github.xingjianluo.threatinteliocjava.refresh;

/**
 * 按代际查询/回滚时，目标代际不可用的可区分异常。
 * reason 为 GENERATION_EVICTED（曾存在但已被容量淘汰）或 GENERATION_NOT_FOUND（从未存在）。
 */
public class GenerationNotFoundException extends RuntimeException {

    private final long generation;
    private final String reason;

    public GenerationNotFoundException(long generation, String reason, String message) {
        super(message);
        this.generation = generation;
        this.reason = reason;
    }

    public long generation() {
        return generation;
    }

    public String reason() {
        return reason;
    }
}
