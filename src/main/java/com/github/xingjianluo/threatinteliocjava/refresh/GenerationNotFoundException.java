package com.github.xingjianluo.threatinteliocjava.refresh;

/**
 * 指定代际不存在（从未产生或已被容量淘汰）时抛出。
 * 已被淘汰的代际同样落入此类，不能被回滚或查询。
 */
public class GenerationNotFoundException extends RuntimeException {

    private final long generationId;

    public GenerationNotFoundException(long generationId, String message) {
        super(message);
        this.generationId = generationId;
    }

    public long generationId() {
        return generationId;
    }
}
