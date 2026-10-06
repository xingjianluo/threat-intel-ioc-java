package com.github.xingjianluo.threatinteliocjava.web;

import com.github.xingjianluo.threatinteliocjava.model.Generation;
import com.github.xingjianluo.threatinteliocjava.model.SourceDisposition;

import java.util.List;

/**
 * 代际视图：一代的来源健康与生效标记（不含指标明细，不受来源权限限制）。
 */
public record GenerationView(
        long id,
        long loadedAt,
        boolean current,
        boolean complete,
        int indicatorCount,
        List<SourceDisposition> sources) {

    public static GenerationView from(Generation generation, long currentId) {
        return new GenerationView(
                generation.id(),
                generation.loadedAt(),
                generation.id() == currentId,
                generation.complete(),
                generation.snapshot().indicators().size(),
                generation.sources());
    }
}
