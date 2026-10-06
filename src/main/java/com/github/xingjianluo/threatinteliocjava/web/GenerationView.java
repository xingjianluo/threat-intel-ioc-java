package com.github.xingjianluo.threatinteliocjava.web;

import com.github.xingjianluo.threatinteliocjava.model.SourceHealth;
import com.github.xingjianluo.threatinteliocjava.model.ThreatSnapshot;

import java.util.List;

/**
 * 一代刷新结果的可追溯视图（不含指标明细，故不受来源权限限制）。
 */
public record GenerationView(
        long version,
        long loadedAt,
        String contentHash,
        int indicatorCount,
        int suppressionCount,
        boolean active,
        List<SourceHealth> sourceHealth) {

    public static GenerationView from(ThreatSnapshot snapshot, boolean active) {
        return new GenerationView(
                snapshot.version(),
                snapshot.loadedAt(),
                snapshot.contentHash(),
                snapshot.indicators().size(),
                snapshot.suppressions().size(),
                active,
                snapshot.sourceHealth());
    }
}
