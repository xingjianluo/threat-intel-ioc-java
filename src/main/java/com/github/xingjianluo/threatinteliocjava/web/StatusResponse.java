package com.github.xingjianluo.threatinteliocjava.web;

import com.github.xingjianluo.threatinteliocjava.model.SourceHealth;
import com.github.xingjianluo.threatinteliocjava.model.ThreatSnapshot;

import java.util.List;
import java.util.Map;

/**
 * 快照状态视图（不含指标明细，故不受来源权限限制）。
 * sourceHealth 给出当前生效代每个来源的采用状态（正常/合法空/读取失败）。
 */
public record StatusResponse(
        long version,
        long loadedAt,
        String contentHash,
        int indicatorCount,
        int suppressionCount,
        Map<String, Integer> sourceCounts,
        List<String> restrictedSources,
        List<SourceHealth> sourceHealth) {

    public static StatusResponse from(ThreatSnapshot snapshot, List<String> restricted) {
        return new StatusResponse(
                snapshot.version(),
                snapshot.loadedAt(),
                snapshot.contentHash(),
                snapshot.indicators().size(),
                snapshot.suppressions().size(),
                snapshot.sourceCounts(),
                restricted,
                snapshot.sourceHealth());
    }
}
