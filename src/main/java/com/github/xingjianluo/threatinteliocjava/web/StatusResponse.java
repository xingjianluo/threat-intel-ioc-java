package com.github.xingjianluo.threatinteliocjava.web;

import com.github.xingjianluo.threatinteliocjava.model.ThreatSnapshot;

import java.util.List;
import java.util.Map;

/**
 * 快照状态视图（不含指标明细，故不受来源权限限制）。
 */
public record StatusResponse(
        long version,
        long loadedAt,
        String contentHash,
        int indicatorCount,
        int suppressionCount,
        Map<String, Integer> sourceCounts,
        List<String> restrictedSources) {

    public static StatusResponse from(ThreatSnapshot snapshot, List<String> restricted) {
        return new StatusResponse(
                snapshot.version(),
                snapshot.loadedAt(),
                snapshot.contentHash(),
                snapshot.indicators().size(),
                snapshot.suppressions().size(),
                snapshot.sourceCounts(),
                restricted);
    }
}
