package com.github.xingjianluo.threatinteliocjava.web;

import com.github.xingjianluo.threatinteliocjava.model.Generation;
import com.github.xingjianluo.threatinteliocjava.model.ThreatSnapshot;
import com.github.xingjianluo.threatinteliocjava.refresh.RefreshOutcome;

import java.util.List;
import java.util.Map;

/**
 * 快照状态视图（不含指标明细，故不受来源权限限制）。
 * 含当前代际、最近刷新结论（未成功的刷新可明确区分）与代际保留情况。
 */
public record StatusResponse(
        long version,
        long loadedAt,
        String contentHash,
        int indicatorCount,
        int suppressionCount,
        Map<String, Integer> sourceCounts,
        List<String> restrictedSources,
        Long currentGeneration,
        Boolean currentGenerationComplete,
        String lastRefreshOutcome,
        Boolean lastRefreshSuccess,
        int generationHistoryCapacity,
        int retainedGenerations) {

    public static StatusResponse from(ThreatSnapshot snapshot, List<String> restricted,
                                      Generation current, RefreshOutcome lastRefresh,
                                      int historyCapacity, int retainedGenerations) {
        return new StatusResponse(
                snapshot.version(),
                snapshot.loadedAt(),
                snapshot.contentHash(),
                snapshot.indicators().size(),
                snapshot.suppressions().size(),
                snapshot.sourceCounts(),
                restricted,
                current == null ? null : current.id(),
                current == null ? null : current.complete(),
                lastRefresh == null ? null : lastRefresh.outcome(),
                lastRefresh == null ? null : lastRefresh.outcome().startsWith("APPLIED"),
                historyCapacity,
                retainedGenerations);
    }
}
