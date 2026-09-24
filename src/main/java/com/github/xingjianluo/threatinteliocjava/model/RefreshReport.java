package com.github.xingjianluo.threatinteliocjava.model;

import java.time.Instant;
import java.util.List;

/**
 * 一次刷新的完整结论。刷新失败（success=false）时旧快照保持不变，
 * 部分失败（status=PARTIAL）时拒绝明细可查。
 *
 * @param status OK / PARTIAL / UNCHANGED / FAILED
 */
public record RefreshReport(
        boolean success,
        String status,
        Instant refreshedAt,
        String contentHash,
        int filesScanned,
        int acceptedEntries,
        int duplicateMerged,
        int conflictConverged,
        int totalIndicators,
        int suppressionRules,
        List<ImportRejection> rejections,
        List<ConflictRecord> conflicts,
        String failureReason
) {
}
