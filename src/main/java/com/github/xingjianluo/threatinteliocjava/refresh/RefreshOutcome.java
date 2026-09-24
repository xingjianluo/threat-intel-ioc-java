package com.github.xingjianluo.threatinteliocjava.refresh;

import com.github.xingjianluo.threatinteliocjava.ingest.ImportReport;
import com.github.xingjianluo.threatinteliocjava.model.RejectedEntry;

import java.util.List;

/**
 * 一次刷新的确定结论。
 *
 * @param outcome     APPLIED / APPLIED_UNCHANGED / REJECTED_PRESERVED / ALREADY_RUNNING / NO_PREVIOUS_STATE
 * @param version     生效后的快照版本（未生效时为当前版本）
 * @param report      归一/导入统计
 * @param failures    文件级与条目级失败明细（原因为可区分枚举）
 * @param message     人类可读结论
 */
public record RefreshOutcome(
        String outcome,
        long version,
        ImportReport report,
        List<RejectedEntry> failures,
        String message) {
}
