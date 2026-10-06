package com.github.xingjianluo.threatinteliocjava.refresh;

import com.github.xingjianluo.threatinteliocjava.ingest.ImportReport;
import com.github.xingjianluo.threatinteliocjava.model.RejectedEntry;
import com.github.xingjianluo.threatinteliocjava.model.SourceHealth;

import java.util.List;

/**
 * 一次刷新的确定结论。
 *
 * @param outcome      APPLIED / APPLIED_PARTIAL / APPLIED_UNCHANGED /
 *                     REJECTED_PRESERVED / REJECTED_NO_PREVIOUS_STATE / ALREADY_RUNNING
 * @param version      生效后的快照版本（未生效时为当前版本）
 * @param report       归一/导入统计
 * @param failures     文件级与条目级失败明细（原因为可区分枚举）
 * @param message      人类可读结论
 * @param sourceHealth 本次刷新每个来源的采用状态（正常采用/合法为空/读取失败）；
 *                     刷新未生效时同样给出，便于区分"读取异常"与"合法空情报"
 */
public record RefreshOutcome(
        String outcome,
        long version,
        ImportReport report,
        List<RejectedEntry> failures,
        String message,
        List<SourceHealth> sourceHealth) {

    /** 兼容旧构造：无来源健康信息。 */
    public RefreshOutcome(String outcome, long version, ImportReport report,
                          List<RejectedEntry> failures, String message) {
        this(outcome, version, report, failures, message, List.of());
    }
}
