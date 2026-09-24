package com.github.xingjianluo.threatinteliocjava.ingest;

import com.github.xingjianluo.threatinteliocjava.model.RejectedEntry;

import java.util.List;

/**
 * 一次导入动作的结构化结论。重复内容不计入新增，拒绝条目逐条带原因。
 */
public record ImportReport(
        int totalRaw,
        int accepted,
        int duplicates,
        int mergedConflicts,
        List<RejectedEntry> rejected) {

    public boolean hasRejections() {
        return rejected != null && !rejected.isEmpty();
    }
}
