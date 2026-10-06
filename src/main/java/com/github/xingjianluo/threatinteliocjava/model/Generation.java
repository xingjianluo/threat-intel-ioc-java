package com.github.xingjianluo.threatinteliocjava.model;

import java.util.List;

/**
 * 一代可追溯的刷新结果：一份完整快照 + 各来源采用状态。
 *
 * @param id        代际编号（与快照版本号一致，单调递增）
 * @param loadedAt  形成时间
 * @param snapshot  该代生效的不可变快照
 * @param sources   各来源处置（正常采用 / 合法为空 / 读取失败）
 */
public record Generation(
        long id,
        long loadedAt,
        ThreatSnapshot snapshot,
        List<SourceDisposition> sources) {

    public Generation {
        sources = List.copyOf(sources);
    }

    /** 该代是否完整可用：没有任何来源读取失败。 */
    public boolean complete() {
        return sources.stream().noneMatch(s -> s.health() == SourceHealth.SKIPPED_UNREADABLE);
    }
}
