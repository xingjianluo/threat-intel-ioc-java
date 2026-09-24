package com.github.xingjianluo.threatinteliocjava.model;

import java.util.List;
import java.util.Map;

/**
 * 一份不可变的情报快照。匹配线程始终读取完整快照，从不会看到部分加载数据。
 *
 * @param version        单调递增版本号（内容未变化的重复刷新不递增）
 * @param loadedAt       加载时间
 * @param contentHash    本次原始文件内容的确定哈希（去重刷新判定用）
 * @param indicators     去重并按 key 排序后的指标
 * @param suppressions   抑制/白名单规则
 * @param sourceCounts   来源 -> 指标条数（用于计数核对）
 */
public record ThreatSnapshot(
        long version,
        long loadedAt,
        String contentHash,
        List<Indicator> indicators,
        List<SuppressionRule> suppressions,
        Map<String, Integer> sourceCounts) {

    /** 初始空快照。 */
    public static ThreatSnapshot empty() {
        return new ThreatSnapshot(0L, 0L, "-", List.of(), List.of(), Map.of());
    }
}
