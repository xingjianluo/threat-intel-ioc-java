package com.github.xingjianluo.threatinteliocjava.model;

import java.util.List;

/**
 * 一次匹配查询的可解释判定结果。
 *
 * @param input           原始输入
 * @param normalizedInput 归一后的输入
 * @param matched         是否命中指标
 * @param suppressed      是否被抑制/白名单覆盖（抑制优先于命中）
 * @param decision        最终结论：HIT / SUPPRESSED / CLEAN
 * @param reasons         判定依据（人类可读，用于日志）
 * @param matchedKeys     命中的指标 key（明细访问控制由查询接口另行处理）
 */
public record Verdict(
        String input,
        String normalizedInput,
        boolean matched,
        boolean suppressed,
        String decision,
        List<String> reasons,
        List<String> matchedKeys) {
}
