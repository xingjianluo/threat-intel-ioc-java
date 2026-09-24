package com.github.xingjianluo.threatinteliocjava.model;

import java.util.Set;

/**
 * 统一指标模型（不可变）。
 *
 * @param type        归一类型
 * @param value       归一后的规范值（小写、压缩、标准 CIDR 等）
 * @param display     原始展示值（保留一个首次导入时的可读形式）
 * @param sources     来源集合（同一指标多次导入按集合合并）
 * @param severity    收敛后的严重度
 * @param firstSeen   首次导入时间
 * @param updatedAt   最近一次内容更新时间
 * @param conflictNote 非空表示存在过冲突并已按确定规则收敛
 */
public record Indicator(
        IndicatorType type,
        String value,
        String display,
        Set<String> sources,
        Severity severity,
        long firstSeen,
        long updatedAt,
        String conflictNote) {

    /** 去重键：类型 + 规范值。 */
    public String key() {
        return type + ":" + value;
    }
}
