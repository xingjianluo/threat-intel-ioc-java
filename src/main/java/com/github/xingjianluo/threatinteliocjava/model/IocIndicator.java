package com.github.xingjianluo.threatinteliocjava.model;

import java.util.List;
import java.util.Set;

/**
 * 归一后的统一指标模型。
 *
 * @param type           统一类型
 * @param canonicalValue 归一值（匹配键）
 * @param displayValue   首次见到的原始写法（可解释展示）
 * @param severity       严重级别
 * @param confidence     置信度 0-100
 * @param description    描述文本
 * @param sources        收敛到该指标的全部来源 feed 名（有序、去重）
 * @param requiredRoles  查看明细所需的角色集合（为空表示不限制）
 */
public record IocIndicator(
        IndicatorType type,
        String canonicalValue,
        String displayValue,
        Severity severity,
        int confidence,
        String description,
        List<String> sources,
        Set<String> requiredRoles
) {
}
