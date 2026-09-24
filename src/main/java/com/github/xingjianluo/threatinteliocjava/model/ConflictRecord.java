package com.github.xingjianluo.threatinteliocjava.model;

/**
 * 同一指标定义相互冲突时的收敛记录：说明选中了哪一条、丢弃了哪一条、依据什么规则。
 */
public record ConflictRecord(
        IndicatorType type,
        String canonicalValue,
        String resolutionRule,
        String chosenDescriptor,
        String ignoredDescriptor
) {
}
