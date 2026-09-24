package com.github.xingjianluo.threatinteliocjava.web;

import com.github.xingjianluo.threatinteliocjava.model.Indicator;

import java.util.Set;

/**
 * 指标明细视图（仅在来源权限校验通过后返回）。
 */
public record IndicatorView(
        String type,
        String value,
        String display,
        Set<String> sources,
        String severity,
        long firstSeen,
        long updatedAt,
        String conflictNote) {

    public static IndicatorView from(Indicator ind) {
        return new IndicatorView(
                ind.type().name(),
                ind.value(),
                ind.display(),
                ind.sources(),
                ind.severity().name(),
                ind.firstSeen(),
                ind.updatedAt(),
                ind.conflictNote());
    }
}
