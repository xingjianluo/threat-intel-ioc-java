package com.github.xingjianluo.threatinteliocjava.normalize;

import com.github.xingjianluo.threatinteliocjava.model.IndicatorType;
import com.github.xingjianluo.threatinteliocjava.model.Severity;

/**
 * 单条原始情报归一化后的中间表示。
 *
 * @param type         归一类型
 * @param value        规范值
 * @param display      原始展示值
 * @param severity     来源声明的严重度
 * @param conflictNote 非空表示刷新内同 key 严重度冲突已按最高值收敛
 */
public record NormalizedRaw(
        IndicatorType type,
        String value,
        String display,
        Severity severity,
        String conflictNote) {

    public NormalizedRaw(IndicatorType type, String value, String display, Severity severity) {
        this(type, value, display, severity, null);
    }

    public NormalizedRaw withConflictNote(String note) {
        return new NormalizedRaw(type, value, display, severity, note);
    }
}
