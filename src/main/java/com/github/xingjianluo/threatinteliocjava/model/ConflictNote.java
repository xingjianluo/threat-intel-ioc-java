package com.github.xingjianluo.threatinteliocjava.model;

/**
 * 同一指标定义发生冲突时的收敛记录（确定性规则：严重度取最高，来源取并集）。
 */
public record ConflictNote(
        String field,
        String keptValue,
        String droppedValue) {

    public String describe() {
        return "conflict[" + field + "]: kept=" + keptValue + ", dropped=" + droppedValue;
    }
}
