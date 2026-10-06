package com.github.xingjianluo.threatinteliocjava.model;

/**
 * 单个情报来源在一代刷新中的采用状态（可区分）。
 */
public enum SourceStatus {
    /** 正常读取并采用（可以包含条目级拒绝记录）。 */
    ADOPTED,
    /** 来源正常读取，但合法地不含任何条目（合法空情报）。 */
    SKIPPED_EMPTY,
    /** 来源这次没能正常读到（IO/文件级解析失败），绝不是合法空情报。 */
    SKIPPED_UNREADABLE
}
