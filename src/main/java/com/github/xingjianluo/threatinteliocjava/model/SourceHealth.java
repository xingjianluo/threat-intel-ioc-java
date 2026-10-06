package com.github.xingjianluo.threatinteliocjava.model;

/**
 * 一代刷新中单个来源的采用状态。
 *
 * <ul>
 *   <li>ADOPTED：来源正常读取并被采用（可以含有被逐条拒绝的坏行）。</li>
 *   <li>SKIPPED_EMPTY：来源正常读取但合法地为空（0 条目、0 坏行），按空情报处理。</li>
 *   <li>SKIPPED_UNREADABLE：来源这次没能正常读到（IO/文件级解析失败），
 *       绝不能被当成合法空情报。</li>
 * </ul>
 */
public enum SourceHealth {
    ADOPTED,
    SKIPPED_EMPTY,
    SKIPPED_UNREADABLE
}
