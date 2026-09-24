package com.github.xingjianluo.threatinteliocjava.ingest;

import com.github.xingjianluo.threatinteliocjava.model.RejectedEntry;

import java.util.List;

/**
 * 单个文件的解析结果：成功条目与逐行拒绝条目（拒绝必须可区分、不可静默丢弃）。
 */
public record ParsedBatch(List<RawEntry> entries, List<RejectedEntry> rejected) {
}
