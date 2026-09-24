package com.github.xingjianluo.threatinteliocjava.ingest;

/**
 * 本地情报文件解析器抽象。不同格式各自实现，产出统一原始条目流。
 */
public interface FeedParser {

    /** 该解析器支持的文件扩展名（小写，含点，例如 ".jsonl"）。 */
    String supportedExtension();

    /**
     * 解析文件全部内容。
     *
     * @param content 文件文本
     * @return 成功条目 + 逐行拒绝条目；文件级结构错误抛 {@link FeedParseException}
     */
    ParsedBatch parse(String content);
}
