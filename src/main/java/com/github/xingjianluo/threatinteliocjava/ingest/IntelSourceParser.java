package com.github.xingjianluo.threatinteliocjava.ingest;

/** 单个情报文件格式解析器。 */
public interface IntelSourceParser {

    /** 是否支持该文件名（按扩展名）。 */
    boolean supports(String fileName);

    /** 解析文件，文件级损坏返回带 fatalError 的结果；条目级问题逐条拒绝。 */
    ParseResult parse(java.nio.file.Path file);
}
