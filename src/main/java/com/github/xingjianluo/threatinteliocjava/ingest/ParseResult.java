package com.github.xingjianluo.threatinteliocjava.ingest;

import com.github.xingjianluo.threatinteliocjava.model.ImportRejection;

import java.util.List;

/** 单个文件的解析结果：条目级问题进入 rejections；文件级致命错误体现在 fatalError。 */
public record ParseResult(
        String sourceFile,
        List<RawIndicator> indicators,
        List<RawSuppression> suppressions,
        List<ImportRejection> rejections,
        String fatalError
) {
    public boolean fatal() {
        return fatalError != null;
    }
}
