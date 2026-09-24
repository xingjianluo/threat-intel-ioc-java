package com.github.xingjianluo.threatinteliocjava.ingest;

import com.github.xingjianluo.threatinteliocjava.normalize.IocNormalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * 扫描情报目录，按文件名把每个文件分派给对应解析器。
 * 结果按文件名排序，保证多次扫描顺序确定（重复导入结果不漂移）。
 * 目录不存在或 I/O 异常直接抛出，由刷新层判定为整体失败并保留旧快照。
 */
@Component
public class IntelFileLoader {

    private static final Logger log = LoggerFactory.getLogger(IntelFileLoader.class);

    private final List<IntelSourceParser> parsers;
    private final IocNormalizer normalizer;

    public IntelFileLoader(List<IntelSourceParser> parsers, IocNormalizer normalizer) {
        this.parsers = parsers;
        this.normalizer = normalizer;
    }

    public IocNormalizer getNormalizer() {
        return normalizer;
    }

    public List<IntelSourceParser> getParsers() {
        return parsers;
    }

    /** 扫描目录，返回按文件名排序的解析结果；I/O 错误抛异常交由刷新层判失败。 */
    public List<ParseResult> loadDirectory(Path directory) throws IOException {
        if (directory == null || !Files.isDirectory(directory)) {
            throw new IOException("情报目录不存在或不是目录: " + directory);
        }
        List<Path> files;
        try (var stream = Files.list(directory)) {
            files = stream.filter(Files::isRegularFile)
                    .sorted(Comparator.comparing(p -> p.getFileName().toString()))
                    .toList();
        }
        List<ParseResult> results = new ArrayList<>();
        for (Path file : files) {
            String fileName = file.getFileName().toString();
            IntelSourceParser parser = parsers.stream()
                    .filter(p -> p.supports(fileName))
                    .findFirst()
                    .orElse(null);
            if (parser == null) {
                log.info("跳过无解析器支持的文件: {}", fileName);
                continue;
            }
            log.info("加载情报文件: {} ({}解析器)", fileName,
                    parser.getClass().getSimpleName());
            results.add(parser.parse(file));
        }
        return results;
    }
}
