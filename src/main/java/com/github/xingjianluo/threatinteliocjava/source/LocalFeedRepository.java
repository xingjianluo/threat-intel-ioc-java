package com.github.xingjianluo.threatinteliocjava.source;

import com.github.xingjianluo.threatinteliocjava.ingest.FeedParseException;
import com.github.xingjianluo.threatinteliocjava.ingest.FeedParser;
import com.github.xingjianluo.threatinteliocjava.ingest.ParsedBatch;
import com.github.xingjianluo.threatinteliocjava.ingest.RawEntry;
import com.github.xingjianluo.threatinteliocjava.model.RejectedEntry;
import com.github.xingjianluo.threatinteliocjava.model.RejectionCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 从本地目录读取情报文件，按扩展名分发解析器。不访问任何外部服务。
 *
 * <p>来源命名约定：文件名去掉扩展名即来源标识（例如 {@code vendorA.jsonl} ->
 * 来源 {@code vendorA}）。目录按确定顺序（文件名升序）扫描，保证内容哈希可复现。
 */
@Component
public class LocalFeedRepository {

    private static final Logger log = LoggerFactory.getLogger(LocalFeedRepository.class);

    private final Map<String, FeedParser> parsersByExtension;

    public LocalFeedRepository(List<FeedParser> parsers) {
        this.parsersByExtension = parsers.stream()
                .collect(Collectors.toUnmodifiableMap(
                        FeedParser::supportedExtension, Function.identity()));
    }

    /** 单个文件解析结果。 */
    public record FeedBatch(String source, String fileName, ParsedBatch batch) {
    }

    /** 目录扫描结果：成功文件的条目 + 文件级失败（失败带可区分原因）。 */
    public record LoadedDirectory(List<FeedBatch> batches, List<RejectedEntry> fileFailures) {

        public List<RawEntry> allEntries() {
            List<RawEntry> all = new ArrayList<>();
            for (FeedBatch batch : batches) {
                all.addAll(batch.batch().entries());
            }
            return List.copyOf(all);
        }
    }

    /** 读取并解析目录下所有受支持文件。目录不存在时返回空结果（不抛异常）。 */
    public LoadedDirectory load(String directory) {
        Path dir = Path.of(directory);
        List<RejectedEntry> fileFailures = new ArrayList<>();
        List<FeedBatch> batches = new ArrayList<>();
        if (!Files.isDirectory(dir)) {
            log.warn("feed directory does not exist, loading empty snapshot: {}", dir.toAbsolutePath());
            return new LoadedDirectory(List.of(), List.of());
        }
        List<Path> files;
        try (var stream = Files.list(dir)) {
            files = stream.filter(Files::isRegularFile)
                    .sorted(Comparator.comparing(p -> p.getFileName().toString()))
                    .toList();
        } catch (IOException e) {
            throw new FeedParseException(RejectionCode.PARSE_IO_ERROR,
                    "cannot list feed directory: " + directory, e);
        }
        for (Path file : files) {
            String fileName = file.getFileName().toString();
            int dot = fileName.lastIndexOf('.');
            String extension = dot >= 0 ? fileName.substring(dot).toLowerCase() : "";
            FeedParser parser = parsersByExtension.get(extension);
            if (parser == null) {
                log.info("skip file with unsupported extension: {}", fileName);
                continue;
            }
            String source = dot >= 0 ? fileName.substring(0, dot) : fileName;
            String content;
            try {
                content = Files.readString(file, StandardCharsets.UTF_8);
            } catch (IOException e) {
                fileFailures.add(new RejectedEntry(source, fileName,
                        RejectionCode.PARSE_IO_ERROR, "unreadable file: " + e.getMessage()));
                continue;
            }
            try {
                ParsedBatch batch = parser.parse(content);
                batches.add(new FeedBatch(source, fileName, batch));
            } catch (FeedParseException e) {
                fileFailures.add(new RejectedEntry(source, fileName, e.code(), e.getMessage()));
            }
        }
        return new LoadedDirectory(List.copyOf(batches), List.copyOf(fileFailures));
    }

    /** 读取单个文本文件；缺失返回 null。 */
    public String readTextFile(String path) {
        try {
            Path p = Path.of(path);
            if (!Files.isRegularFile(p)) {
                return null;
            }
            return Files.readString(p, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new FeedParseException(RejectionCode.PARSE_IO_ERROR,
                    "cannot read file: " + path, e);
        }
    }

    /**
     * 对目录内所有已支持文件的原始字节做确定哈希（文件名排序后逐个更新），
     * 用于识别"相同内容重复刷新"，避免无意义的版本递增与状态漂移。
     */
    public String contentHash(String directory) {
        Path dir = Path.of(directory);
        if (!Files.isDirectory(dir)) {
            return "empty:" + dir;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            List<Path> files;
            try (var stream = Files.list(dir)) {
                files = stream.filter(Files::isRegularFile)
                        .filter(p -> {
                            String n = p.getFileName().toString();
                            int dot = n.lastIndexOf('.');
                            String ext = dot >= 0 ? n.substring(dot).toLowerCase() : "";
                            return parsersByExtension.containsKey(ext);
                        })
                        .sorted(Comparator.comparing(p -> p.getFileName().toString()))
                        .toList();
            }
            for (Path file : files) {
                digest.update(file.getFileName().toString().getBytes(StandardCharsets.UTF_8));
                digest.update((byte) 0);
                digest.update(Files.readAllBytes(file));
                digest.update((byte) 0);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (Exception e) {
            throw new FeedParseException(RejectionCode.PARSE_IO_ERROR,
                    "cannot compute content hash for: " + directory, e);
        }
    }
}
