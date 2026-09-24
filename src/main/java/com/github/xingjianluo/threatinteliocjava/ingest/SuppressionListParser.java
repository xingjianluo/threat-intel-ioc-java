package com.github.xingjianluo.threatinteliocjava.ingest;

import com.github.xingjianluo.threatinteliocjava.model.ImportRejection;
import com.github.xingjianluo.threatinteliocjava.model.RejectionReason;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 抑制/白名单格式：文件名约定为 suppressions.csv，
 * 表头列：id,type,value,reason（reason 可空）。抑制规则与指标使用同一套归一语义，
 * 且匹配时优先级高于命中。规则本身不合法（列数不符/缺字段）按
 * MALFORMED_SUPPRESSION_RULE 逐条拒绝。
 */
@Component
public class SuppressionListParser implements IntelSourceParser {

    private static final Logger log = LoggerFactory.getLogger(SuppressionListParser.class);

    @Override
    public boolean supports(String fileName) {
        return fileName != null && fileName.equalsIgnoreCase("suppressions.csv");
    }

    @Override
    public ParseResult parse(Path file) {
        String name = file.getFileName().toString();
        List<RawSuppression> suppressions = new ArrayList<>();
        List<ImportRejection> rejections = new ArrayList<>();
        try (BufferedReader reader = Files.newBufferedReader(file)) {
            String headerLine;
            do {
                headerLine = reader.readLine();
            } while (headerLine != null
                    && (headerLine.isBlank() || headerLine.stripLeading().startsWith("#")));
            if (headerLine == null) {
                return new ParseResult(name, List.of(), suppressions, rejections,
                        "suppressions.csv 为空文件");
            }
            List<String> header = CsvIntelParser.splitCsv(headerLine);
            if (header == null) {
                return new ParseResult(name, List.of(), suppressions, rejections,
                        "suppressions.csv 表头引号未闭合");
            }
            Map<String, Integer> columns = new LinkedHashMap<>();
            for (int i = 0; i < header.size(); i++) {
                columns.put(header.get(i).trim().toLowerCase(), i);
            }
            Integer idCol = columns.get("id");
            Integer typeCol = columns.get("type");
            Integer valueCol = columns.get("value");
            if (idCol == null || typeCol == null || valueCol == null) {
                return new ParseResult(name, List.of(), suppressions, rejections,
                        "suppressions.csv 表头必须包含 id,type,value 列");
            }
            int lineNo = 1;
            String rawLine;
            while ((rawLine = reader.readLine()) != null) {
                lineNo++;
                String trimmed = rawLine.stripLeading();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                List<String> fields = CsvIntelParser.splitCsv(rawLine);
                if (fields == null) {
                    rejections.add(new ImportRejection(name, lineNo, rawLine,
                            RejectionReason.MALFORMED_SUPPRESSION_RULE, "引号未闭合"));
                    continue;
                }
                if (fields.size() != header.size()) {
                    rejections.add(new ImportRejection(name, lineNo, rawLine,
                            RejectionReason.MALFORMED_SUPPRESSION_RULE,
                            "列数 " + fields.size() + " 与表头列数 " + header.size() + " 不一致"));
                    continue;
                }
                String id = fields.get(idCol);
                String type = fields.get(typeCol);
                String value = fields.get(valueCol);
                if (id == null || id.isBlank() || type == null || type.isBlank()
                        || value == null || value.isBlank()) {
                    rejections.add(new ImportRejection(name, lineNo, rawLine,
                            RejectionReason.MALFORMED_SUPPRESSION_RULE,
                            "缺少必填字段 id/type/value"));
                    continue;
                }
                Integer reasonCol = columns.get("reason");
                String reason = reasonCol == null ? null : fields.get(reasonCol);
                suppressions.add(new RawSuppression(name, lineNo, id.trim(), type.trim(),
                        value.trim(), (reason == null || reason.isBlank()) ? null : reason.trim()));
            }
        } catch (IOException e) {
            log.warn("抑制列表读取失败（致命）: {} - {}", name, e.getMessage());
            return new ParseResult(name, List.of(), suppressions, rejections,
                    "suppressions.csv 读取失败: " + e.getMessage());
        }
        log.info("抑制列表解析完成: {} 规则={} 拒绝={}", name, suppressions.size(),
                rejections.size());
        return new ParseResult(name, List.of(), suppressions, rejections, null);
    }
}
