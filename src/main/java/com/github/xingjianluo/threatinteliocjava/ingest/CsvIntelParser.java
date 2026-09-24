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
 * 第二种本地情报格式：带表头 CSV。
 * 必需列：type,value；可选列：severity,confidence,description。
 * 支持双引号包裹与 "" 转义；空行与 # 注释行跳过；列数与表头不符的行按
 * MALFORMED_LINE 逐条拒绝，引号未闭合同理。
 */
@Component
public class CsvIntelParser implements IntelSourceParser {

    private static final Logger log = LoggerFactory.getLogger(CsvIntelParser.class);

    @Override
    public boolean supports(String fileName) {
        if (fileName == null) {
            return false;
        }
        String n = fileName.toLowerCase();
        return n.endsWith(".csv") && !n.equals("suppressions.csv");
    }

    @Override
    public ParseResult parse(Path file) {
        String name = file.getFileName().toString();
        List<RawIndicator> indicators = new ArrayList<>();
        List<ImportRejection> rejections = new ArrayList<>();
        try (BufferedReader reader = Files.newBufferedReader(file)) {
            String headerLine;
            do {
                headerLine = reader.readLine();
            } while (headerLine != null
                    && (headerLine.isBlank() || headerLine.stripLeading().startsWith("#")));
            if (headerLine == null) {
                return new ParseResult(name, indicators, List.of(), rejections, "CSV 为空文件");
            }
            List<String> header = splitCsv(headerLine);
            if (header == null) {
                return new ParseResult(name, indicators, List.of(), rejections,
                        "CSV 表头引号未闭合");
            }
            Map<String, Integer> columns = new LinkedHashMap<>();
            for (int i = 0; i < header.size(); i++) {
                columns.put(header.get(i).trim().toLowerCase(), i);
            }
            Integer typeCol = columns.get("type");
            Integer valueCol = columns.get("value");
            if (typeCol == null || valueCol == null) {
                return new ParseResult(name, indicators, List.of(), rejections,
                        "CSV 表头必须包含 type 与 value 列");
            }
            int lineNo = 1;
            String rawLine;
            while ((rawLine = reader.readLine()) != null) {
                lineNo++;
                String trimmed = rawLine.stripLeading();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                List<String> fields = splitCsv(rawLine);
                if (fields == null) {
                    rejections.add(new ImportRejection(name, lineNo, rawLine,
                            RejectionReason.MALFORMED_LINE, "CSV 行引号未闭合"));
                    continue;
                }
                if (fields.size() != header.size()) {
                    rejections.add(new ImportRejection(name, lineNo, rawLine,
                            RejectionReason.MALFORMED_LINE,
                            "列数 " + fields.size() + " 与表头列数 " + header.size() + " 不一致"));
                    continue;
                }
                String type = fields.get(typeCol);
                String value = fields.get(valueCol);
                if (type == null || type.isBlank()) {
                    rejections.add(new ImportRejection(name, lineNo, rawLine,
                            RejectionReason.MISSING_REQUIRED_FIELD, "缺少 type"));
                    continue;
                }
                if (value == null || value.isBlank()) {
                    rejections.add(new ImportRejection(name, lineNo, rawLine,
                            RejectionReason.MISSING_REQUIRED_FIELD, "缺少 value"));
                    continue;
                }
                indicators.add(new RawIndicator(name, lineNo, type.trim(), value.trim(),
                        column(fields, columns, "severity"),
                        column(fields, columns, "confidence"),
                        column(fields, columns, "description")));
            }
        } catch (IOException e) {
            log.warn("CSV 情报文件读取失败（致命）: {} - {}", name, e.getMessage());
            return new ParseResult(name, indicators, List.of(), rejections,
                    "CSV 读取失败: " + e.getMessage());
        }
        log.info("CSV 解析完成: {} 指标={} 拒绝={}", name, indicators.size(), rejections.size());
        return new ParseResult(name, indicators, List.of(), rejections, null);
    }

    private String column(List<String> fields, Map<String, Integer> columns, String key) {
        Integer idx = columns.get(key);
        if (idx == null) {
            return null;
        }
        String v = fields.get(idx);
        return (v == null || v.isBlank()) ? null : v.trim();
    }

    /**
     * 按行拆分 CSV（不支持跨行引号字段）；引号未闭合返回 null。
     */
    static List<String> splitCsv(String line) {
        List<String> out = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (inQuotes) {
                if (c == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        field.append('"');
                        i++;
                    } else {
                        inQuotes = false;
                    }
                } else {
                    field.append(c);
                }
            } else if (c == '"') {
                inQuotes = true;
            } else if (c == ',') {
                out.add(field.toString());
                field.setLength(0);
            } else {
                field.append(c);
            }
        }
        if (inQuotes) {
            return null;
        }
        out.add(field.toString());
        return out;
    }
}
