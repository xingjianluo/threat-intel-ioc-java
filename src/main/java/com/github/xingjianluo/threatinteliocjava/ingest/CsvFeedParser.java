package com.github.xingjianluo.threatinteliocjava.ingest;

import com.github.xingjianluo.threatinteliocjava.model.RejectedEntry;
import com.github.xingjianluo.threatinteliocjava.model.RejectionCode;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 简易 CSV 格式解析器。
 * <ul>
 *   <li>首行必须为表头，至少包含 type,value 两列（severity 可选，顺序任意）。</li>
 *   <li># 开头为注释，空行忽略；字段支持双引号包裹与 "" 转义。</li>
 *   <li>列数与表头不一致、引号未闭合等逐行问题按 MALFORMED_FORMAT 拒绝。</li>
 *   <li>缺失表头为文件级结构错误，抛 {@link FeedParseException}。</li>
 * </ul>
 */
@Component
public class CsvFeedParser implements FeedParser {

    @Override
    public String supportedExtension() {
        return ".csv";
    }

    @Override
    public ParsedBatch parse(String content) {
        String[] lines = content.split("\n", -1);
        int idx = 0;
        String[] header = null;
        while (idx < lines.length) {
            String t = lines[idx].trim();
            if (t.isEmpty() || t.startsWith("#")) {
                idx++;
                continue;
            }
            try {
                header = parseCsvLine(lines[idx]);
            } catch (IllegalArgumentException e) {
                throw new FeedParseException(RejectionCode.MALFORMED_FORMAT,
                        "unreadable CSV header on line " + (idx + 1) + ": " + e.getMessage());
            }
            idx++;
            break;
        }
        if (header == null) {
            throw new FeedParseException(RejectionCode.MALFORMED_FORMAT,
                    "CSV file has no header row; expected columns including 'type' and 'value'");
        }
        int typeCol = -1;
        int valueCol = -1;
        int severityCol = -1;
        for (int c = 0; c < header.length; c++) {
            String name = header[c].trim().toLowerCase(Locale.ROOT);
            switch (name) {
                case "type" -> typeCol = c;
                case "value" -> valueCol = c;
                case "severity" -> severityCol = c;
                default -> { }
            }
        }
        if (typeCol < 0 || valueCol < 0) {
            throw new FeedParseException(RejectionCode.MALFORMED_FORMAT,
                    "CSV header must contain 'type' and 'value' columns, got: "
                            + String.join(",", header));
        }

        List<RawEntry> entries = new ArrayList<>();
        List<RejectedEntry> rejected = new ArrayList<>();
        for (int i = idx; i < lines.length; i++) {
            int lineNo = i + 1;
            String raw = lines[i];
            String trimmed = raw.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            String[] fields;
            try {
                fields = parseCsvLine(raw);
            } catch (IllegalArgumentException e) {
                rejected.add(new RejectedEntry(null, "L" + lineNo + ": " + trim(trimmed),
                        RejectionCode.MALFORMED_FORMAT, "malformed CSV quoting: " + e.getMessage()));
                continue;
            }
            int expected = header.length;
            if (fields.length != expected) {
                rejected.add(new RejectedEntry(null, "L" + lineNo + ": " + trim(trimmed),
                        RejectionCode.MALFORMED_FORMAT,
                        "expected " + expected + " columns but found " + fields.length));
                continue;
            }
            String type = fields[typeCol].trim();
            String value = fields[valueCol].trim();
            String severity = severityCol >= 0 ? fields[severityCol].trim() : null;
            if (type.isEmpty() || value.isEmpty()) {
                rejected.add(new RejectedEntry(null, "L" + lineNo + ": " + trim(trimmed),
                        RejectionCode.MALFORMED_FORMAT, "type/value must not be blank"));
                continue;
            }
            entries.add(new RawEntry(lineNo, type, value,
                    severity == null || severity.isEmpty() ? null : severity));
        }
        return new ParsedBatch(List.copyOf(entries), List.copyOf(rejected));
    }

    /** 支持双引号引用字段与 "" 转义的最小 CSV 行解析。 */
    static String[] parseCsvLine(String line) {
        List<String> out = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char ch = line.charAt(i);
            if (inQuotes) {
                if (ch == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        field.append('"');
                        i++;
                    } else {
                        inQuotes = false;
                    }
                } else {
                    field.append(ch);
                }
            } else {
                if (ch == '"') {
                    inQuotes = true;
                } else if (ch == ',') {
                    out.add(field.toString());
                    field.setLength(0);
                } else {
                    field.append(ch);
                }
            }
        }
        if (inQuotes) {
            throw new IllegalArgumentException("unterminated quoted field");
        }
        out.add(field.toString());
        return out.toArray(String[]::new);
    }

    private String trim(String s) {
        return s.length() > 200 ? s.substring(0, 200) + "..." : s;
    }
}
