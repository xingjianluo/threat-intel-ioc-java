package com.github.xingjianluo.threatinteliocjava.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.threatinteliocjava.model.RejectedEntry;
import com.github.xingjianluo.threatinteliocjava.model.RejectionCode;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * JSON Lines 格式解析器：每行一个 JSON 对象，字段 type/value/severity。
 * <ul>
 *   <li>空行/纯空白行：忽略。</li>
 *   <li>非 JSON 行或字段缺失/非字符串：按 MALFORMED_FORMAT 逐条拒绝。</li>
 * </ul>
 * 行级问题不使用异常，保证坏行带行号可区分地返回。
 */
@Component
public class JsonlFeedParser implements FeedParser {

    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public String supportedExtension() {
        return ".jsonl";
    }

    @Override
    public ParsedBatch parse(String content) {
        List<RawEntry> entries = new ArrayList<>();
        List<RejectedEntry> rejected = new ArrayList<>();
        String[] lines = content.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            int lineNo = i + 1;
            String line = lines[i].trim();
            if (line.isEmpty()) {
                continue;
            }
            try {
                JsonNode node = mapper.readTree(line);
                if (node == null || !node.isObject()) {
                    rejected.add(reject(lineNo, line, RejectionCode.MALFORMED_FORMAT,
                            "line is not a JSON object"));
                    continue;
                }
                String type = textField(node, "type");
                String value = textField(node, "value");
                if (type == null || value == null) {
                    rejected.add(reject(lineNo, line, RejectionCode.MALFORMED_FORMAT,
                            "missing required string fields 'type'/'value'"));
                    continue;
                }
                String severity = textField(node, "severity");
                entries.add(new RawEntry(lineNo, type, value, severity));
            } catch (Exception e) {
                rejected.add(reject(lineNo, line, RejectionCode.MALFORMED_FORMAT,
                        "invalid JSON: " + e.getMessage()));
            }
        }
        return new ParsedBatch(List.copyOf(entries), List.copyOf(rejected));
    }

    private String textField(JsonNode node, String name) {
        JsonNode field = node.get(name);
        if (field == null || field.isNull()) {
            return null;
        }
        if (!field.isTextual()) {
            throw new IllegalArgumentException("field '" + name + "' must be a string");
        }
        return field.asText();
    }

    private RejectedEntry reject(int lineNo, String line, RejectionCode code, String detail) {
        return new RejectedEntry(null, "L" + lineNo + ": " + truncate(line), code, detail);
    }

    private String truncate(String line) {
        return line.length() > 200 ? line.substring(0, 200) + "..." : line;
    }
}
