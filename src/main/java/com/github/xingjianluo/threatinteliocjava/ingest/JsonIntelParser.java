package com.github.xingjianluo.threatinteliocjava.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.threatinteliocjava.model.ImportRejection;
import com.github.xingjianluo.threatinteliocjava.model.RejectionReason;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * 第一种本地情报格式：JSON。
 * 顶层可以是指标数组，或形如 {"indicators":[...], "suppressions":[...]} 的对象。
 * JSON 整体无法解析属文件级致命错误（PARSE_ERROR）；单条字段缺失/类型不支持等
 * 属条目级错误，逐条拒绝并保留可区分原因，绝不静默丢弃。
 */
@Component
public class JsonIntelParser implements IntelSourceParser {

    private static final Logger log = LoggerFactory.getLogger(JsonIntelParser.class);

    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public boolean supports(String fileName) {
        return fileName != null && fileName.toLowerCase().endsWith(".json");
    }

    @Override
    public ParseResult parse(Path file) {
        String name = file.getFileName().toString();
        List<RawIndicator> indicators = new ArrayList<>();
        List<RawSuppression> suppressions = new ArrayList<>();
        List<ImportRejection> rejections = new ArrayList<>();

        JsonNode root;
        try {
            root = mapper.readTree(Files.newBufferedReader(file));
        } catch (IOException e) {
            log.warn("JSON 情报文件解析失败（致命）: {} - {}", name, e.getMessage());
            return new ParseResult(name, indicators, suppressions, rejections,
                    "JSON 解析失败: " + e.getMessage());
        }
        if (root == null || root.isNull()) {
            return new ParseResult(name, indicators, suppressions, rejections,
                    "JSON 顶层为空");
        }

        JsonNode indicatorNode;
        JsonNode suppressionNode = null;
        if (root.isArray()) {
            indicatorNode = root;
        } else if (root.isObject()) {
            indicatorNode = root.get("indicators");
            suppressionNode = root.get("suppressions");
        } else {
            return new ParseResult(name, indicators, suppressions, rejections,
                    "JSON 顶层必须是数组或对象");
        }
        if (indicatorNode == null || !indicatorNode.isArray()) {
            return new ParseResult(name, indicators, suppressions, rejections,
                    "JSON 缺少 indicators 数组");
        }
        int index = 0;
        for (JsonNode entry : indicatorNode) {
            index++;
            String raw = safeText(entry);
            if (!entry.isObject()) {
                rejections.add(new ImportRejection(name, index, raw,
                        RejectionReason.MALFORMED_LINE, "指标条目必须是 JSON 对象"));
                continue;
            }
            RawIndicator parsed = parseIndicator(name, index, entry, raw, rejections);
            if (parsed != null) {
                indicators.add(parsed);
            }
        }
        if (suppressionNode != null) {
            if (!suppressionNode.isArray()) {
                rejections.add(new ImportRejection(name, null, "<suppressions>",
                        RejectionReason.MALFORMED_SUPPRESSION_RULE,
                        "suppressions 必须是数组"));
            } else {
                int sIndex = 0;
                for (JsonNode entry : suppressionNode) {
                    sIndex++;
                    String raw = safeText(entry);
                    if (!entry.isObject()) {
                        rejections.add(new ImportRejection(name, sIndex, raw,
                                RejectionReason.MALFORMED_SUPPRESSION_RULE, "抑制规则必须是 JSON 对象"));
                        continue;
                    }
                    RawSuppression parsed = parseSuppression(name, sIndex, entry, raw, rejections);
                    if (parsed != null) {
                        suppressions.add(parsed);
                    }
                }
            }
        }
        log.info("JSON 解析完成: {} 指标={} 抑制={} 拒绝={}", name,
                indicators.size(), suppressions.size(), rejections.size());
        return new ParseResult(name, indicators, suppressions, rejections, null);
    }

    private RawIndicator parseIndicator(String file, int line, JsonNode node, String raw,
                                        List<ImportRejection> rejections) {
        String type = textOrNull(node.get("type"));
        String value = textOrNull(node.get("value"));
        if (type == null || type.isBlank()) {
            rejections.add(new ImportRejection(file, line, raw,
                    RejectionReason.MISSING_REQUIRED_FIELD, "缺少 type 字段"));
            return null;
        }
        if (value == null || value.isBlank()) {
            rejections.add(new ImportRejection(file, line, raw,
                    RejectionReason.MISSING_REQUIRED_FIELD, "缺少 value 字段"));
            return null;
        }
        return new RawIndicator(file, line, type.trim(), value.trim(),
                textOrNull(node.get("severity")),
                textOrNull(node.get("confidence")),
                textOrNull(node.get("description")));
    }

    private RawSuppression parseSuppression(String file, int line, JsonNode node, String raw,
                                            List<ImportRejection> rejections) {
        String id = textOrNull(node.get("id"));
        String type = textOrNull(node.get("type"));
        String value = textOrNull(node.get("value"));
        if (id == null || id.isBlank() || type == null || type.isBlank()
                || value == null || value.isBlank()) {
            rejections.add(new ImportRejection(file, line, raw,
                    RejectionReason.MALFORMED_SUPPRESSION_RULE,
                    "抑制规则缺少必填字段 id/type/value"));
            return null;
        }
        return new RawSuppression(file, line, id.trim(), type.trim(), value.trim(),
                textOrNull(node.get("reason")));
    }

    private String textOrNull(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        return node.isTextual() ? node.asText() : node.toString();
    }

    private String safeText(JsonNode node) {
        try {
            return mapper.writeValueAsString(node);
        } catch (Exception e) {
            return String.valueOf(node);
        }
    }
}
