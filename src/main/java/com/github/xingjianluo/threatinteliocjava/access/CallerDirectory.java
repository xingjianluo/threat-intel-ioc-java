package com.github.xingjianluo.threatinteliocjava.access;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.threatinteliocjava.source.LocalFeedRepository;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 本地调用方目录：apiKey -> Caller 映射。优先从本地 JSON 文件装载；
 * 文件缺失时回退到内置演示目录，全程不依赖任何外部身份服务或真实凭据体系。
 *
 * <p>文件格式：{@code [{"id":"analyst-1","role":"ANALYST","apiKey":"analyst-key"}, ...]}
 */
@Component
public class CallerDirectory {

    private static final Logger log = LoggerFactory.getLogger(CallerDirectory.class);

    /** 内置演示目录（仅用于本地验证，非真实凭据）。 */
    static final String FALLBACK_JSON = """
            [
              {"id":"admin-1",     "role":"ADMIN",             "apiKey":"admin-key"},
              {"id":"analyst-1",   "role":"ANALYST",           "apiKey":"analyst-key"},
              {"id":"viewer-1",    "role":"RESTRICTED_VIEWER", "apiKey":"viewer-key"}
            ]
            """;

    private final LocalFeedRepository repository;
    private final ObjectMapper mapper = new ObjectMapper();
    private volatile Map<String, Caller> byApiKey = Map.of();

    public CallerDirectory(LocalFeedRepository repository) {
        this.repository = repository;
    }

    @PostConstruct
    void initFallback() {
        loadBuiltinFallback();
    }

    /** 装载内置演示目录（测试手工装配时也可显式调用）。 */
    public void loadBuiltinFallback() {
        try {
            applyJson(FALLBACK_JSON, "built-in fallback directory");
        } catch (Exception e) {
            log.error("failed to load built-in caller directory", e);
        }
    }

    /** 从本地文件装载；文件不存在时保留内置默认目录。 */
    public void load(String filePath) {
        String json = repository.readTextFile(filePath);
        if (json == null) {
            log.warn("caller file not found, keeping built-in directory: {}", filePath);
            return;
        }
        applyJson(json, filePath);
    }

    private synchronized void applyJson(String json, String origin) {
        Map<String, Caller> loaded = new LinkedHashMap<>();
        try {
            JsonNode root = mapper.readTree(json);
            if (root == null || !root.isArray()) {
                throw new IllegalArgumentException("caller directory must be a JSON array");
            }
            for (JsonNode node : root) {
                String id = requireText(node, "id");
                String roleText = requireText(node, "role");
                String apiKey = requireText(node, "apiKey");
                Role role;
                try {
                    role = Role.valueOf(roleText.trim().toUpperCase());
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("unknown role '" + roleText + "' for caller " + id);
                }
                if (loaded.putIfAbsent(apiKey, new Caller(id, role)) != null) {
                    throw new IllegalArgumentException("duplicate apiKey in caller directory");
                }
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid caller directory JSON in " + origin
                    + ": " + e.getMessage(), e);
        }
        byApiKey = Map.copyOf(loaded);
        log.info("loaded {} callers from {}", loaded.size(), origin);
    }

    private String requireText(JsonNode node, String name) {
        JsonNode field = node.get(name);
        if (field == null || !field.isTextual() || field.asText().isBlank()) {
            throw new IllegalArgumentException("missing/non-string field '" + name + "'");
        }
        return field.asText();
    }

    /** 按 apiKey 解析调用方；未知 key 返回 null（调用方据此拒绝或按匿名处理）。 */
    public Caller resolve(String apiKey) {
        if (apiKey == null || apiKey.isBlank()) {
            return null;
        }
        return byApiKey.get(apiKey);
    }
}
