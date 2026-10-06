package com.github.xingjianluo.threatinteliocjava.tests;

import com.github.xingjianluo.threatinteliocjava.config.ThreatIntelProperties;
import com.github.xingjianluo.threatinteliocjava.refresh.RefreshPolicy;
import com.github.xingjianluo.threatinteliocjava.refresh.ThreatIntelService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 代际 / 回滚 / 覆盖解释的端到端 HTTP 测试。
 * 本类会把共享应用上下文推进到 v2 并回滚，因此标记 AFTER_CLASS 重建上下文，
 * 不影响其他集成测试对初始状态的假设。
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class GenerationApiIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ThreatIntelService service;

    @Autowired
    private ThreatIntelProperties properties;

    @TempDir
    Path tempDir;

    /** 把服务推进到 v2（内容不同的临时目录），返回 v2 版本号。 */
    private long advanceToV2() throws Exception {
        Path dir = Files.createDirectory(tempDir.resolve("gen2"));
        Files.writeString(dir.resolve("gen2feed.jsonl"),
                "{\"type\":\"domain\",\"value\":\"gen2-evil.example\",\"severity\":\"high\"}\n");
        var outcome = service.refresh(dir.toString(), properties.getSuppressionFile(),
                Set.copyOf(properties.getRestrictedSources()), RefreshPolicy.FAIL_CLOSED);
        assertEquals("APPLIED", outcome.outcome());
        assertEquals(2, outcome.version());
        return outcome.version();
    }

    @Test
    @DirtiesContext(methodMode = DirtiesContext.MethodMode.AFTER_METHOD)
    void generationsEndpointListsActiveAndHistoricalGenerationsWithHealth() throws Exception {
        advanceToV2();
        mvc.perform(get("/api/v1/threat-intel/generations"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].version").value(1))
                .andExpect(jsonPath("$[0].active").value(false))
                .andExpect(jsonPath("$[0].sourceHealth[0].status").value("ADOPTED"))
                .andExpect(jsonPath("$[1].version").value(2))
                .andExpect(jsonPath("$[1].active").value(true))
                .andExpect(jsonPath("$[1].sourceHealth[0].source").value("gen2feed"));
    }

    @Test
    @DirtiesContext(methodMode = DirtiesContext.MethodMode.AFTER_METHOD)
    void matchCanQuerySpecificGenerationViaApi() throws Exception {
        advanceToV2();
        // 默认看最新一代：v1 的指标在 v2 不存在
        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"type\":\"domain\",\"value\":\"evil.example.com\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("CLEAN"));
        // 指定 v1：同一输入命中
        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"type\":\"domain\",\"value\":\"evil.example.com\",\"generation\":1}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("HIT"));
        // 不存在的代：404 且原因可区分
        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"value\":\"evil.example.com\",\"generation\":99}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("GENERATION_UNAVAILABLE"))
                .andExpect(jsonPath("$.reason").value("GENERATION_NOT_FOUND"));
    }

    @Test
    @DirtiesContext(methodMode = DirtiesContext.MethodMode.AFTER_METHOD)
    void rollbackEndpointSwapsActiveGenerationWithRoleEnforcement() throws Exception {
        advanceToV2();
        // 匿名 401、viewer 403
        mvc.perform(post("/api/v1/threat-intel/rollback").param("version", "1"))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/threat-intel/rollback").param("version", "1")
                        .header("X-API-Key", "viewer-key"))
                .andExpect(status().isForbidden());
        // analyst 回滚到 v1
        mvc.perform(post("/api/v1/threat-intel/rollback").param("version", "1")
                        .header("X-API-Key", "analyst-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.outcome").value("ROLLED_BACK"))
                .andExpect(jsonPath("$.version").value(1));
        // 回滚后默认查询看到 v1 的完整内容
        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"type\":\"domain\",\"value\":\"evil.example.com\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("HIT"));
        // 被淘汰/不存在的代不可回滚
        mvc.perform(post("/api/v1/threat-intel/rollback").param("version", "99")
                        .header("X-API-Key", "analyst-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.outcome").value("GENERATION_NOT_FOUND"));
    }

    @Test
    @DirtiesContext(methodMode = DirtiesContext.MethodMode.AFTER_METHOD)
    void coveredButNotMatchedIsExposedInApi() throws Exception {
        // 10.200.1.1 被 SUP-1002（10.0.0.0/8）圈住但无指标命中
        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"value\":\"10.200.1.1\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("COVERED"))
                .andExpect(jsonPath("$.matched").value(false))
                .andExpect(jsonPath("$.covered").value(true))
                .andExpect(jsonPath("$.coveringRuleIds[0]").value("SUP-1002"));
        // 无权调用方看到完全一致的覆盖/命中判定
        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"value\":\"10.200.1.1\",\"apiKey\":\"viewer-key\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("COVERED"))
                .andExpect(jsonPath("$.matched").value(false));
    }
}
