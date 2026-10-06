package com.github.xingjianluo.threatinteliocjava.tests;

import com.github.xingjianluo.threatinteliocjava.refresh.RefreshOutcome;
import com.github.xingjianluo.threatinteliocjava.refresh.RefreshPolicy;
import com.github.xingjianluo.threatinteliocjava.refresh.ThreatIntelService;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
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
 * 代际治理端到端测试：代际列表（含来源健康）、按代匹配、回滚与权限边界、
 * 已淘汰/未知代际的 404、状态中的最近刷新结论。
 *
 * <p>启动时首装为第 1 代（data/feeds）；本类再发布第 2 代
 * （含 正常 / 合法空 / 读取失败 三种来源）。方法按序执行，类结束后销毁上下文，
 * 不影响其他集成测试类。
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class GenerationApiIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ThreatIntelService service;

    @TempDir
    static Path sharedTemp;

    private static String gen2Dir;

    @Test
    @Order(1)
    void secondGenerationExposesSourceHealthViaApi() throws Exception {
        Path dir = sharedTemp.resolve("gen2");
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("good.jsonl"),
                "{\"type\":\"domain\",\"value\":\"gen2-only.example\"}\n");
        Files.writeString(dir.resolve("quiet.jsonl"), "");
        Files.writeString(dir.resolve("broken.csv"), "not-a-valid-header\n1,2\n");
        gen2Dir = dir.toString();

        RefreshOutcome outcome = service.refresh(gen2Dir,
                "src/test/resources/data/suppressions.jsonl",
                Set.of(), RefreshPolicy.ACCEPT_PARTIAL);
        assertEquals("APPLIED_PARTIAL", outcome.outcome());

        mvc.perform(get("/api/v1/threat-intel/generations"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(2))
                .andExpect(jsonPath("$[0].current").value(true))
                .andExpect(jsonPath("$[0].complete").value(false))
                .andExpect(jsonPath("$[0].sources[?(@.source=='good')].health")
                        .value("ADOPTED"))
                .andExpect(jsonPath("$[0].sources[?(@.source=='quiet')].health")
                        .value("SKIPPED_EMPTY"))
                .andExpect(jsonPath("$[0].sources[?(@.source=='broken')].health")
                        .value("SKIPPED_UNREADABLE"))
                .andExpect(jsonPath("$[1].id").value(1))
                .andExpect(jsonPath("$[1].current").value(false))
                .andExpect(jsonPath("$[1].complete").value(true));

        // 状态接口：最近刷新结论明确为"未完全成功"，而非一份合法空情报
        mvc.perform(get("/api/v1/threat-intel/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.currentGeneration").value(2))
                .andExpect(jsonPath("$.currentGenerationComplete").value(false))
                .andExpect(jsonPath("$.lastRefreshOutcome").value("APPLIED_PARTIAL"))
                .andExpect(jsonPath("$.lastRefreshSuccess").value(true))
                .andExpect(jsonPath("$.generationHistoryCapacity").value(5))
                .andExpect(jsonPath("$.retainedGenerations").value(2));
    }

    @Test
    @Order(2)
    void matchCanTargetLatestOrSpecificGeneration() throws Exception {
        // 最新一代（第 2 代）不含首装指标
        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"value\":\"evil.example.com\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("CLEAN"));
        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"value\":\"gen2-only.example\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("HIT"));
        // 指定第 1 代：看到历史结果
        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"value\":\"evil.example.com\",\"generation\":1}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("HIT"));
        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"value\":\"gen2-only.example\",\"generation\":1}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("CLEAN"));
        // 从未存在/已淘汰的代际 -> 404
        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"value\":\"evil.example.com\",\"generation\":99}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("GENERATION_NOT_FOUND"))
                .andExpect(jsonPath("$.generation").value(99));
    }

    @Test
    @Order(3)
    void rollbackEnforcesRoleAndAtomicallySwitchesCurrentGeneration() throws Exception {
        mvc.perform(post("/api/v1/threat-intel/rollback").param("generation", "1"))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/threat-intel/rollback")
                        .param("generation", "1")
                        .header("X-API-Key", "viewer-key"))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/threat-intel/rollback")
                        .param("generation", "99")
                        .header("X-API-Key", "analyst-key"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("GENERATION_NOT_FOUND"));

        mvc.perform(post("/api/v1/threat-intel/rollback")
                        .param("generation", "1")
                        .header("X-API-Key", "analyst-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.current").value(true));

        // 回滚后最新查询即为第 1 代结果
        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"value\":\"evil.example.com\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("HIT"));
        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"value\":\"gen2-only.example\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("CLEAN"));
        mvc.perform(get("/api/v1/threat-intel/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.currentGeneration").value(1));
    }
}
