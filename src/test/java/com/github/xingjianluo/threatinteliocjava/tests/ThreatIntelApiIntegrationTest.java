package com.github.xingjianluo.threatinteliocjava.tests;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 端到端 HTTP 测试（启动时从测试资源目录完成首装）。
 */
@SpringBootTest
@AutoConfigureMockMvc
class ThreatIntelApiIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Test
    void matchEndpointReturnsConsistentHitWithReasoning() throws Exception {
        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"type":"domain","value":"WWW.Evil.Example.COM","apiKey":"viewer-key"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("HIT"))
                .andExpect(jsonPath("$.matched").value(true))
                .andExpect(jsonPath("$.normalizedInput").value("www.evil.example.com"))
                .andExpect(jsonPath("$.reasons[0]").exists());
    }

    @Test
    void suppressionDecisionIsExposedInApi() throws Exception {
        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"type":"domain","value":"safe.example.com"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("SUPPRESSED"))
                .andExpect(jsonPath("$.matched").value(true))
                .andExpect(jsonPath("$.suppressed").value(true));
    }

    @Test
    void invalidInputIs400WithDistinguishableReasonCode() throws Exception {
        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"type":"ip","value":"not-an-ip"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_INDICATOR"))
                .andExpect(jsonPath("$.reasonCode").value("INVALID_VALUE"));

        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"type":"quantum-ioc","value":"x"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reasonCode").value("UNSUPPORTED_TYPE"));
    }

    @Test
    void restrictedDetailIs403ForViewerBut200ForAnalyst() throws Exception {
        mvc.perform(get("/api/v1/threat-intel/indicators")
                        .param("key", "DOMAIN:restricted.internal")
                        .header("X-API-Key", "viewer-key"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("ACCESS_DENIED"))
                .andExpect(jsonPath("$.source").value("vendorB"));

        mvc.perform(get("/api/v1/threat-intel/indicators")
                        .param("key", "DOMAIN:restricted.internal")
                        .header("X-API-Key", "analyst-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].value").value("restricted.internal"));

        mvc.perform(get("/api/v1/threat-intel/indicators")
                        .param("key", "DOMAIN:restricted.internal"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void anonymousMatchRedactsRestrictedKeysButKeepsHitDecision() throws Exception {
        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"type":"domain","value":"restricted.internal"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("HIT"))
                .andExpect(jsonPath("$.visibleMatchedKeys[0]").value("REDACTED[restricted source]"));

        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"type":"domain","value":"restricted.internal","apiKey":"analyst-key"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("HIT"))
                .andExpect(jsonPath("$.visibleMatchedKeys[0]").value("DOMAIN:restricted.internal"));
    }

    @Test
    void refreshEndpointEnforcesRoleAndReportsUnchanged() throws Exception {
        mvc.perform(post("/api/v1/threat-intel/refresh")
                        .header("X-API-Key", "viewer-key"))
                .andExpect(status().isForbidden());

        mvc.perform(post("/api/v1/threat-intel/refresh")
                        .header("X-API-Key", "analyst-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.outcome").value("APPLIED_UNCHANGED"));
    }

    @Test
    void statusEndpointReportsSnapshot() throws Exception {
        mvc.perform(get("/api/v1/threat-intel/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value(1))
                .andExpect(jsonPath("$.suppressionCount").value(2))
                .andExpect(jsonPath("$.restrictedSources[0]").value("vendorB"));
    }

    @Test
    void cidrContainmentAndObfuscationMatchEndToEnd() throws Exception {
        // 十进制八进制混淆写法等价 + CIDR 包含 + 白名单抑制
        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"value":"012.1.2.3"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("SUPPRESSED"));

        mvc.perform(post("/api/v1/threat-intel/match")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"value":"192.168.10.77"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("CLEAN"));
    }
}
