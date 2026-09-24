package com.github.xingjianluo.threatinteliocjava.web;

import com.github.xingjianluo.threatinteliocjava.access.AccessControlService;
import com.github.xingjianluo.threatinteliocjava.access.Caller;
import com.github.xingjianluo.threatinteliocjava.config.ThreatIntelProperties;
import com.github.xingjianluo.threatinteliocjava.model.Indicator;
import com.github.xingjianluo.threatinteliocjava.model.Verdict;
import com.github.xingjianluo.threatinteliocjava.refresh.RefreshOutcome;
import com.github.xingjianluo.threatinteliocjava.refresh.RefreshPolicy;
import com.github.xingjianluo.threatinteliocjava.refresh.ThreatIntelService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Set;

/**
 * HTTP 接口：匹配查询、指标明细（受来源权限控制）、手动刷新、状态查看。
 */
@RestController
public class ThreatIntelController {

    private static final Logger log = LoggerFactory.getLogger(ThreatIntelController.class);

    private final ThreatIntelService service;
    private final AccessControlService accessControl;
    private final ThreatIntelProperties properties;

    public ThreatIntelController(ThreatIntelService service,
                                 AccessControlService accessControl,
                                 ThreatIntelProperties properties) {
        this.service = service;
        this.accessControl = accessControl;
        this.properties = properties;
    }

    /**
     * 匹配查询。命中/抑制/清洁结论对任何调用方一致；
     * 受限来源的命中 key 仅对有权限调用方可见，其余脱敏，但不改变 decision。
     */
    @PostMapping("/api/v1/threat-intel/match")
    public MatchResponse match(@RequestBody MatchRequest request) {
        if (request == null || request.value() == null || request.value().isBlank()) {
            throw new IllegalArgumentException("request body must contain non-blank 'value'");
        }
        Caller caller = accessControl.authenticate(request.apiKey());
        Verdict verdict = service.match(request.type(), request.value(), caller);
        List<String> visibleKeys = service.visibleKeys(verdict.matchedKeys(), caller);
        return MatchResponse.from(verdict, visibleKeys);
    }

    /**
     * 指标明细查询：受限来源对无权调用方返回 403。
     * 注意该接口与匹配判定分离，拒绝访问不影响匹配结论。
     */
    @GetMapping("/api/v1/threat-intel/indicators")
    public List<IndicatorView> lookup(@RequestParam String key,
                                      @RequestHeader(value = "X-API-Key", required = false) String apiKey) {
        Caller caller = accessControl.authenticate(apiKey);
        if (caller == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "valid X-API-Key required for indicator detail lookup");
        }
        List<Indicator> indicators = service.lookupIndicatorsByKey(key, caller);
        return indicators.stream().map(IndicatorView::from).toList();
    }

    /**
     * 手动刷新（默认仅 ANALYST/ADMIN；viewer-key 会被拒绝）。
     * 并发刷新的第二个请求得到 ALREADY_RUNNING。
     */
    @PostMapping("/api/v1/threat-intel/refresh")
    public RefreshOutcome refresh(@RequestParam(required = false) RefreshPolicy policy,
                                  @RequestHeader(value = "X-API-Key", required = false) String apiKey) {
        Caller caller = accessControl.authenticate(apiKey);
        if (caller == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "valid X-API-Key required for refresh");
        }
        if (caller.role().name().equals("RESTRICTED_VIEWER")) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "RESTRICTED_VIEWER may not trigger refresh");
        }
        RefreshPolicy effective = policy != null ? policy : properties.getRefreshPolicy();
        log.info("manual refresh requested by caller={} policy={}", caller.id(), effective);
        return service.refresh(properties.getFeedDirectory(),
                properties.getSuppressionFile(),
                Set.copyOf(properties.getRestrictedSources()), effective);
    }

    @GetMapping("/api/v1/threat-intel/status")
    public StatusResponse status() {
        return StatusResponse.from(service.currentSnapshot(),
                List.copyOf(accessControl.restrictedSources()));
    }
}
