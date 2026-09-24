package com.github.xingjianluo.threatinteliocjava.web;

import com.github.xingjianluo.threatinteliocjava.model.IocIndicator;
import com.github.xingjianluo.threatinteliocjava.model.MatchVerdict;
import com.github.xingjianluo.threatinteliocjava.model.RefreshReport;
import com.github.xingjianluo.threatinteliocjava.service.AccessControlService;
import com.github.xingjianluo.threatinteliocjava.service.IntelRegistry;
import com.github.xingjianluo.threatinteliocjava.service.IntelSnapshot;
import com.github.xingjianluo.threatinteliocjava.service.MatcherService;
import com.github.xingjianluo.threatinteliocjava.service.RefreshService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * 对外接口：
 * GET  /api/match?value=&type=  匹配判定（X-Roles 仅审计，不影响判定）
 * GET  /api/indicators/{type}/{value} 指标明细（受限来源需 X-Roles 权限，否则 403）
 * POST /api/admin/refresh       手动刷新（串行，返回完整结论）
 * GET  /api/health              当前快照状态与上次刷新结论
 */
@RestController
@RequestMapping("/api")
public class IntelController {

    private final MatcherService matcher;
    private final RefreshService refreshService;
    private final AccessControlService accessControl;
    private final IntelRegistry registry;

    public IntelController(MatcherService matcher, RefreshService refreshService,
                           AccessControlService accessControl, IntelRegistry registry) {
        this.matcher = matcher;
        this.refreshService = refreshService;
        this.accessControl = accessControl;
        this.registry = registry;
    }

    @GetMapping("/match")
    public MatchVerdict match(@RequestParam("value") String value,
                              @RequestParam(value = "type", required = false) String type,
                              @RequestHeader(value = "X-Roles", required = false) String rolesHeader) {
        Set<String> roles = accessControl.parseRoles(rolesHeader);
        return matcher.match(value, type, roles);
    }

    @GetMapping("/indicators/{type}/{value:.+}")
    public ResponseEntity<IndicatorDetailResponse> indicatorDetail(
            @PathVariable("type") String type,
            @PathVariable("value") String value,
            @RequestHeader(value = "X-Roles", required = false) String rolesHeader) {
        Set<String> roles = accessControl.parseRoles(rolesHeader);
        IocIndicator indicator = matcher.detail(type, value, roles);
        boolean restricted = !indicator.requiredRoles().isEmpty();
        return ResponseEntity.ok(new IndicatorDetailResponse(
                indicator.type().name(),
                indicator.canonicalValue(),
                indicator.displayValue(),
                indicator.severity().name(),
                indicator.confidence(),
                indicator.description(),
                indicator.sources(),
                restricted,
                indicator.requiredRoles()));
    }

    @PostMapping("/admin/refresh")
    public RefreshReport refresh() {
        return refreshService.refresh();
    }

    @GetMapping("/health")
    public HealthResponse health() {
        Optional<IntelSnapshot> snapshot = registry.currentSnapshot();
        RefreshReport last = refreshService.lastReport();
        return new HealthResponse(
                snapshot.isPresent(),
                snapshot.map(s -> s.getBuiltAt().toString()).orElse(null),
                snapshot.map(IntelSnapshot::indicatorCount).orElse(0),
                snapshot.map(IntelSnapshot::suppressionCount).orElse(0),
                last == null ? "NEVER" : last.status());
    }

    /** 指标明细响应：受限明细在通过权限校验后才完整给出。 */
    public record IndicatorDetailResponse(
            String type,
            String canonicalValue,
            String displayValue,
            String severity,
            int confidence,
            String description,
            List<String> sources,
            boolean restricted,
            Set<String> requiredRoles
    ) {
    }

    public record HealthResponse(boolean loaded, String builtAt, int indicators, int suppressions,
                                 String lastRefreshStatus) {
    }
}
