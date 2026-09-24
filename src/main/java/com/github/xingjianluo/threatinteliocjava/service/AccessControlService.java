package com.github.xingjianluo.threatinteliocjava.service;

import com.github.xingjianluo.threatinteliocjava.config.IntelProperties;
import com.github.xingjianluo.threatinteliocjava.model.IocIndicator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 本地角色访问控制：
 * <ul>
 *   <li>调用方角色来自请求头 X-Roles，逗号分隔，统一小写；缺省视为匿名（空集）。</li>
 *   <li>仅“受限来源”（intel.restricted-sources）产出的指标需要查看权限；
 *       所需角色由 intel.source-roles.&lt;feed名&gt; 配置，缺省为 "restricted-intel:reader"。</li>
 *   <li>一个指标收敛了多个来源时，只要其中任一受限来源要求的角色未满足即拒绝；
 *       该判定只作用于明细查询接口，不改变匹配命中本身。</li>
 * </ul>
 */
@Service
public class AccessControlService {

    private static final Logger log = LoggerFactory.getLogger(AccessControlService.class);

    /** 受限来源未显式配置角色时的默认所需角色。 */
    public static final String DEFAULT_RESTRICTED_ROLE = "restricted-intel:reader";

    private final List<String> restrictedSources;
    private final IntelProperties properties;

    public AccessControlService(IntelProperties properties) {
        this.properties = properties;
        this.restrictedSources = properties.restrictedSources().stream()
                .map(s -> s.toLowerCase(Locale.ROOT))
                .toList();
    }

    public Set<String> parseRoles(String headerValue) {
        if (headerValue == null || headerValue.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(headerValue.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> s.toLowerCase(Locale.ROOT))
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /** 该指标明细所需的全部角色：来自其受限来源的并集；无受限来源时为空集。 */
    public Set<String> requiredRolesFor(IocIndicator indicator) {
        Set<String> required = new LinkedHashSet<>();
        for (String source : indicator.sources()) {
            if (restrictedSources.contains(source.toLowerCase(Locale.ROOT))) {
                String configured = properties.sourceRoles().get(source);
                if (configured == null) {
                    configured = properties.sourceRoles().get(source.toLowerCase(Locale.ROOT));
                }
                if (configured == null || configured.isBlank()) {
                    required.add(DEFAULT_RESTRICTED_ROLE);
                } else {
                    Arrays.stream(configured.split(","))
                            .map(String::trim)
                            .filter(s -> !s.isEmpty())
                            .forEach(required::add);
                }
            }
        }
        return required;
    }

    /** 校验明细访问权限，不足抛 {@link AccessDeniedException}。 */
    public void checkDetailAccess(IocIndicator indicator, Set<String> callerRoles) {
        Set<String> required = requiredRolesFor(indicator);
        if (required.isEmpty()) {
            return;
        }
        if (!callerRoles.containsAll(required)) {
            log.warn("访问被拒绝: indicator={}/{} 需要角色={} 调用方角色={}",
                    indicator.type(), indicator.canonicalValue(), required, callerRoles);
            throw new AccessDeniedException(
                    "权限不足：该指标来源于受限来源，需要角色 " + required
                            + "，调用方角色 " + callerRoles);
        }
    }
}
