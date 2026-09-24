package com.github.xingjianluo.threatinteliocjava.access;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Set;

/**
 * 访问控制：受限来源的指标明细仅 ANALYST/ADMIN 可见。
 *
 * <p>边界说明：该服务只控制"指标明细查询"。匹配命中判定
 * （HIT/SUPPRESSED/CLEAN 与判定依据）对任何调用方都一致，
 * 无权限只会让明细 key 被脱敏，绝不改变命中本身。
 */
@Service
public class AccessControlService {

    private static final Logger log = LoggerFactory.getLogger(AccessControlService.class);

    private final CallerDirectory directory;
    private volatile Set<String> restrictedSources = Set.of();

    public AccessControlService(CallerDirectory directory) {
        this.directory = directory;
    }

    /** 设置受限来源集合（由快照刷新同步更新）。 */
    public void updateRestrictedSources(Set<String> sources) {
        this.restrictedSources = Set.copyOf(sources);
        log.info("restricted sources updated: {}", this.restrictedSources);
    }

    public boolean isRestricted(String source) {
        return restrictedSources.contains(source);
    }

    public Set<String> restrictedSources() {
        return restrictedSources;
    }

    /** 解析调用方；未知/缺失 apiKey 返回 null（匿名）。 */
    public Caller authenticate(String apiKey) {
        return directory.resolve(apiKey);
    }

    /**
     * 校验调用方是否可见该来源的指标明细；不通过抛 {@link AccessDeniedException}。
     * 匿名调用方对受限来源一律拒绝。
     */
    public void checkIndicatorDetail(Caller caller, String source) {
        if (!restrictedSources.contains(source)) {
            return;
        }
        if (caller == null || caller.role() == Role.RESTRICTED_VIEWER) {
            log.warn("access denied: caller={} attempted restricted source={}",
                    caller == null ? "<anonymous>" : caller.id(), source);
            throw new AccessDeniedException(caller == null ? "<anonymous>" : caller.id(), source);
        }
    }
}
