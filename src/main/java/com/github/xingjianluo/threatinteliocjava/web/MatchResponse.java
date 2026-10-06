package com.github.xingjianluo.threatinteliocjava.web;

import com.github.xingjianluo.threatinteliocjava.model.Verdict;

import java.util.List;

/**
 * 匹配响应：命中/覆盖结论对所有调用方一致；受限来源明细做脱敏，不暴露给无权调用方。
 * covered 表示被抑制/白名单规则圈住但未命中任何指标（不是真正的命中）。
 */
public record MatchResponse(
        String input,
        String normalizedInput,
        String decision,
        boolean matched,
        boolean suppressed,
        boolean covered,
        List<String> reasons,
        List<String> visibleMatchedKeys) {

    public static MatchResponse from(Verdict verdict, List<String> visibleKeys) {
        return new MatchResponse(
                verdict.input(),
                verdict.normalizedInput(),
                verdict.decision(),
                verdict.matched(),
                verdict.suppressed(),
                verdict.covered(),
                verdict.reasons(),
                visibleKeys);
    }
}
