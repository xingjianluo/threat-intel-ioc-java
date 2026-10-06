package com.github.xingjianluo.threatinteliocjava.web;

import com.github.xingjianluo.threatinteliocjava.model.Verdict;

import java.util.List;

/**
 * 匹配响应：命中结论对所有调用方一致；受限来源明细做脱敏，不暴露给无权调用方。
 * covered/coveringRuleIds 解释"被规则圈住"的范围，与是否真实命中相互独立。
 */
public record MatchResponse(
        String input,
        String normalizedInput,
        String decision,
        boolean matched,
        boolean suppressed,
        boolean covered,
        List<String> coveringRuleIds,
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
                verdict.coveringRuleIds(),
                verdict.reasons(),
                visibleKeys);
    }
}
