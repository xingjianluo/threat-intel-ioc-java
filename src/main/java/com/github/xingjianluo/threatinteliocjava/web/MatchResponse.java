package com.github.xingjianluo.threatinteliocjava.web;

import com.github.xingjianluo.threatinteliocjava.model.Verdict;

import java.util.List;

/**
 * 匹配响应：命中结论对所有调用方一致；受限来源明细做脱敏，不暴露给无权调用方。
 */
public record MatchResponse(
        String input,
        String normalizedInput,
        String decision,
        boolean matched,
        boolean suppressed,
        List<String> reasons,
        List<String> visibleMatchedKeys) {

    public static MatchResponse from(Verdict verdict, List<String> visibleKeys) {
        return new MatchResponse(
                verdict.input(),
                verdict.normalizedInput(),
                verdict.decision(),
                verdict.matched(),
                verdict.suppressed(),
                verdict.reasons(),
                visibleKeys);
    }
}
