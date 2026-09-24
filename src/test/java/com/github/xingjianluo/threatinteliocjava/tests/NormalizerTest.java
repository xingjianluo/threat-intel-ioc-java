package com.github.xingjianluo.threatinteliocjava.tests;

import com.github.xingjianluo.threatinteliocjava.model.IndicatorType;
import com.github.xingjianluo.threatinteliocjava.model.RejectionCode;
import com.github.xingjianluo.threatinteliocjava.normalize.NormalizationException;
import com.github.xingjianluo.threatinteliocjava.normalize.Normalizer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 归一化等价规则单元测试：大小写、混淆写法、域名根点/通配、URL 默认端口等。
 */
class NormalizerTest {

    private final Normalizer normalizer = new Normalizer();

    @Test
    void ipv4EquivalentObfuscationsConverge() {
        String canonical = normalizer.normalizeValue(IndicatorType.IPV4, "192.168.10.10");
        assertEquals("192.168.10.10", canonical);
        // 十六进制首段 + 八进制其余段，全部等价于 192.168.10.10
        assertEquals(canonical, normalizer.normalizeValue(IndicatorType.IPV4, "0xC0.0250.012.012"));
        // 32 位整数（十进制与 0x）
        assertEquals(canonical, normalizer.normalizeValue(IndicatorType.IPV4, "3232238090"));
        assertEquals(canonical, normalizer.normalizeValue(IndicatorType.IPV4, "0xC0A80A0A"));
        // 末尾端口与方括号
        assertEquals(canonical, normalizer.normalizeValue(IndicatorType.IPV4, "[192.168.10.10]:443"));
        // 多段位宽写法
        assertEquals(canonical, normalizer.normalizeValue(IndicatorType.IPV4, "192.168.2570"));
        assertEquals(canonical, normalizer.normalizeValue(IndicatorType.IPV4, "192.11012618"));
    }

    @Test
    void ipv4CidrHostBitsAreZeroed() {
        assertEquals("10.0.0.0/8", normalizer.normalizeValue(IndicatorType.IPV4, "10.5.6.7/8"));
        assertEquals("192.168.0.0/16", normalizer.normalizeValue(IndicatorType.IPV4, "192.168.20.30/16"));
        NormalizationException ex = assertThrows(NormalizationException.class,
                () -> normalizer.normalizeValue(IndicatorType.IPV4, "10.0.0.0/33"));
        assertEquals(RejectionCode.INVALID_VALUE, ex.code());
    }

    @Test
    void invalidIpv4RejectedWithReason() {
        NormalizationException ex = assertThrows(NormalizationException.class,
                () -> normalizer.normalizeValue(IndicatorType.IPV4, "not-an-ip"));
        assertEquals(RejectionCode.INVALID_VALUE, ex.code());
    }

    @Test
    void domainVariantsConvergeAndSubdomainRulesHold() {
        assertEquals("evil.example.com",
                normalizer.normalizeValue(IndicatorType.DOMAIN, "Evil.Example.COM."));
        assertEquals("cdn-bad.net",
                normalizer.normalizeValue(IndicatorType.DOMAIN, "*.CDN-Bad.NET"));
        assertTrue(normalizer.isSubDomainOrSame("a.b.evil.com", "evil.com"));
        assertTrue(normalizer.isSubDomainOrSame("evil.com", "evil.com"));
        assertFalse(normalizer.isSubDomainOrSame("notevil.com", "evil.com"));
        // 看起来像 IP 的值不能被当作域名
        assertThrows(NormalizationException.class,
                () -> normalizer.normalizeValue(IndicatorType.DOMAIN, "1.2.3.4"));
    }

    @Test
    void urlNormalizesSchemeHostDefaultPort() {
        assertEquals("http://bad.example.com/a?b=1",
                normalizer.normalizeValue(IndicatorType.URL, "HTTP://Bad.Example.COM:80/a?b=1#frag"));
        assertEquals("bad.example.com",
                normalizer.hostOfUrl("http://bad.example.com/a"));
        // 保留非默认端口
        assertEquals("http://bad.example.com:8080/",
                normalizer.normalizeValue(IndicatorType.URL, "bad.example.com:8080/"));
        assertThrows(NormalizationException.class,
                () -> normalizer.normalizeValue(IndicatorType.URL, "ftp://x/y"));
    }

    @Test
    void hashesAndEmailNormalizedAndTyped() {
        assertEquals("abcd1234abcd1234abcd1234abcd1234",
                normalizer.normalizeValue(IndicatorType.HASH_MD5, "ABCD1234ABCD1234ABCD1234ABCD1234"));
        assertThrows(NormalizationException.class,
                () -> normalizer.normalizeValue(IndicatorType.HASH_MD5, "zz"));
        assertEquals("phish@baddie.example",
                normalizer.normalizeValue(IndicatorType.EMAIL, " Phish@Baddie.example "));
    }

    @Test
    void unsupportedTypeIsDistinguishable() {
        NormalizationException ex = assertThrows(NormalizationException.class,
                () -> normalizer.normalizeType("quantum-ioc"));
        assertEquals(RejectionCode.UNSUPPORTED_TYPE, ex.code());
    }

    @Test
    void typeInferenceIsDeterministic() {
        assertEquals(IndicatorType.DOMAIN, normalizer.inferType("sub.Example.com"));
        assertEquals(IndicatorType.IPV4, normalizer.inferType("10.0.0.1"));
        assertEquals(IndicatorType.URL, normalizer.inferType("https://x.example/p"));
        assertEquals(IndicatorType.HASH_MD5,
                normalizer.inferType("abcd1234abcd1234abcd1234abcd1234"));
    }
}
