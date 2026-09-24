package com.github.xingjianluo.threatinteliocjava.tests;

import com.github.xingjianluo.threatinteliocjava.model.IndicatorType;
import com.github.xingjianluo.threatinteliocjava.normalize.Cidr;
import com.github.xingjianluo.threatinteliocjava.normalize.IocNormalizer;
import com.github.xingjianluo.threatinteliocjava.normalize.NormalizationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** 归一器等价规则单元测试。 */
class IocNormalizerTest {

    private final IocNormalizer normalizer = new IocNormalizer();

    @Test
    @DisplayName("IP: 十进制整数/十六进制整数/点分写法等价")
    void ipObfuscationsAreEquivalent() {
        String canonical = "1.2.3.4";
        assertEquals(canonical, normalizer.ip("1.2.3.4"));
        assertEquals(canonical, normalizer.ip("0x01020304"));
        assertEquals(canonical, normalizer.ip("16909060"));
        assertEquals(canonical, normalizer.ip("0x01020304"));
    }

    @Test
    @DisplayName("IPv6: 完整写法与压缩写法等价")
    void ipv6Compression() {
        assertEquals("2001:db8::1",
                normalizer.ip("2001:0db8:0000:0000:0000:0000:0000:0001"));
        assertEquals("::ffff:102:304", normalizer.ip("::ffff:1.2.3.4"));
    }

    @Test
    @DisplayName("主机名不能作为 IP，非法 IP 被拒绝")
    void ipRejectsHostnamesAndGarbage() {
        assertThrows(NormalizationException.class, () -> normalizer.ip("example.com"));
        assertThrows(NormalizationException.class, () -> normalizer.ip("999.0.0.1"));
        assertThrows(NormalizationException.class, () -> normalizer.ip(""));
        assertThrows(NormalizationException.class, () -> normalizer.ip("0x100000000"));
    }

    @Test
    @DisplayName("CIDR: 主机位清零后等价")
    void cidrHostBitsCleared() {
        assertEquals("192.168.1.0/24",
                normalizer.normalize(IndicatorType.CIDR, "192.168.1.77/24"));
        Cidr c = normalizer.cidr("10.0.0.0/8");
        assertTrue(c.contains("10.255.255.255"));
        assertFalse(c.contains("11.0.0.0"));
    }

    @Test
    @DisplayName("域名: 大小写/末尾点/IDN 等价")
    void domainEquivalence() {
        assertEquals("malware.example.com", normalizer.domain("MALWARE.Example.Com"));
        assertEquals("malware.example.com", normalizer.domain("malware.example.com."));
        assertEquals("xn--bcher-kva.example", normalizer.domain("bücher.example"));
        assertEquals("xn--bcher-kva.example", normalizer.domain("xn--bcher-kva.example"));
    }

    @Test
    @DisplayName("非法域名被拒绝，错误不静默")
    void invalidDomainsRejected() {
        assertThrows(NormalizationException.class, () -> normalizer.domain("ex..com"));
        assertThrows(NormalizationException.class, () -> normalizer.domain("-bad.com"));
        assertThrows(NormalizationException.class, () -> normalizer.domain("bad.c0m"));
    }

    @Test
    @DisplayName("URL: scheme/host 小写、默认端口、参数排序、去 fragment 等价")
    void urlEquivalence() {
        String canonical = "http://x.example.com/a?x=1&y=2";
        assertEquals(canonical, normalizer.url("HTTP://X.Example.COM:80/a?y=2&x=1#frag"));
        assertEquals(canonical, normalizer.url("http://x.example.com/a?x=1&y=2"));
        assertEquals("https://x.example.com/", normalizer.url("https://x.example.com"));
    }

    @Test
    @DisplayName("URL: 非 http(s) 或缺主机被拒绝")
    void invalidUrlsRejected() {
        assertThrows(NormalizationException.class, () -> normalizer.url("ftp://x.com/"));
        assertThrows(NormalizationException.class, () -> normalizer.url("http://"));
    }

    @Test
    @DisplayName("哈希: 大小写等价且长度校验")
    void hashEquivalence() {
        String md5 = "0123456789abcdef0123456789abcdef";
        assertEquals(md5, normalizer.hash("0123456789ABCDEF0123456789ABCDEF"));
        assertEquals(md5, normalizer.hash("0x" + "0123456789ABCDEF0123456789ABCDEF"));
        assertThrows(NormalizationException.class, () -> normalizer.hash("zzz"));
        assertThrows(NormalizationException.class, () -> normalizer.hash("0123"));
    }

    @Test
    @DisplayName("类型自动检测")
    void detectType() {
        assertEquals(IndicatorType.CIDR, normalizer.detectType("10.0.0.0/8"));
        assertEquals(IndicatorType.IP, normalizer.detectType("8.8.8.8"));
        assertEquals(IndicatorType.URL, normalizer.detectType("http://x/a"));
        assertEquals(IndicatorType.HASH,
                normalizer.detectType("0123456789abcdef0123456789abcdef"));
        assertEquals(IndicatorType.DOMAIN, normalizer.detectType("a.example.com"));
        assertNull(normalizer.detectType("???"));
    }
}
