package com.github.xingjianluo.threatinteliocjava.tests;

import com.github.xingjianluo.threatinteliocjava.ingest.CsvIntelParser;
import com.github.xingjianluo.threatinteliocjava.ingest.JsonIntelParser;
import com.github.xingjianluo.threatinteliocjava.ingest.ParseResult;
import com.github.xingjianluo.threatinteliocjava.ingest.SuppressionListParser;
import com.github.xingjianluo.threatinteliocjava.model.RejectionReason;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/** 解析器：文件级致命错误与条目级拒绝必须可区分。 */
class IntelParserTest {

    @TempDir
    Path dir;

    private Path write(String name, String content) throws IOException {
        Path f = dir.resolve(name);
        Files.writeString(f, content);
        return f;
    }

    @Test
    @DisplayName("JSON: 正常解析指标与抑制规则")
    void jsonHappyPath() throws Exception {
        ParseResult r = new JsonIntelParser().parse(write("f.json", """
                {"indicators":[{"type":"ip","value":"1.1.1.1","confidence":"9"}],
                 "suppressions":[{"id":"w","type":"domain","value":"a.com"}]}
                """));
        assertFalse(r.fatal());
        assertEquals(1, r.indicators().size());
        assertEquals(1, r.suppressions().size());
        assertTrue(r.rejections().isEmpty());
    }

    @Test
    @DisplayName("JSON: 整体损坏是致命错误；单条问题是条目级拒绝")
    void jsonFatalVsEntryRejection() throws Exception {
        ParseResult broken = new JsonIntelParser().parse(write("b.json", "{ not json"));
        assertTrue(broken.fatal());
        assertNotNull(broken.fatalError());

        ParseResult mixed = new JsonIntelParser().parse(write("m.json", """
                {"indicators":[
                  {"type":"ip","value":"1.1.1.1"},
                  {"type":"wat","value":"2.2.2.2"},
                  {"type":"ip"},
                  "oops"
                ]}
                """));
        assertFalse(mixed.fatal());
        // "wat" 类型在解析层保留，到刷新归一层才按 UNSUPPORTED_INDICATOR_TYPE 拒绝
        assertEquals(2, mixed.indicators().size());
        assertEquals(2, mixed.rejections().size());
        assertTrue(mixed.rejections().stream()
                .anyMatch(x -> x.reason() == RejectionReason.MISSING_REQUIRED_FIELD));
        assertTrue(mixed.rejections().stream()
                .anyMatch(x -> x.reason() == RejectionReason.MALFORMED_LINE));
    }

    @Test
    @DisplayName("CSV: 表头驱动、注释与空行跳过、引号字段")
    void csvHappyPath() throws Exception {
        String csv = "# a comment\n"
                + "type,value,severity,confidence,description\n"
                + "ip,1.1.1.1,high,9,\"a, quoted\"\n"
                + "\n"
                + "DOMAIN,EXAMPLE.COM,low,1,x\n";
        ParseResult r = new CsvIntelParser().parse(write("f.csv", csv));
        assertFalse(r.fatal());
        assertEquals(2, r.indicators().size());
        assertEquals("a, quoted", r.indicators().get(0).description());
        assertTrue(r.rejections().isEmpty());
    }

    @Test
    @DisplayName("CSV: 列数不符/缺字段按条目拒绝且保留行号与原因")
    void csvEntryRejections() throws Exception {
        ParseResult r = new CsvIntelParser().parse(write("f.csv", """
                type,value,severity,confidence
                ip,1.1.1.1,high
                ip,,high,1
                ,1.1.1.1,high,1
                """));
        assertFalse(r.fatal());
        assertTrue(r.indicators().isEmpty());
        assertEquals(3, r.rejections().size());
        assertEquals(RejectionReason.MALFORMED_LINE, r.rejections().get(0).reason());
        assertEquals(RejectionReason.MISSING_REQUIRED_FIELD, r.rejections().get(1).reason());
        assertEquals(3, r.rejections().get(1).line());
    }

    @Test
    @DisplayName("CSV: 缺必需列表头是致命错误")
    void csvMissingHeaderIsFatal() throws Exception {
        ParseResult r = new CsvIntelParser().parse(write("f.csv", "foo,bar\n1,2\n"));
        assertTrue(r.fatal());
    }

    @Test
    @DisplayName("suppressions.csv: 正常解析，缺字段条目级拒绝，仅该文件名被识别")
    void suppressionParser() throws Exception {
        var parser = new SuppressionListParser();
        assertTrue(parser.supports("suppressions.csv"));
        assertFalse(parser.supports("other.csv"));
        ParseResult r = parser.parse(write("suppressions.csv", """
                id,type,value,reason
                W1,domain,a.com,benign
                ,domain,b.com,no id
                """));
        assertFalse(r.fatal());
        assertEquals(1, r.suppressions().size());
        assertEquals(1, r.rejections().size());
        assertEquals(RejectionReason.MALFORMED_SUPPRESSION_RULE,
                r.rejections().get(0).reason());
    }

    @Test
    @DisplayName("supports 按扩展名/约定文件名区分")
    void supportsRouting() {
        assertTrue(new JsonIntelParser().supports("x.json"));
        assertFalse(new JsonIntelParser().supports("x.csv"));
        assertTrue(new CsvIntelParser().supports("x.csv"));
        assertFalse(new CsvIntelParser().supports("suppressions.csv"));
    }
}
