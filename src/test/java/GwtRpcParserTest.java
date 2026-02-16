import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GwtRpcParserTest {

    @Test
    void parseRequestResolvesStringTableReferences() {
        String body = "7|0|4|http://target/app/|ABCDEF|com.test.Service|doThing|1|2|3|4|";
        List<GwtRpcParser.RpcRow> rows = GwtRpcParser.parseRequest(body);

        assertTrue(rows.stream().anyMatch(r -> r.field().equals("StringTable[1]") && r.raw().equals("http://target/app/")));
        assertTrue(rows.stream().anyMatch(r -> r.field().equals("Module Base URL Ref") && r.resolved().equals("http://target/app/")));
        assertTrue(rows.stream().anyMatch(r -> r.field().equals("Method Ref") && r.resolved().equals("doThing")));
    }

    @Test
    void parseRequestReturnsEmptyForNull() {
        assertTrue(GwtRpcParser.parseRequest(null).isEmpty());
    }

    @Test
    void parseRequestReturnsEmptyForEmptyString() {
        assertTrue(GwtRpcParser.parseRequest("").isEmpty());
    }

    @Test
    void parseResponseReturnsEmptyForNull() {
        assertTrue(GwtRpcParser.parseResponse(null).isEmpty());
    }

    @Test
    void parseResponseReturnsEmptyForEmptyString() {
        assertTrue(GwtRpcParser.parseResponse("").isEmpty());
    }

    @Test
    void parseResponseParsesOkPayload() {
        String body = "//OK[\"done\",123,[\"a\",\"b\"]]";
        List<GwtRpcParser.RpcRow> rows = GwtRpcParser.parseResponse(body);

        assertEquals("Status", rows.get(0).field());
        assertEquals("OK", rows.get(0).resolved());
        assertTrue(rows.stream().anyMatch(r -> r.field().startsWith("Payload[") && r.raw().contains("done")));
    }

    @Test
    void parseRequestPreservesEmptyTokensInsideStringTable() {
        String body = "7|0|4|http://target/app/||com.test.Service|doThing|1|2|3|4|";
        List<GwtRpcParser.RpcRow> rows = GwtRpcParser.parseRequest(body);

        assertTrue(rows.stream().anyMatch(r -> r.field().equals("StringTable[2]") && r.raw().isEmpty()));
        assertTrue(rows.stream().anyMatch(r -> r.field().equals("Service Interface Ref") && r.resolved().equals("com.test.Service")));
        assertTrue(rows.stream().anyMatch(r -> r.field().equals("Method Ref") && r.resolved().equals("doThing")));
    }

    @Test
    void parseRequestIgnoresTerminalDelimiterOnly() {
        String body = "7|0|2|module|policy|1|2|";
        List<GwtRpcParser.RpcRow> rows = GwtRpcParser.parseRequest(body);

        assertEquals("String Table Count", rows.get(2).field());
        assertTrue(rows.stream().anyMatch(r -> r.field().equals("Module Base URL Ref") && r.resolved().equals("module")));
        assertTrue(rows.stream().noneMatch(r -> r.field().equals("Payload Token") && r.raw().isEmpty()));
    }
}
