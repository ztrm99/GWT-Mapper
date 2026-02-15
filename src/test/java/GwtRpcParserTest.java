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
    void parseResponseParsesOkPayload() {
        String body = "//OK[\"done\",123,[\"a\",\"b\"]]";
        List<GwtRpcParser.RpcRow> rows = GwtRpcParser.parseResponse(body);

        assertEquals("Status", rows.get(0).field());
        assertEquals("OK", rows.get(0).resolved());
        assertTrue(rows.stream().anyMatch(r -> r.field().startsWith("Payload[") && r.raw().contains("done")));
    }
}
