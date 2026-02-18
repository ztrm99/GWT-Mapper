import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class GwtHistoryAnnotationPolicyTest {
    @Test
    void detectNoteForRpcAndCache() {
        assertEquals("GWT RPC request",
                GwtHistoryAnnotationPolicy.detectNote("/app/service", true));
        assertEquals("GWT RPC cache file",
                GwtHistoryAnnotationPolicy.detectNote("/app/ABC.cache.js", false));
        assertEquals("GWT RPC request | GWT RPC cache file",
                GwtHistoryAnnotationPolicy.detectNote("/app/ABC.cache.js", true));
    }

    @Test
    void mergeNoteAvoidsDuplicates() {
        assertEquals("Existing note | GWT RPC request",
                GwtHistoryAnnotationPolicy.mergeNote("Existing note", "GWT RPC request"));
        assertEquals("GWT RPC request | GWT RPC cache file",
                GwtHistoryAnnotationPolicy.mergeNote("GWT RPC request", "GWT RPC request | GWT RPC cache file"));
    }
}
