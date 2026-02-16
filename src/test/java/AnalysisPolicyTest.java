import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AnalysisPolicyTest {

    @Test
    void shouldProcessHistoryItemHonorsScopeOnlySetting() {
        assertTrue(AnalysisPolicy.shouldProcessHistoryItem(false, false));
        assertTrue(AnalysisPolicy.shouldProcessHistoryItem(false, true));
        assertFalse(AnalysisPolicy.shouldProcessHistoryItem(true, false));
        assertTrue(AnalysisPolicy.shouldProcessHistoryItem(true, true));
    }

    @Test
    void shouldExtractResponseArtifactsUsesBoundedLimit() {
        assertTrue(AnalysisPolicy.shouldExtractResponseArtifacts(10, 10));
        assertTrue(AnalysisPolicy.shouldExtractResponseArtifacts(9, 10));
        assertFalse(AnalysisPolicy.shouldExtractResponseArtifacts(11, 10));
        assertFalse(AnalysisPolicy.shouldExtractResponseArtifacts(10, 0));
        assertFalse(AnalysisPolicy.shouldExtractResponseArtifacts(-1, 10));
    }
}
