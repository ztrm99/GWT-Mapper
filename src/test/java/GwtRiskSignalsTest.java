import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GwtRiskSignalsTest {

    @Test
    void buildInformationalFindingsIncludesAllHintsWhenPresent() {
        GwtRiskSignals.Signals signals = new GwtRiskSignals.Signals(
                "com.example.UserService::getUser",
                2,
                1
        );
        List<String> findings = GwtRiskSignals.buildInformationalFindings(signals, 3);

        assertEquals(4, findings.size());
        assertTrue(findings.stream().anyMatch(s -> s.contains("Semantic RPC method detected")));
        assertTrue(findings.stream().anyMatch(s -> s.contains("Potential BAC/IDOR surface")));
        assertTrue(findings.stream().anyMatch(s -> s.contains("Potential injection surface")));
        assertTrue(findings.stream().anyMatch(s -> s.contains("Authorization-diff hint")));
    }

    @Test
    void buildInformationalFindingsOmitsAuthzHintForSingleContext() {
        GwtRiskSignals.Signals signals = new GwtRiskSignals.Signals("com.example.A::m", 0, 0);
        List<String> findings = GwtRiskSignals.buildInformationalFindings(signals, 1);
        assertEquals(1, findings.size());
    }
}
