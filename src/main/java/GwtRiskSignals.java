import java.util.ArrayList;
import java.util.List;

public final class GwtRiskSignals {
    public record Signals(String methodKey, int idCandidateCount, int injectionCandidateCount) {
    }

    private GwtRiskSignals() {
    }

    public static Signals fromSemantic(GwtRpcSemanticParser.SemanticRequest semantic) {
        String methodKey = safe(semantic.methodKey());
        int idCount = GwtPentestHeuristics.extractIdCandidates(semantic).size();
        int injectionCount = GwtPentestHeuristics.countLikelyInjectionParams(semantic);
        return new Signals(methodKey, idCount, injectionCount);
    }

    public static List<String> buildInformationalFindings(Signals signals, int authContextCount) {
        List<String> findings = new ArrayList<>();
        if (!signals.methodKey().isEmpty()) {
            findings.add("Semantic RPC method detected: " + signals.methodKey());
        }
        if (signals.idCandidateCount() > 0) {
            findings.add("Potential BAC/IDOR surface: " + signals.idCandidateCount() + " ID-like parameter(s) detected.");
        }
        if (signals.injectionCandidateCount() > 0) {
            findings.add("Potential injection surface: " + signals.injectionCandidateCount() + " free-text parameter(s) detected.");
        }
        if (!signals.methodKey().isEmpty() && authContextCount > 1) {
            findings.add("Authorization-diff hint: method seen under multiple auth contexts (" + authContextCount + "). Compare cross-role responses.");
        }
        return findings;
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
