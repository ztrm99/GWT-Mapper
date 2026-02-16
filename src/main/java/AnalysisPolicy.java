public final class AnalysisPolicy {
    private AnalysisPolicy() {
    }

    public static boolean shouldProcessHistoryItem(boolean scopeOnly, boolean inScope) {
        return !scopeOnly || inScope;
    }

    public static boolean shouldExtractResponseArtifacts(int responseSizeBytes, int maxAllowedBytes) {
        return responseSizeBytes >= 0 && maxAllowedBytes > 0 && responseSizeBytes <= maxAllowedBytes;
    }
}
