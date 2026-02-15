import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ArtifactStore {
    public enum UpsertResult {
        ADDED,
        UPDATED,
        UNCHANGED
    }

    private final Map<String, GwtArtifact> artifacts = new LinkedHashMap<>();

    public synchronized UpsertResult upsertPreferRicher(GwtArtifact artifact) {
        String key = artifact.key();
        GwtArtifact existing = artifacts.get(key);
        if (existing == null) {
            artifacts.put(key, artifact);
            return UpsertResult.ADDED;
        }

        boolean hasNewRequest = existing.sourceRequest == null && artifact.sourceRequest != null;
        boolean hasNewMessage = existing.sourceMessage == null && artifact.sourceMessage != null;
        boolean hasNewResponse = (existing.sourceMessage == null || !existing.sourceMessage.hasResponse())
                && artifact.sourceMessage != null
                && artifact.sourceMessage.hasResponse();
        if (hasNewRequest || hasNewMessage || hasNewResponse) {
            GwtArtifact merged = new GwtArtifact(
                    existing.host,
                    existing.path,
                    existing.type,
                    existing.resolvedUrl,
                    existing.source,
                    existing.discoveredAt,
                    artifact.sourceRequest != null ? artifact.sourceRequest : existing.sourceRequest,
                    artifact.sourceMessage != null ? artifact.sourceMessage : existing.sourceMessage
            );
            artifacts.put(key, merged);
            return UpsertResult.UPDATED;
        }

        return UpsertResult.UNCHANGED;
    }

    public synchronized GwtArtifact find(String host, String path, String type) {
        return artifacts.get(host + "|" + path + "|" + type);
    }

    public synchronized List<GwtArtifact> all() {
        return new ArrayList<>(artifacts.values());
    }

    public synchronized void clear() {
        artifacts.clear();
    }
}
