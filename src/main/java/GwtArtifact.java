import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

public class GwtArtifact {
    public final String host;
    public final String path;
    public final String type;
    public final String resolvedUrl;
    public final String source;
    public final String discoveredAt;
    public final HttpRequest sourceRequest;
    public final HttpRequestResponse sourceMessage;

    public GwtArtifact(String host, String path, String type, String resolvedUrl, String source, String discoveredAt, HttpRequest sourceRequest, HttpRequestResponse sourceMessage) {
        this.host = host;
        this.path = path;
        this.type = type;
        this.resolvedUrl = resolvedUrl;
        this.source = source;
        this.discoveredAt = discoveredAt;
        this.sourceRequest = sourceRequest;
        this.sourceMessage = sourceMessage;
    }

    public String key() {
        return host + "|" + path + "|" + type;
    }
}
