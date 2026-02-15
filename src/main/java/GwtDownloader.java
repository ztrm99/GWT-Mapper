import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Set;
import java.util.function.Consumer;

import static burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl;

public class GwtDownloader {
    private static final Set<String> FORWARDED_AUTH_HEADERS = Set.of(
            "cookie",
            "authorization",
            "proxy-authorization",
            "x-csrf-token",
            "x-xsrf-token",
            "x-auth-token"
    );

    private final MontoyaApi api;

    public GwtDownloader(MontoyaApi api) {
        this.api = api;
    }

    public void downloadArtifact(GwtArtifact artifact, Path root, Consumer<String> info, Consumer<String> error) {
        try {
            Files.createDirectories(root);

            HttpRequest req = buildDownloadRequest(artifact);
            HttpRequestResponse response = api.http().sendRequest(req);
            if (!response.hasResponse()) {
                info.accept("No response for download URL: " + artifact.resolvedUrl);
                return;
            }

            Path out = root.resolve(sanitizeFileName(artifact.host + "_" + artifact.path));
            Files.write(out, response.response().body().getBytes());
            info.accept("Downloaded artifact to " + out);
        } catch (Exception ex) {
            error.accept("Failed to download artifact: " + artifact.resolvedUrl + ": " + ex.getMessage());
        }
    }

    private HttpRequest buildDownloadRequest(GwtArtifact artifact) {
        HttpRequest request = httpRequestFromUrl(artifact.resolvedUrl);
        if (artifact.sourceRequest == null) {
            return request;
        }

        for (HttpHeader header : artifact.sourceRequest.headers()) {
            String name = safe(header.name());
            String lower = name.toLowerCase(Locale.ROOT);
            if (FORWARDED_AUTH_HEADERS.contains(lower)) {
                request = request.withAddedHeader(name, safe(header.value()));
            }
        }

        if (!request.hasHeader("Referer")) {
            request = request.withAddedHeader("Referer", artifact.sourceRequest.url());
        }
        return request;
    }

    private static String sanitizeFileName(String raw) {
        return raw.replaceAll("[^A-Za-z0-9._-]", "_");
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }
}
