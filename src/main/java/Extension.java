import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.intruder.HttpRequestTemplate;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.io.BufferedWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

import static burp.api.montoya.core.Range.range;
import static burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse;
import static burp.api.montoya.http.message.requests.HttpRequest.httpRequest;
import static burp.api.montoya.http.message.responses.HttpResponse.httpResponse;

public class Extension implements BurpExtension, HttpHandler, PassiveScanCheck, HttpRequestEditorProvider, HttpResponseEditorProvider, ContextMenuItemsProvider {
    private static final String ISSUE_NAME = "GWT RPC technology identified";
    private static final AuditIssueSeverity ISSUE_SEVERITY = AuditIssueSeverity.INFORMATION;
    private static final String SETTING_OUTPUT_DIR = "output_dir";
    private static final String SETTING_PASSIVE_SCAN_ENABLED = "passive_scan_enabled";
    private static final String SETTING_SCOPE_ONLY_HISTORY = "scope_only_history";
    private static final String SETTING_PASSIVE_MAX_BODY_BYTES = "passive_max_body_bytes";
    private static final String SETTING_FAST_ANALYZE = "fast_analyze";
    private static final int PREVIEW_MAX_BYTES = 250_000;
    private static final int DEFAULT_PASSIVE_MAX_BODY_BYTES = 300_000;

    private MontoyaApi api;
    private PersistedObject extensionData;
    private ArtifactStore artifactStore;
    private GwtDownloader downloader;
    private ExecutorService passiveExecutor;
    private ExecutorService historyExecutor;
    private ExecutorService downloadExecutor;
    private volatile Future<?> historyFuture;

    private JPanel mainPanel;
    private DashboardPanel dashboard;
    private DefaultTableModel methodsCatalogModel;
    private JTable methodsCatalogTable;
    private final Set<String> methodsCatalogSet = ConcurrentHashMap.newKeySet();
    private final Set<String> expandedNoCacheUrls = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean cancelHistoryFlag = new AtomicBoolean(false);
    private JTabbedPane workTabs;
    private int analysisRunCounter = 0;
    private int passiveMaxBodyBytes;
    private Path defaultOutputDir;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.api = montoyaApi;
        this.extensionData = montoyaApi.persistence().extensionData();
        this.defaultOutputDir = Paths.get(System.getProperty("user.home"), ".gwt-scanner");
        this.passiveMaxBodyBytes = loadPassiveMaxBodyBytes();
        this.artifactStore = new ArtifactStore();
        this.downloader = new GwtDownloader(montoyaApi);
        this.passiveExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "gwt-passive-worker");
            t.setDaemon(true);
            return t;
        });
        this.historyExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "gwt-history-analysis");
            t.setDaemon(true);
            return t;
        });
        this.downloadExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "gwt-download-worker");
            t.setDaemon(true);
            return t;
        });

        montoyaApi.extension().setName("GWT RPC Mapper");
        initUi();

        montoyaApi.userInterface().registerSuiteTab("GWT Scanner", mainPanel);
        montoyaApi.userInterface().registerHttpRequestEditorProvider(this);
        montoyaApi.userInterface().registerHttpResponseEditorProvider(this);
        montoyaApi.userInterface().registerContextMenuItemsProvider(this);

        montoyaApi.http().registerHttpHandler(this);
        montoyaApi.scanner().registerPassiveScanCheck(this, ScanCheckType.PER_REQUEST);

        montoyaApi.logging().logToOutput("GWT RPC Mapper loaded.");
    }

    @Override
    public String checkName() {
        return "GWT RPC Passive Detector";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse requestResponse) {
        if (!isPassiveScanEnabled()) {
            return AuditResult.auditResult();
        }

        List<String> findings = new ArrayList<>();

        HttpRequest req = requestResponse.request();
        String reqPath = req.pathWithoutQuery();
        String reqUrl = req.url();

        if (GwtDetector.isPotentialGwtPath(reqPath)) {
            String type = GwtDetector.classifyArtifact(reqPath);
            recordArtifact(req.httpService().host(), reqPath, type, reqUrl, "request path", req, requestResponse);
            findings.add("Detected " + type + " in request path: <code>" + reqPath + "</code>");
        }

        if (GwtDetector.looksLikeGwtRpcRequest(req)) {
            recordArtifact(req.httpService().host(), reqPath, "GWT RPC Endpoint", reqUrl, "rpc request", req, requestResponse);
            findings.add("Detected GWT RPC request format or headers at: <code>" + reqUrl + "</code>");
        }

        if (requestResponse.hasResponse()) {
            HttpResponse resp = requestResponse.response();
            int respSize = resp.toByteArray().length();
            if (respSize <= passiveMaxBodyBytes) {
                String body = safe(resp.bodyToString());
                List<String> extracted = GwtDetector.extractArtifactPaths(body);
                for (String path : extracted) {
                    String resolved = GwtDetector.resolvePath(reqUrl, path);
                    String host = GwtDetector.hostFromUrl(reqUrl);
                    String type = GwtDetector.classifyArtifact(path);
                    recordArtifact(host, path, type, resolved, "response body", req, requestResponse);
                    findings.add("Detected " + type + " reference in response: <code>" + escapeHtml(path) + "</code>");
                }
            }
        }

        if (findings.isEmpty()) {
            return AuditResult.auditResult();
        }

        StringBuilder detail = new StringBuilder();
        detail.append("<p>GWT artifacts and/or RPC traffic were detected.</p><ul>");
        for (String finding : findings) {
            detail.append("<li>").append(finding).append("</li>");
        }
        detail.append("</ul>");

        AuditIssue issue = AuditIssue.auditIssue(
                ISSUE_NAME,
                detail.toString(),
                null,
                req.url(),
                ISSUE_SEVERITY,
                AuditIssueConfidence.CERTAIN,
                "GWT RPC attack surface",
                "The application appears to use Google Web Toolkit (GWT) RPC endpoints or artifacts that can be mapped for controlled penetration testing.",
                ISSUE_SEVERITY,
                requestResponse
        );

        return AuditResult.auditResult(issue);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        if (!existingIssue.name().equals(newIssue.name())) {
            return ConsolidationAction.KEEP_BOTH;
        }
        if (safe(existingIssue.baseUrl()).equals(safe(newIssue.baseUrl())) && safe(existingIssue.detail()).equals(safe(newIssue.detail()))) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (!isPassiveScanEnabled()) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        String reqPath = requestToBeSent.pathWithoutQuery();
        HttpRequest reqCopy = requestToBeSent.copyToTempFile();
        passiveExecutor.submit(() -> {
            if (GwtDetector.isPotentialGwtPath(reqPath)) {
                String type = GwtDetector.classifyArtifact(reqPath);
                recordArtifact(reqCopy.httpService().host(), reqPath, type, reqCopy.url(), "request path", reqCopy, null);
            }

            if (GwtDetector.looksLikeGwtRpcRequest(reqCopy)) {
                recordArtifact(reqCopy.httpService().host(), reqPath, "GWT RPC Endpoint", reqCopy.url(), "rpc request", reqCopy, null);
            }
        });

        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (!isPassiveScanEnabled()) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        HttpRequest sourceRequest = responseReceived.initiatingRequest();
        HttpRequestResponse sourceMessage = httpRequestResponse(sourceRequest, responseReceived);
        String initiatingUrl = sourceRequest.url();
        int responseSize = responseReceived.toByteArray().length();
        if (responseSize <= passiveMaxBodyBytes) {
            HttpRequest requestCopy = sourceRequest.copyToTempFile();
            HttpRequestResponse messageCopy = sourceMessage.copyToTempFile();
            String body = safe(responseReceived.bodyToString());
            passiveExecutor.submit(() -> {
                for (String found : GwtDetector.extractArtifactPaths(body)) {
                    String resolved = GwtDetector.resolvePath(initiatingUrl, found);
                    recordArtifact(GwtDetector.hostFromUrl(initiatingUrl), found, GwtDetector.classifyArtifact(found), resolved, "response body", requestCopy, messageCopy);
                }
            });
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
        return new GwtRequestEditor();
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext) {
        return new GwtResponseEditor();
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (!event.isFrom(
                InvocationType.PROXY_HISTORY,
                InvocationType.MESSAGE_EDITOR_REQUEST,
                InvocationType.MESSAGE_VIEWER_REQUEST
        )) {
            return Collections.emptyList();
        }

        List<HttpRequestResponse> selected = selectedRequestResponsesFromContext(event);
        if (selected.isEmpty()) {
            return Collections.emptyList();
        }

        JMenuItem analyzeToDashboard = new JMenuItem("GWT: Analyze Request -> Dashboard");
        analyzeToDashboard.addActionListener(e -> analyzeFromContext(selected));

        JMenuItem sendToIntruder = new JMenuItem("GWT: Send Request -> Intruder (auto positions)");
        sendToIntruder.addActionListener(e -> sendFromContextToIntruder(selected));

        List<Component> menu = new ArrayList<>();
        menu.add(analyzeToDashboard);
        menu.add(sendToIntruder);
        return menu;
    }

    private void initUi() {
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        dashboard = new DashboardPanel();

        JPanel scannerPanel = new JPanel(new BorderLayout());
        methodsCatalogModel = new DefaultTableModel(new Object[]{"Method", "Source", "First Seen"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        methodsCatalogTable = new JTable(methodsCatalogModel);
        methodsCatalogTable.setRowSorter(new TableRowSorter<>(methodsCatalogModel));
        scannerPanel.add(new JScrollPane(methodsCatalogTable), BorderLayout.CENTER);
        JPanel scannerControls = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton exportScannerCsvButton = new JButton("Export Scanner CSV");
        exportScannerCsvButton.addActionListener(e -> exportMethodsCsv());
        scannerControls.add(exportScannerCsvButton);
        scannerPanel.add(scannerControls, BorderLayout.SOUTH);

        workTabs = new JTabbedPane();
        workTabs.addTab("Dashboard", dashboard);
        workTabs.addTab("Scanner", scannerPanel);

        mainPanel.add(workTabs, BorderLayout.CENTER);
    }

    private void chooseFolder() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (chooser.showOpenDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
            dashboard.outputFolderField.setText(chooser.getSelectedFile().toPath().toString());
            persistSettings();
        }
    }

    private void persistSettings() {
        String outputDir = safe(dashboard.outputFolderField.getText()).trim();
        if (outputDir.isEmpty()) {
            outputDir = defaultOutputDir.toString();
            dashboard.outputFolderField.setText(outputDir);
        }
        int parsedPassiveMax = parsePositiveInt(safe(dashboard.passiveMaxBodyBytesField.getText()), DEFAULT_PASSIVE_MAX_BODY_BYTES);
        passiveMaxBodyBytes = parsedPassiveMax;
        dashboard.passiveMaxBodyBytesField.setText(String.valueOf(passiveMaxBodyBytes));
        extensionData.setString(SETTING_OUTPUT_DIR, outputDir);
        extensionData.setBoolean(SETTING_PASSIVE_SCAN_ENABLED, dashboard.passiveScanCheckBox.isSelected());
        extensionData.setBoolean(SETTING_SCOPE_ONLY_HISTORY, dashboard.scopeOnlyHistoryCheckBox.isSelected());
        extensionData.setBoolean(SETTING_FAST_ANALYZE, dashboard.fastAnalyzeCheckBox.isSelected());
        extensionData.setInteger(SETTING_PASSIVE_MAX_BODY_BYTES, passiveMaxBodyBytes);
        info("Settings saved.");
    }

    private String loadOutputDirectory() {
        String persisted = extensionData.getString(SETTING_OUTPUT_DIR);
        if (persisted == null || persisted.isBlank()) {
            return defaultOutputDir.toString();
        }
        return persisted;
    }

    private boolean loadPassiveScanEnabled() {
        Boolean persisted = extensionData.getBoolean(SETTING_PASSIVE_SCAN_ENABLED);
        return persisted == null || persisted;
    }

    private boolean loadScopeOnlyHistory() {
        Boolean persisted = extensionData.getBoolean(SETTING_SCOPE_ONLY_HISTORY);
        return persisted == null || persisted;
    }

    private boolean loadFastAnalyze() {
        Boolean persisted = extensionData.getBoolean(SETTING_FAST_ANALYZE);
        return persisted == null || persisted;
    }

    private int loadPassiveMaxBodyBytes() {
        Integer persisted = extensionData.getInteger(SETTING_PASSIVE_MAX_BODY_BYTES);
        if (persisted == null || persisted <= 0) {
            return DEFAULT_PASSIVE_MAX_BODY_BYTES;
        }
        return persisted;
    }

    private boolean isPassiveScanEnabled() {
        return dashboard == null || dashboard.passiveScanCheckBox.isSelected();
    }

    private void applyFilter() {
        String filter = safe(dashboard.filterField.getText()).trim();
        if (filter.isEmpty()) {
            dashboard.rowSorter.setRowFilter(null);
            return;
        }
        dashboard.rowSorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(filter)));
    }

    private void clearArtifacts() {
        artifactStore.clear();
        dashboard.artifactsModel.setRowCount(0);
        dashboard.requestPreviewEditor.setRequest(placeholderRequest("Select an artifact row to preview request."));
        dashboard.responsePreviewEditor.setResponse(placeholderResponse("Select an artifact row to preview response."));
        setAnalysisText(
                "Click 'Analyze Selected Item(s)' to extract GWT methods/version/headers.",
                Collections.emptyList(),
                "",
                "Cleared"
        );
    }

    private void exportCsv() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(Paths.get("gwt-artifacts.csv").toFile());
        if (chooser.showSaveDialog(mainPanel) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        Path output = chooser.getSelectedFile().toPath();
        try (BufferedWriter writer = Files.newBufferedWriter(output)) {
            writer.write("host,path,type,resolved_url,source,discovered_at");
            writer.newLine();
            for (GwtArtifact artifact : artifactStore.all()) {
                writer.write(csv(artifact.host));
                writer.write(",");
                writer.write(csv(artifact.path));
                writer.write(",");
                writer.write(csv(artifact.type));
                writer.write(",");
                writer.write(csv(artifact.resolvedUrl));
                writer.write(",");
                writer.write(csv(artifact.source));
                writer.write(",");
                writer.write(csv(artifact.discoveredAt));
                writer.newLine();
            }
            info("Exported CSV to " + output);
        } catch (Exception ex) {
            error("Failed to export CSV", ex);
        }
    }

    private void exportMethodsCsv() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(Paths.get("gwt-methods.csv").toFile());
        if (chooser.showSaveDialog(mainPanel) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        Path output = chooser.getSelectedFile().toPath();
        try (BufferedWriter writer = Files.newBufferedWriter(output)) {
            writer.write("method,source,first_seen");
            writer.newLine();
            for (int i = 0; i < methodsCatalogModel.getRowCount(); i++) {
                String method = String.valueOf(methodsCatalogModel.getValueAt(i, 0));
                String source = String.valueOf(methodsCatalogModel.getValueAt(i, 1));
                String seen = String.valueOf(methodsCatalogModel.getValueAt(i, 2));
                writer.write(csv(method));
                writer.write(",");
                writer.write(csv(source));
                writer.write(",");
                writer.write(csv(seen));
                writer.newLine();
            }
            info("Exported methods CSV to " + output);
        } catch (Exception ex) {
            error("Failed to export methods CSV", ex);
        }
    }

    private static String csv(String value) {
        String escaped = safe(value).replace("\"", "\"\"");
        return "\"" + escaped + "\"";
    }

    private void useTempFolder() {
        try {
            Path tempOutputDir = Files.createTempDirectory("gwt-scanner-");
            dashboard.outputFolderField.setText(tempOutputDir.toString());
            persistSettings();
            info("Using temporary folder: " + tempOutputDir);
        } catch (Exception ex) {
            error("Unable to create temporary directory", ex);
        }
    }

    private void downloadSelected() {
        int[] rows = dashboard.artifactsTable.getSelectedRows();
        if (rows.length == 0) {
            JOptionPane.showMessageDialog(mainPanel, "Select at least one artifact row.");
            return;
        }

        List<GwtArtifact> targets = new ArrayList<>();
        for (int selectedRow : rows) {
            int row = dashboard.artifactsTable.convertRowIndexToModel(selectedRow);
            String host = String.valueOf(dashboard.artifactsModel.getValueAt(row, 0));
            String path = String.valueOf(dashboard.artifactsModel.getValueAt(row, 1));
            String type = String.valueOf(dashboard.artifactsModel.getValueAt(row, 2));
            GwtArtifact artifact = artifactStore.find(host, path, type);
            if (artifact != null) {
                targets.add(artifact);
            }
        }
        if (targets.isEmpty()) {
            info("No downloadable artifacts found for selected rows.");
            return;
        }

        Path outputRoot = resolveOutputRoot();
        downloadExecutor.submit(() -> {
            for (GwtArtifact artifact : targets) {
                downloader.downloadArtifact(artifact, outputRoot, this::info, msg -> api.logging().logToError("[GWT Mapper] " + msg));
            }
        });
    }

    private void downloadAll() {
        List<GwtArtifact> all = artifactStore.all();
        if (all.isEmpty()) {
            info("No artifacts available to download.");
            return;
        }
        Path outputRoot = resolveOutputRoot();
        downloadExecutor.submit(() -> {
            for (GwtArtifact artifact : all) {
                downloader.downloadArtifact(artifact, outputRoot, this::info, msg -> api.logging().logToError("[GWT Mapper] " + msg));
            }
        });
    }

    private Path resolveOutputRoot() {
        String configured = safe(dashboard.outputFolderField.getText()).trim();
        if (!configured.isEmpty()) {
            return Paths.get(configured);
        }
        return defaultOutputDir;
    }

    private boolean recordArtifact(String host, String path, String type, String resolvedUrl, String source, HttpRequest sourceRequest, HttpRequestResponse sourceMessage) {
        if (path == null || path.isEmpty()) {
            return false;
        }

        HttpRequest storedRequest = sourceRequest == null ? null : sourceRequest.copyToTempFile();
        HttpRequestResponse storedMessage = sourceMessage == null ? null : sourceMessage.copyToTempFile();
        GwtArtifact artifact = new GwtArtifact(host, path, type, resolvedUrl, source, now(), storedRequest, storedMessage);
        ArtifactStore.UpsertResult result = artifactStore.upsertPreferRicher(artifact);
        if (result == ArtifactStore.UpsertResult.UNCHANGED) {
            return false;
        }
        if (result == ArtifactStore.UpsertResult.UPDATED) {
            SwingUtilities.invokeLater(this::updateSelectedPreview);
            maybeExpandNoCache(artifact);
            return false;
        }

        SwingUtilities.invokeLater(() -> dashboard.artifactsModel.addRow(new Object[]{
                artifact.host,
                artifact.path,
                artifact.type,
                artifact.resolvedUrl,
                artifact.source,
                artifact.discoveredAt
        }));
        enrichMethodsCatalogFromArtifact(artifact);
        maybeExpandNoCache(artifact);
        return true;
    }

    private void enrichMethodsCatalogFromArtifact(GwtArtifact artifact) {
        try {
            List<String> found = new ArrayList<>();
            if (artifact.sourceRequest != null) {
                List<GwtRpcParser.RpcRow> rows = GwtRpcParser.parseRequest(artifact.sourceRequest.bodyToString());
                String method = findResolved(rows, "Method Ref");
                if (!method.isEmpty()) {
                    found.add(method);
                }
            }
            if (artifact.path.toLowerCase().endsWith(".cache.js") && artifact.sourceMessage != null && artifact.sourceMessage.hasResponse()) {
                String body = safe(artifact.sourceMessage.response().bodyToString());
                found.addAll(MethodExtractor.extractCacheMethodsLikeGwtMap(body));
            }
            if (!found.isEmpty()) {
                String sourceUrl = safe(artifact.resolvedUrl);
                if (sourceUrl.isEmpty()) {
                    sourceUrl = safe(artifact.path);
                }
                addMethodsToCatalog(found, sourceUrl);
            }
        } catch (Exception ex) {
            api.logging().logToError("[GWT Mapper] Method catalog enrichment failed: " + ex.getMessage());
        }
    }

    private void maybeExpandNoCache(GwtArtifact artifact) {
        String pathLower = safe(artifact.path).toLowerCase();
        if (!pathLower.endsWith(".nocache.js")) {
            return;
        }
        String url = safe(artifact.resolvedUrl);
        if (url.isEmpty()) {
            return;
        }
        if (!expandedNoCacheUrls.add(url)) {
            return;
        }
        passiveExecutor.submit(() -> expandNoCacheToPermutations(url, artifact.sourceRequest));
    }

    private void expandNoCacheToPermutations(String noCacheUrl, HttpRequest sourceRequest) {
        try {
            HttpRequest req = httpRequest(noCacheUrl);
            if (sourceRequest != null) {
                req = reuseAuthHeaders(req, sourceRequest);
            }
            HttpRequestResponse rr = api.http().sendRequest(req);
            if (!rr.hasResponse()) {
                return;
            }
            String body = safe(rr.response().bodyToString());
            Set<String> permutations = MethodExtractor.extractPermutationsFromNoCache(body);
            String moduleBase = noCacheUrl.substring(0, Math.max(0, noCacheUrl.lastIndexOf('/') + 1));
            for (String perm : permutations) {
                String cacheUrl = moduleBase + perm + ".cache.js";
                recordArtifact(
                        GwtDetector.hostFromUrl(cacheUrl),
                        extractPath(cacheUrl),
                        "GWT Cache JS",
                        cacheUrl,
                        "nocache expansion",
                        req,
                        rr
                );
            }
        } catch (Exception ex) {
            api.logging().logToError("[GWT Mapper] NoCache expansion failed for " + noCacheUrl + ": " + ex.getMessage());
        }
    }

    private HttpRequest reuseAuthHeaders(HttpRequest request, HttpRequest sourceRequest) {
        try {
            for (var header : sourceRequest.headers()) {
                String n = safe(header.name()).toLowerCase();
                if (n.equals("cookie") || n.equals("authorization") || n.equals("x-csrf-token") || n.equals("x-xsrf-token")) {
                    request = request.withAddedHeader(header.name(), safe(header.value()));
                }
            }
        } catch (Exception ex) {
            api.logging().logToError("[GWT Mapper] Auth header reuse failed: " + ex.getMessage());
        }
        return request;
    }

    private static String now() {
        return LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }

    private void info(String msg) {
        api.logging().logToOutput("[GWT Mapper] " + msg);
    }

    private void error(String msg, Exception ex) {
        api.logging().logToError("[GWT Mapper] " + msg + ": " + ex.getMessage());
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }

    private static int parsePositiveInt(String value, int fallback) {
        try {
            int parsed = Integer.parseInt(value.trim());
            return parsed > 0 ? parsed : fallback;
        } catch (Exception ex) {
            return fallback;
        }
    }

    private static int parseIntOr(String value, int fallback) {
        try {
            return Integer.parseInt(safe(value).trim());
        } catch (Exception ex) {
            return fallback;
        }
    }

    private static String escapeHtml(String input) {
        return safe(input)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    private void setAnalysisText(String summary, List<String> methods, String headers, String runLabel) {
        dashboard.analysisSummaryArea.setText(safe(summary));
        dashboard.analysisHeadersArea.setText(safe(headers));
        dashboard.methodsTableModel.setRowCount(0);
        for (String method : methods) {
            dashboard.methodsTableModel.addRow(new Object[]{method});
        }
        dashboard.analysisSummaryArea.setCaretPosition(0);
        dashboard.analysisHeadersArea.setCaretPosition(0);
        dashboard.analysisRunsArea.insert(
                "=== " + runLabel + " ===\n" +
                        safe(summary) + "\n" +
                        (methods.isEmpty() ? "" : ("Methods: " + String.join(", ", methods) + "\n")) +
                        safe(headers) + "\n\n",
                0
        );
    }

    private void addMethodsToCatalog(List<String> methods, String sourceLabel) {
        if (methodsCatalogModel == null || methods == null) {
            return;
        }
        for (String method : methods) {
            String m = safe(method).trim();
            if (m.isEmpty()) {
                continue;
            }
            if (methodsCatalogSet.add(m)) {
                String seen = now();
                SwingUtilities.invokeLater(() -> methodsCatalogModel.addRow(new Object[]{m, sourceLabel, seen}));
            }
        }
    }

    private void updateSelectedPreview() {
        GwtArtifact artifact = selectedArtifact();
        if (artifact == null) {
            dashboard.requestPreviewEditor.setRequest(placeholderRequest("Select an artifact row to preview request."));
            dashboard.responsePreviewEditor.setResponse(placeholderResponse("Select an artifact row to preview response."));
            return;
        }

        dashboard.requestPreviewEditor.setRequest(buildPreviewRequest(artifact));
        dashboard.responsePreviewEditor.setResponse(buildPreviewResponse(artifact));
    }

    private GwtArtifact selectedArtifact() {
        int selectedRow = dashboard.artifactsTable.getSelectedRow();
        if (selectedRow < 0) {
            return null;
        }
        int row = dashboard.artifactsTable.convertRowIndexToModel(selectedRow);
        String host = String.valueOf(dashboard.artifactsModel.getValueAt(row, 0));
        String path = String.valueOf(dashboard.artifactsModel.getValueAt(row, 1));
        String type = String.valueOf(dashboard.artifactsModel.getValueAt(row, 2));
        return artifactStore.find(host, path, type);
    }

    private List<GwtArtifact> selectedArtifacts() {
        int[] selectedRows = dashboard.artifactsTable.getSelectedRows();
        List<GwtArtifact> out = new ArrayList<>();
        for (int selectedRow : selectedRows) {
            int row = dashboard.artifactsTable.convertRowIndexToModel(selectedRow);
            String host = String.valueOf(dashboard.artifactsModel.getValueAt(row, 0));
            String path = String.valueOf(dashboard.artifactsModel.getValueAt(row, 1));
            String type = String.valueOf(dashboard.artifactsModel.getValueAt(row, 2));
            GwtArtifact artifact = artifactStore.find(host, path, type);
            if (artifact != null) {
                out.add(artifact);
            }
        }
        if (out.isEmpty()) {
            GwtArtifact single = selectedArtifact();
            if (single != null) {
                out.add(single);
            }
        }
        return out;
    }

    private HttpRequest buildPreviewRequest(GwtArtifact artifact) {
        if (artifact.sourceMessage != null) {
            int len = artifact.sourceMessage.request().toByteArray().length();
            if (len > PREVIEW_MAX_BYTES) {
                return placeholderRequest("TOO BIG FILE: request is " + len + " bytes.");
            }
            return artifact.sourceMessage.request();
        }
        if (artifact.sourceRequest != null) {
            int len = artifact.sourceRequest.toByteArray().length();
            if (len > PREVIEW_MAX_BYTES) {
                return placeholderRequest("TOO BIG FILE: request is " + len + " bytes.");
            }
            return artifact.sourceRequest;
        }
        return placeholderRequest("No request data available for this artifact.");
    }

    private HttpResponse buildPreviewResponse(GwtArtifact artifact) {
        if (artifact.sourceMessage == null || !artifact.sourceMessage.hasResponse()) {
            return placeholderResponse("No response data available for this artifact.");
        }
        int len = artifact.sourceMessage.response().toByteArray().length();
        if (len > PREVIEW_MAX_BYTES) {
            return placeholderResponse("TOO BIG FILE: response is " + len + " bytes.");
        }
        return artifact.sourceMessage.response();
    }

    private HttpRequest placeholderRequest(String message) {
        return httpRequest("GET /gwt-scanner-preview HTTP/1.1\r\nHost: preview.local\r\n\r\n" + message);
    }

    private HttpResponse placeholderResponse(String message) {
        return httpResponse("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + message);
    }

    private void analyzeSelectedArtifacts() {
        List<GwtArtifact> selected = selectedArtifacts();
        if (selected.isEmpty()) {
            setAnalysisText("Select one or more artifact rows first.", Collections.emptyList(), "", "Analyze Selected");
            return;
        }

        AnalysisAccumulator acc = new AnalysisAccumulator();
        boolean deepCacheLookup = dashboard == null || !dashboard.fastAnalyzeCheckBox.isSelected();
        for (GwtArtifact artifact : selected) {
            analyzeArtifactInto(acc, artifact, true, deepCacheLookup);
        }
        setAnalysisText(acc.summary.toString(), new ArrayList<>(acc.methods), acc.headers.toString(), "Analyze Selected (" + selected.size() + " item(s))");
    }

    private void analyzeHttpHistory() {
        if (historyFuture != null && !historyFuture.isDone()) {
            return;
        }

        final boolean scopeOnly = dashboard.scopeOnlyHistoryCheckBox.isSelected();
        cancelHistoryFlag.set(false);
        dashboard.cancelHistoryButton.setEnabled(true);
        dashboard.historyProgressLabel.setText("Running...");
        setAnalysisText("Analyzing full HTTP proxy history...", Collections.emptyList(), "", "History Analysis Started");

        historyFuture = historyExecutor.submit(() -> {
            AnalysisAccumulator acc = new AnalysisAccumulator();
            int total = 0;
            int matched = 0;
            int artifactsAdded = 0;

            try {
                for (var item : api.proxy().history()) {
                    if (cancelHistoryFlag.get()) {
                        break;
                    }

                    HttpRequest req = item.request();
                    if (!AnalysisPolicy.shouldProcessHistoryItem(scopeOnly, req.isInScope())) {
                        continue;
                    }

                    total++;
                    HttpResponse resp = item.hasResponse() ? item.response() : null;
                    HttpRequestResponse message = item.hasResponse() ? httpRequestResponse(req, resp) : null;

                    String reqPath = req.pathWithoutQuery();
                    String reqUrl = req.url();
                    String reqHost = req.httpService().host();
                    int added = detectAndRecordArtifacts(req, message, "history", passiveMaxBodyBytes);
                    boolean rowMatched = added > 0;
                    artifactsAdded += added;
                    if (rowMatched) {
                        matched++;
                        analyzeArtifactInto(acc, new GwtArtifact(reqHost, reqPath, "History Entry", reqUrl, "history", now(), req, message), false, false);
                    }

                    if (total % 100 == 0) {
                        int progressCount = total;
                        SwingUtilities.invokeLater(() -> dashboard.historyProgressLabel.setText("Processed " + progressCount + " items"));
                    }
                }

                StringBuilder summary = new StringBuilder();
                if (cancelHistoryFlag.get()) {
                    summary.append("History analysis canceled by user.\n");
                } else {
                    summary.append("History Analysis Complete\n");
                }
                summary.append("Total Processed Items: ").append(total).append('\n');
                summary.append("Matched GWT Items: ").append(matched).append('\n');
                summary.append("New Artifacts Added: ").append(artifactsAdded).append('\n');
                acc.summary.insert(0, summary + "\n");

                SwingUtilities.invokeLater(() -> {
                    setAnalysisText(acc.summary.toString(), new ArrayList<>(acc.methods), acc.headers.toString(), "History Analysis Result");
                    dashboard.historyProgressLabel.setText(cancelHistoryFlag.get() ? "Canceled" : "Done");
                    dashboard.cancelHistoryButton.setEnabled(false);
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    setAnalysisText("History analysis failed: " + ex.getMessage(), Collections.emptyList(), "", "History Analysis Failed");
                    dashboard.historyProgressLabel.setText("Failed");
                    dashboard.cancelHistoryButton.setEnabled(false);
                });
            }
        });
    }

    private List<HttpRequestResponse> selectedRequestResponsesFromContext(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = new ArrayList<>(event.selectedRequestResponses());
        if (!selected.isEmpty()) {
            return selected;
        }
        Optional<burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse> editor = event.messageEditorRequestResponse();
        if (editor.isPresent()) {
            selected.add(editor.get().requestResponse());
        }
        return selected;
    }

    private void analyzeFromContext(List<HttpRequestResponse> selected) {
        AnalysisAccumulator acc = new AnalysisAccumulator();
        int added = 0;
        int analyzed = 0;
        for (HttpRequestResponse rr : selected) {
            HttpRequest req = rr.request();
            String reqPath = req.pathWithoutQuery();
            String reqUrl = req.url();
            String reqHost = req.httpService().host();

            int found = detectAndRecordArtifacts(req, rr, "context", passiveMaxBodyBytes);
            added += found;
            boolean matched = found > 0;

            if (matched) {
                analyzed++;
                analyzeArtifactInto(acc, new GwtArtifact(reqHost, reqPath, "Context Entry", reqUrl, "context", now(), req, rr), false, false);
            }
        }

        final int finalAdded = added;
        final int finalAnalyzed = analyzed;
        SwingUtilities.invokeLater(() -> {
            if (finalAnalyzed == 0) {
                setAnalysisText("No GWT request/response patterns detected in selected item(s).", Collections.emptyList(), "", "Context Analyze");
            } else {
                String summary = "Context Analyze Complete\nSelected Items: " + selected.size() +
                        "\nAnalyzed GWT Items: " + finalAnalyzed +
                        "\nNew Artifacts Added: " + finalAdded + "\n\n" + acc.summary;
                setAnalysisText(summary, new ArrayList<>(acc.methods), acc.headers.toString(), "Context Analyze");
                workTabs.setSelectedIndex(0);
            }
        });
    }

    private void sendFromContextToIntruder(List<HttpRequestResponse> selected) {
        int sent = 0;
        for (HttpRequestResponse rr : selected) {
            HttpRequest req = rr.request();
            if (!GwtDetector.looksLikeGwtRpcRequest(req)) {
                continue;
            }
            List<burp.api.montoya.core.Range> positions = detectGwtIntruderPositions(req);
            if (positions.isEmpty()) {
                continue;
            }
            String method = detectRpcMethodName(req);
            String tabName = method.isEmpty() ? "GWT-RPC" : method;
            HttpRequestTemplate template = HttpRequestTemplate.httpRequestTemplate(req, positions);
            api.intruder().sendToIntruder(req.httpService(), template, tabName);
            sent++;
        }
        int finalSent = sent;
        SwingUtilities.invokeLater(() -> {
            if (finalSent == 0) {
                setAnalysisText("No eligible GWT RPC request found for Intruder payload positioning.", Collections.emptyList(), "", "Context Intruder");
            } else {
                setAnalysisText("Sent " + finalSent + " request(s) to Intruder with auto-detected GWT payload positions.", Collections.emptyList(), "", "Context Intruder");
                workTabs.setSelectedIndex(0);
            }
        });
    }

    private String detectRpcMethodName(HttpRequest request) {
        List<GwtRpcParser.RpcRow> rows = GwtRpcParser.parseRequest(request.bodyToString());
        return findResolved(rows, "Method Ref");
    }

    private List<burp.api.montoya.core.Range> detectGwtIntruderPositions(HttpRequest request) {
        String body = safe(request.bodyToString());
        if (body.isEmpty()) {
            return Collections.emptyList();
        }

        List<TokenSpan> tokens = tokenizePipeWithOffsets(body);
        if (tokens.size() < 8) {
            return Collections.emptyList();
        }

        int stringCount = parseIntOr(tokens.get(2).text, -1);
        if (stringCount < 0) {
            return Collections.emptyList();
        }
        int payloadStart = 3 + stringCount;
        if (payloadStart + 5 > tokens.size()) {
            return Collections.emptyList();
        }

        int bodyOffset = request.bodyOffset();
        List<burp.api.montoya.core.Range> ranges = new ArrayList<>();
        int paramCount = parseIntOr(tokens.get(payloadStart + 4).text, -1);
        int valuesStart = payloadStart + 5;
        if (paramCount > 0) {
            int valuesEnd = Math.min(tokens.size(), valuesStart + paramCount);
            for (int i = valuesStart; i < valuesEnd; i++) {
                TokenSpan t = tokens.get(i);
                ranges.add(range(bodyOffset + t.start, bodyOffset + t.end));
            }
        }

        if (ranges.isEmpty()) {
            for (int i = valuesStart; i < tokens.size(); i++) {
                TokenSpan t = tokens.get(i);
                ranges.add(range(bodyOffset + t.start, bodyOffset + t.end));
            }
        }
        return ranges;
    }

    private List<TokenSpan> tokenizePipeWithOffsets(String body) {
        List<TokenSpan> spans = new ArrayList<>();
        int tokenStart = 0;
        for (int i = 0; i <= body.length(); i++) {
            boolean atDelimiter = i == body.length() || body.charAt(i) == '|';
            if (!atDelimiter) {
                continue;
            }
            if (i > tokenStart) {
                spans.add(new TokenSpan(body.substring(tokenStart, i), tokenStart, i));
            }
            tokenStart = i + 1;
        }
        return spans;
    }

    private int detectAndRecordArtifacts(HttpRequest req, HttpRequestResponse message,
                                         String sourceLabel,
                                         int responseBodyLimitBytes) {
        int count = 0;
        String reqPath = req.pathWithoutQuery();
        String reqUrl = req.url();
        String reqHost = req.httpService().host();
        if (GwtDetector.isPotentialGwtPath(reqPath)) {
            count += recordArtifactFromHistory(reqHost, reqPath, GwtDetector.classifyArtifact(reqPath),
                    reqUrl, sourceLabel + " request path", req, message);
        }
        if (GwtDetector.looksLikeGwtRpcRequest(req)) {
            count += recordArtifactFromHistory(reqHost, reqPath, "GWT RPC Endpoint",
                    reqUrl, sourceLabel + " rpc request", req, message);
        }
        if (message != null && message.hasResponse()) {
            int responseSize = message.response().toByteArray().length();
            if (AnalysisPolicy.shouldExtractResponseArtifacts(responseSize, responseBodyLimitBytes)) {
                String body = safe(message.response().bodyToString());
                for (String found : GwtDetector.extractArtifactPaths(body)) {
                    String resolved = GwtDetector.resolvePath(reqUrl, found);
                    count += recordArtifactFromHistory(GwtDetector.hostFromUrl(reqUrl), found,
                            GwtDetector.classifyArtifact(found), resolved,
                            sourceLabel + " response body", req, message);
                }
            } else {
                api.logging().logToOutput("[GWT Mapper] Skipping response artifact extraction for oversized response (" + responseSize + " bytes): " + reqUrl);
            }
        }
        return count;
    }

    private int recordArtifactFromHistory(String host, String path, String type, String resolvedUrl, String source, HttpRequest sourceRequest, HttpRequestResponse sourceMessage) {
        return recordArtifact(host, path, type, resolvedUrl, source, sourceRequest, sourceMessage) ? 1 : 0;
    }

    private void analyzeArtifactInto(AnalysisAccumulator acc, GwtArtifact artifact, boolean includeArtifactHeader, boolean deepCacheLookup) {
        if (includeArtifactHeader) {
            acc.summary.append("Artifact: ").append(artifact.type).append('\n');
            acc.summary.append("URL: ").append(artifact.resolvedUrl).append('\n');
            acc.summary.append("Source: ").append(artifact.source).append("\n\n");
        }

        HttpRequest request = artifact.sourceRequest;
        if (request != null) {
            appendGwtHeaders(acc.summary, request);
            appendGwtHeaders(acc.headers, request);

            List<GwtRpcParser.RpcRow> requestRows = GwtRpcParser.parseRequest(request.bodyToString());
            String protocol = findResolved(requestRows, "Protocol Version");
            String service = findResolved(requestRows, "Service Interface Ref");
            String method = findResolved(requestRows, "Method Ref");
            if (!protocol.isEmpty()) {
                acc.summary.append("Protocol Version: ").append(protocol).append('\n');
            }
            if (!service.isEmpty()) {
                acc.summary.append("Service: ").append(service).append('\n');
            }
            if (!method.isEmpty()) {
                acc.summary.append("Method: ").append(method).append('\n');
                acc.methods.add(method);
            }
        }

        if (artifact.sourceMessage != null && artifact.sourceMessage.hasResponse()) {
            String responseBody = safe(artifact.sourceMessage.response().bodyToString());
            int bytes = artifact.sourceMessage.response().toByteArray().length();
            acc.summary.append("Response Size: ").append(bytes).append(" bytes\n");
            if (bytes <= PREVIEW_MAX_BYTES) {
                String version = MethodExtractor.extractGwtVersion(responseBody);
                if (!version.isEmpty()) {
                    acc.summary.append("GWT Version Hint: ").append(version).append('\n');
                }
                acc.methods.addAll(MethodExtractor.extractMethodHints(responseBody));
                acc.methods.addAll(MethodExtractor.extractCacheMethodsLikeGwtMap(responseBody));
            } else {
                acc.summary.append("Response body skipped (TOO BIG FILE)\n");
            }
        }

        // If this is an RPC endpoint, try analyzing related permutation cache.js
        if (deepCacheLookup && "GWT RPC Endpoint".equals(artifact.type)) {
            String cacheAnalysis = analyzeRelatedCacheFromRpc(artifact);
            if (!cacheAnalysis.isEmpty()) {
                acc.summary.append(cacheAnalysis).append('\n');
            }
        }
        acc.summary.append('\n');
    }

    private StringBuilder appendGwtHeaders(StringBuilder sb, HttpRequest request) {
        boolean found = false;
        try {
            for (var header : request.headers()) {
                String name = safe(header.name());
                String lower = name.toLowerCase();
                if (lower.startsWith("x-gwt-") || lower.equals("content-type")) {
                    sb.append(name).append(": ").append(safe(header.value())).append('\n');
                    found = true;
                }
            }
        } catch (Exception ignored) {
            sb.append("Header extraction failed for this request.\n");
            return sb;
        }
        if (!found) {
            sb.append("No GWT-specific headers found.\n");
        }
        return sb;
    }

    private String analyzeRelatedCacheFromRpc(GwtArtifact artifact) {
        if (artifact.sourceRequest == null) {
            return "";
        }
        String permutation = "";
        String moduleBase = "";
        try {
            for (var h : artifact.sourceRequest.headers()) {
                String n = safe(h.name()).toLowerCase();
                if ("x-gwt-permutation".equals(n)) {
                    permutation = safe(h.value()).trim();
                } else if ("x-gwt-module-base".equals(n)) {
                    moduleBase = safe(h.value()).trim();
                }
            }
        } catch (Exception ex) {
            api.logging().logToError("[GWT Mapper] Cache header extraction failed: " + ex.getMessage());
            return "";
        }
        if (permutation.isEmpty() || moduleBase.isEmpty()) {
            return "";
        }
        String cacheUrl = moduleBase + (moduleBase.endsWith("/") ? "" : "/") + permutation + ".cache.js";
        try {
            HttpRequest req = httpRequest(cacheUrl);
            HttpRequestResponse rr = api.http().sendRequest(req);
            if (!rr.hasResponse()) {
                return "";
            }
            // Add related permutation to dashboard immediately.
            recordArtifact(
                    GwtDetector.hostFromUrl(cacheUrl),
                    extractPath(cacheUrl),
                    "GWT Cache JS",
                    cacheUrl,
                    "analysis related cache",
                    req,
                    rr
            );
            String body = safe(rr.response().bodyToString());
            if (rr.response().toByteArray().length() > PREVIEW_MAX_BYTES) {
                return "Related cache.js detected but too big to analyze: " + cacheUrl;
            }
            // Add nested references found in related cache.js to dashboard.
            for (String found : GwtDetector.extractArtifactPaths(body)) {
                String resolved = GwtDetector.resolvePath(cacheUrl, found);
                recordArtifact(
                        GwtDetector.hostFromUrl(resolved),
                        found,
                        GwtDetector.classifyArtifact(found),
                        resolved,
                        "analysis related cache ref",
                        req,
                        rr
                );
            }
            Set<String> methods = MethodExtractor.extractCacheMethodsLikeGwtMap(body);
            if (methods.isEmpty()) {
                return "Related cache.js analyzed, no method hints extracted: " + cacheUrl;
            }
            return "Related cache.js method hints (" + methods.size() + "): " + String.join(", ", methods.stream().limit(20).toList());
        } catch (Exception ex) {
            api.logging().logToError("[GWT Mapper] Related cache analysis failed: " + ex.getMessage());
            return "";
        }
    }

    private String extractPath(String url) {
        try {
            var uri = java.net.URI.create(url);
            return safe(uri.getPath());
        } catch (Exception ex) {
            return url;
        }
    }

    private String findResolved(List<GwtRpcParser.RpcRow> rows, String fieldName) {
        for (GwtRpcParser.RpcRow row : rows) {
            if (row.field().equals(fieldName)) {
                return safe(row.resolved());
            }
        }
        return "";
    }

    private final class DashboardPanel extends JPanel {
        final DefaultTableModel artifactsModel;
        final JTable artifactsTable;
        final TableRowSorter<DefaultTableModel> rowSorter;
        final JTextField outputFolderField;
        final JTextField passiveMaxBodyBytesField;
        final JTextField filterField;
        final JCheckBox passiveScanCheckBox;
        final JCheckBox scopeOnlyHistoryCheckBox;
        final JCheckBox fastAnalyzeCheckBox;
        final JButton cancelHistoryButton;
        final JLabel historyProgressLabel;
        final HttpRequestEditor requestPreviewEditor;
        final HttpResponseEditor responsePreviewEditor;
        final JTextArea analysisSummaryArea;
        final JTextArea analysisHeadersArea;
        final JTextArea analysisRunsArea;
        final DefaultTableModel methodsTableModel;
        final JTable methodsTable;
        final JTabbedPane analysisTabs;

        DashboardPanel() {
            super(new BorderLayout());

            JPanel top = new JPanel(new GridLayout(3, 1, 6, 6));
            JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JPanel row3 = new JPanel(new FlowLayout(FlowLayout.LEFT));

            outputFolderField = new JTextField(loadOutputDirectory(), 45);
            passiveMaxBodyBytesField = new JTextField(String.valueOf(passiveMaxBodyBytes), 8);

            JButton browseButton = new JButton("Browse...");
            browseButton.addActionListener(e -> chooseFolder());

            JButton saveSettingsButton = new JButton("Save Settings");
            saveSettingsButton.addActionListener(e -> persistSettings());

            passiveScanCheckBox = new JCheckBox("Enable Passive Scan", loadPassiveScanEnabled());
            passiveScanCheckBox.addActionListener(e -> persistSettings());

            JButton downloadSelectedButton = new JButton("Download Selected");
            downloadSelectedButton.addActionListener(e -> downloadSelected());

            JButton downloadAllButton = new JButton("Download All");
            downloadAllButton.addActionListener(e -> downloadAll());

            JButton tempFolderButton = new JButton("Use Temporary Folder");
            tempFolderButton.addActionListener(e -> useTempFolder());

            JButton clearButton = new JButton("Clear Artifacts");
            clearButton.addActionListener(e -> clearArtifacts());

            JButton exportCsvButton = new JButton("Export CSV");
            exportCsvButton.addActionListener(e -> exportCsv());
            JButton exportMethodsButton = new JButton("Export Methods");
            exportMethodsButton.addActionListener(e -> exportMethodsCsv());
            JButton analyzeSelectedButton = new JButton("Analyze Selected Item(s)");
            analyzeSelectedButton.addActionListener(e -> analyzeSelectedArtifacts());
            JButton analyzeHistoryButton = new JButton("Analyze HTTP History");
            analyzeHistoryButton.addActionListener(e -> analyzeHttpHistory());
            cancelHistoryButton = new JButton("Cancel History Analysis");
            cancelHistoryButton.setEnabled(false);
            cancelHistoryButton.addActionListener(e -> cancelHistoryFlag.set(true));

            filterField = new JTextField(28);
            JButton applyFilterButton = new JButton("Apply Filter");
            applyFilterButton.addActionListener(e -> applyFilter());
            scopeOnlyHistoryCheckBox = new JCheckBox("Scope-Only History", loadScopeOnlyHistory());
            scopeOnlyHistoryCheckBox.addActionListener(e -> persistSettings());
            fastAnalyzeCheckBox = new JCheckBox("Fast Analyze (skip cache fetch)", loadFastAnalyze());
            fastAnalyzeCheckBox.addActionListener(e -> persistSettings());
            historyProgressLabel = new JLabel("Idle");

            row1.add(new JLabel("Download Folder:"));
            row1.add(outputFolderField);
            row1.add(browseButton);
            row1.add(saveSettingsButton);
            row1.add(passiveScanCheckBox);
            row1.add(new JLabel("Passive Max Body (bytes):"));
            row1.add(passiveMaxBodyBytesField);

            row2.add(downloadSelectedButton);
            row2.add(downloadAllButton);
            row2.add(tempFolderButton);
            row2.add(clearButton);
            row2.add(exportCsvButton);
            row2.add(exportMethodsButton);
            row2.add(analyzeSelectedButton);
            row2.add(analyzeHistoryButton);

            row3.add(new JLabel("Filter:"));
            row3.add(filterField);
            row3.add(applyFilterButton);
            row3.add(scopeOnlyHistoryCheckBox);
            row3.add(fastAnalyzeCheckBox);
            row3.add(cancelHistoryButton);
            row3.add(historyProgressLabel);

            top.add(row1);
            top.add(row2);
            top.add(row3);

            artifactsModel = new DefaultTableModel(new Object[]{
                    "Host", "Artifact Path", "Type", "Resolved URL", "Source", "Discovered At"
            }, 0) {
                @Override
                public boolean isCellEditable(int row, int column) {
                    return false;
                }
            };

            artifactsTable = new JTable(artifactsModel);
            rowSorter = new TableRowSorter<>(artifactsModel);
            artifactsTable.setRowSorter(rowSorter);
            artifactsTable.getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) {
                    updateSelectedPreview();
                }
            });

            requestPreviewEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
            responsePreviewEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
            analysisSummaryArea = createReadOnlyTextArea();
            analysisHeadersArea = createReadOnlyTextArea();
            analysisRunsArea = createReadOnlyTextArea();
            methodsTableModel = new DefaultTableModel(new Object[]{"Method"}, 0) {
                @Override
                public boolean isCellEditable(int row, int column) {
                    return false;
                }
            };
            methodsTable = new JTable(methodsTableModel);
            methodsTable.setRowSorter(new TableRowSorter<>(methodsTableModel));
            analysisTabs = new JTabbedPane();
            analysisTabs.addTab("Summary", new JScrollPane(analysisSummaryArea));
            analysisTabs.addTab("Methods", new JScrollPane(methodsTable));
            analysisTabs.addTab("Headers", new JScrollPane(analysisHeadersArea));
            analysisTabs.addTab("Runs", new JScrollPane(analysisRunsArea));
            requestPreviewEditor.setRequest(placeholderRequest("Select an artifact row to preview request."));
            responsePreviewEditor.setResponse(placeholderResponse("Select an artifact row to preview response."));
            String initMsg = "Click 'Analyze Selected Item(s)' to extract GWT methods/version/headers.";
            analysisSummaryArea.setText(initMsg);
            analysisHeadersArea.setText("");
            analysisRunsArea.insert("=== Initial State ===\n" + initMsg + "\n\n", 0);

            JPanel previews = new JPanel(new GridLayout(1, 3, 6, 6));
            previews.add(wrapTitled("Request Preview", requestPreviewEditor.uiComponent()));
            previews.add(wrapTitled("Response Preview", responsePreviewEditor.uiComponent()));
            previews.add(wrapTitled("Analysis", analysisTabs));

            JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(artifactsTable), previews);
            split.setResizeWeight(0.60);

            add(top, BorderLayout.NORTH);
            add(split, BorderLayout.CENTER);
        }

        private JTextArea createReadOnlyTextArea() {
            JTextArea area = new JTextArea();
            area.setEditable(false);
            area.setLineWrap(true);
            area.setWrapStyleWord(true);
            return area;
        }

        private JPanel wrapTitled(String title, Component component) {
            JPanel panel = new JPanel(new BorderLayout());
            panel.setBorder(BorderFactory.createTitledBorder(title));
            panel.add(component, BorderLayout.CENTER);
            return panel;
        }
    }

    private static final class AnalysisAccumulator {
        private final StringBuilder summary = new StringBuilder();
        private final Set<String> methods = new LinkedHashSet<>();
        private final StringBuilder headers = new StringBuilder();
    }

    private static final class TokenSpan {
        private final String text;
        private final int start;
        private final int end;

        private TokenSpan(String text, int start, int end) {
            this.text = text;
            this.start = start;
            this.end = end;
        }
    }

    private static final class RpcTableModel extends DefaultTableModel {
        private RpcTableModel() {
            super(new Object[]{"Index", "Field", "Raw", "Resolved"}, 0);
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }

        private void setRows(List<GwtRpcParser.RpcRow> rows) {
            setRowCount(0);
            for (GwtRpcParser.RpcRow row : rows) {
                addRow(new Object[]{row.index(), row.field(), row.raw(), row.resolved()});
            }
        }
    }

    private final class GwtRequestEditor implements ExtensionProvidedHttpRequestEditor {
        private final JPanel panel;
        private final RpcTableModel model;
        private HttpRequestResponse current;

        private GwtRequestEditor() {
            panel = new JPanel(new BorderLayout());
            model = new RpcTableModel();
            panel.add(new JScrollPane(new JTable(model)), BorderLayout.CENTER);
        }

        @Override
        public HttpRequest getRequest() {
            return current == null ? null : current.request();
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            current = requestResponse;
            if (requestResponse == null) {
                model.setRows(Collections.emptyList());
                return;
            }
            model.setRows(GwtRpcParser.parseRequest(requestResponse.request().bodyToString()));
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            return requestResponse != null && GwtDetector.looksLikeGwtRpcRequest(requestResponse.request());
        }

        @Override
        public String caption() {
            return "GWT";
        }

        @Override
        public java.awt.Component uiComponent() {
            return panel;
        }

        @Override
        public Selection selectedData() {
            return null;
        }

        @Override
        public boolean isModified() {
            return false;
        }
    }

    private final class GwtResponseEditor implements ExtensionProvidedHttpResponseEditor {
        private final JPanel panel;
        private final RpcTableModel model;
        private HttpRequestResponse current;

        private GwtResponseEditor() {
            panel = new JPanel(new BorderLayout());
            model = new RpcTableModel();
            panel.add(new JScrollPane(new JTable(model)), BorderLayout.CENTER);
        }

        @Override
        public HttpResponse getResponse() {
            return current == null ? null : current.response();
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            current = requestResponse;
            if (requestResponse == null || !requestResponse.hasResponse()) {
                model.setRows(Collections.emptyList());
                return;
            }
            model.setRows(GwtRpcParser.parseResponse(requestResponse.response().bodyToString()));
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            if (requestResponse == null || !requestResponse.hasResponse()) {
                return false;
            }
            String body = safe(requestResponse.response().bodyToString()).trim();
            return body.startsWith("//OK") || body.startsWith("//EX") || body.matches("^\\d+\\|\\d+\\|.*");
        }

        @Override
        public String caption() {
            return "GWT";
        }

        @Override
        public java.awt.Component uiComponent() {
            return panel;
        }

        @Override
        public Selection selectedData() {
            return null;
        }

        @Override
        public boolean isModified() {
            return false;
        }
    }
}
