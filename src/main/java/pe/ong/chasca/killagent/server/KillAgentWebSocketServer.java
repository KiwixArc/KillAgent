package pe.ong.chasca.killagent.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.java_websocket.WebSocket;
import org.java_websocket.drafts.Draft;
import org.java_websocket.exceptions.InvalidDataException;
import org.java_websocket.framing.CloseFrame;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.handshake.ServerHandshakeBuilder;
import org.java_websocket.server.DefaultSSLWebSocketServerFactory;
import org.java_websocket.server.WebSocketServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pe.ong.chasca.killagent.config.AgentConfig;
import pe.ong.chasca.killagent.config.AgentVersion;
import pe.ong.chasca.killagent.config.ConfigurationLoader;
import pe.ong.chasca.killagent.crypto.AuthChallengeResult;
import pe.ong.chasca.killagent.crypto.CryptoOperationException;
import pe.ong.chasca.killagent.crypto.CryptoService;
import pe.ong.chasca.killagent.crypto.DocumentDigestResult;
import pe.ong.chasca.killagent.hardware.CardReaderManager;
import pe.ong.chasca.killagent.hardware.CardType;
import pe.ong.chasca.killagent.hardware.HardwareListener;
import pe.ong.chasca.killagent.hardware.HardwareStatus;
import pe.ong.chasca.killagent.security.LoopbackSslContextFactory;
import pe.ong.chasca.killagent.security.OriginValidator;
import pe.ong.chasca.killagent.server.dto.*;
import pe.ong.chasca.killagent.ui.CardWaitProvider;
import pe.ong.chasca.killagent.ui.PinPromptProvider;
import pe.ong.chasca.killagent.ui.SwingCardWaitProvider;
import pe.ong.chasca.killagent.ui.SwingPinPromptProvider;
import pe.ong.chasca.killagent.ui.SystemTrayManager;

import javax.net.ssl.SSLContext;
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Hardened loopback-only (127.0.0.1) WebSocket / WSS server mediating Zero Trust cryptographic
 * operations between the Ch'aska React SPA and local PKCS#11 DNIe smart cards.
 */
public class KillAgentWebSocketServer extends WebSocketServer implements HardwareListener {

    private static final Logger logger = LoggerFactory.getLogger(KillAgentWebSocketServer.class);
    private static final String VERSION = AgentVersion.getVersion();
    private static final int MAX_PAYLOAD_CHARS = 32_768;
    private static final int PIN_PROMPT_TIMEOUT_SECONDS = 30;
    private static final String STATION_BUSY_MESSAGE =
            "Ya existe una solicitud de verificación con PIN activa en esta estación.";
    private static final String DEFAULT_AUTH_OPERATION_TITLE = "Verificación de Seguridad DNIe";
    private static final String DEFAULT_AUTH_OPERATION_DESCRIPTION =
            "Autenticación Institucional Ch'aska (Verificación DNIe)";

    private final AgentConfig config;
    private final CardReaderManager cardReaderManager;
    private final CryptoService cryptoService;
    private final SystemTrayManager trayManager;
    private final PinPromptProvider pinPromptProvider;
    private final CardWaitProvider cardWaitProvider;
    private final OriginValidator originValidator;
    private final ObjectMapper objectMapper;

    private final Map<WebSocket, String> connectionIds = new ConcurrentHashMap<>();
    private final Semaphore hardwareOperationLock = new Semaphore(1);
    private final AtomicReference<WebSocket> activeOperationConnection = new AtomicReference<>();
    private final AtomicReference<String> activeOperationRequestId = new AtomicReference<>();
    private final ExecutorService cryptoWorkerExecutor;
    private final CountDownLatch startedLatch = new CountDownLatch(1);

    public KillAgentWebSocketServer(
            AgentConfig config,
            CardReaderManager cardReaderManager,
            CryptoService cryptoService,
            SystemTrayManager trayManager
    ) {
        this(config, cardReaderManager, cryptoService, trayManager, new SwingPinPromptProvider(), new SwingCardWaitProvider());
    }

    public KillAgentWebSocketServer(
            AgentConfig config,
            CardReaderManager cardReaderManager,
            CryptoService cryptoService,
            SystemTrayManager trayManager,
            PinPromptProvider pinPromptProvider
    ) {
        this(config, cardReaderManager, cryptoService, trayManager, pinPromptProvider, new SwingCardWaitProvider());
    }

    public KillAgentWebSocketServer(
            AgentConfig config,
            CardReaderManager cardReaderManager,
            CryptoService cryptoService,
            SystemTrayManager trayManager,
            PinPromptProvider pinPromptProvider,
            CardWaitProvider cardWaitProvider
    ) {
        super(validateAndCreateLoopbackAddress(config));
        this.config = config;
        this.cardReaderManager = cardReaderManager;
        this.cryptoService = cryptoService;
        this.trayManager = trayManager;
        this.pinPromptProvider = pinPromptProvider != null ? pinPromptProvider : new SwingPinPromptProvider();
        this.cardWaitProvider = cardWaitProvider != null ? cardWaitProvider : new SwingCardWaitProvider();
        this.originValidator = new OriginValidator(config);
        this.objectMapper = new ObjectMapper();
        this.cryptoWorkerExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "killagent-crypto-worker");
            t.setDaemon(true);
            return t;
        });

        setReuseAddr(true);
        setTcpNoDelay(true);
        setConnectionLostTimeout(30);

        if (config.secureWss()) {
            configureTlsTransport(config);
        }

        this.cardReaderManager.addListener(this);
    }

    private static InetSocketAddress validateAndCreateLoopbackAddress(AgentConfig config) {
        ConfigurationLoader.validateLoopbackHost(config.host());
        return new InetSocketAddress(config.host().trim(), config.port());
    }

    private void configureTlsTransport(AgentConfig config) {
        try {
            SSLContext sslContext = LoopbackSslContextFactory.createSslContext(config);
            setWebSocketFactory(new DefaultSSLWebSocketServerFactory(sslContext));
        } catch (Exception e) {
            logger.error("Failed to initialize WSS TLS context: {}", e.getMessage(), e);
            throw new IllegalStateException("WSS TLS initialization failed", e);
        }
    }

    /**
     * Layer 1 Anti-CSWSH Defense: Rejects unauthorized Origin headers during HTTP Upgrade handshake
     * before a WebSocket session is even established.
     */
    @Override
    public ServerHandshakeBuilder onWebsocketHandshakeReceivedAsServer(
            WebSocket conn,
            Draft draft,
            ClientHandshake request
    ) throws InvalidDataException {
        ServerHandshakeBuilder builder = super.onWebsocketHandshakeReceivedAsServer(conn, draft, request);
        String origin = request.getFieldValue("Origin");
        if (!originValidator.isAllowed(origin)) {
            logger.warn("Blocked WebSocket HTTP upgrade from unauthorized Origin: '{}'", origin);
            throw new InvalidDataException(CloseFrame.REFUSE, "Origin not authorized by KILLAgent Zero Trust policy.");
        }
        return builder;
    }

    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {
        String origin = handshake.getFieldValue("Origin");
        // Layer 2 Defense-in-depth verification
        if (!originValidator.isAllowed(origin)) {
            logger.warn("Closing connection from unauthorized Origin: '{}'", origin);
            conn.close(CloseFrame.REFUSE, "Unauthorized Origin");
            return;
        }

        String wsConnectionId = "ws-killagent-" + UUID.randomUUID().toString().substring(0, 13);
        connectionIds.put(conn, wsConnectionId);
        notifyTrayConnectionCountChanged();

        HardwareStatus hwStatus = cardReaderManager.getStatus();
        ConnectionEstablishedMessage welcome = new ConnectionEstablishedMessage(wsConnectionId, VERSION, hwStatus);
        sendJson(conn, welcome);
        logger.info("WebSocket session established: id={}, origin={}", wsConnectionId, origin);
    }

    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {
        String id = connectionIds.remove(conn);
        notifyTrayConnectionCountChanged();
        if (activeOperationConnection.compareAndSet(conn, null)) {
            String abortedRequestId = activeOperationRequestId.getAndSet(null);
            logger.info(
                    "Client WebSocket closed during active hardware operation (id={}, requestId={}); aborting modal so hardware lock is released.",
                    id,
                    abortedRequestId
            );
            cardWaitProvider.abortActiveWait(CardWaitProvider.WaitOutcome.CLIENT_DISCONNECTED);
            pinPromptProvider.abortActivePrompt(PinPromptProvider.AbortReason.CLIENT_DISCONNECTED);
        }
        logger.info("WebSocket session closed: id={}, code={}, remote={}", id, code, remote);
    }

    @Override
    public void onMessage(WebSocket conn, String message) {
        if (message == null || message.length() > MAX_PAYLOAD_CHARS) {
            sendJson(conn, new ErrorMessage(null, ErrorCode.MALFORMED_REQUEST, "Payload size invalid or exceeds limit."));
            return;
        }

        try {
            JsonNode root = objectMapper.readTree(message);
            if (root == null || !root.isObject()) {
                sendJson(conn, new ErrorMessage(null, ErrorCode.MALFORMED_REQUEST, "Expected JSON object message."));
                return;
            }

            String type = root.hasNonNull("type") ? root.get("type").asText().trim() : "";
            String requestId = root.hasNonNull("requestId")
                    ? root.get("requestId").asText().trim()
                    : UUID.randomUUID().toString();

            logger.info("Processing incoming command: type={}, requestId={}", type, requestId);

            switch (type) {
                case "SIGN_AUTH_CHALLENGE" -> handleSignAuthChallenge(conn, root, requestId);
                case "SIGN_DOCUMENT_DIGEST" -> handleSignDocumentDigest(conn, root, requestId);
                case "CANCEL_ACTIVE_OPERATION" -> handleCancelActiveOperation(conn, requestId);
                case "GET_HARDWARE_STATUS", "PING" -> sendJson(
                        conn,
                        new HardwareStatusResponseMessage(requestId, cardReaderManager.getStatus())
                );
                default -> {
                    logger.warn("Unsupported command type '{}' (requestId={})", type, requestId);
                    sendJson(conn, new ErrorMessage(
                            requestId,
                            ErrorCode.MALFORMED_REQUEST,
                            "Tipo de operación no soportado: " + type
                    ));
                }
            }
        } catch (Exception e) {
            logger.warn("Malformed JSON frame received: {}", e.getMessage());
            sendJson(conn, new ErrorMessage(null, ErrorCode.MALFORMED_REQUEST, "Formato JSON inválido."));
        }
    }

    private void handleCancelActiveOperation(WebSocket conn, String requestId) {
        if (conn != null && conn == activeOperationConnection.get()) {
            logger.info(
                    "Client requested cancellation of active hardware operation (cancelRequestId={}, activeRequestId={}).",
                    requestId,
                    activeOperationRequestId.get()
            );
            cardWaitProvider.abortActiveWait(CardWaitProvider.WaitOutcome.USER_CANCELLED);
            pinPromptProvider.abortActivePrompt(PinPromptProvider.AbortReason.USER_CANCELLED);
        } else {
            logger.debug("Ignoring CANCEL_ACTIVE_OPERATION from non-owning or idle connection (requestId={}).", requestId);
        }
    }

    private void handleSignAuthChallenge(WebSocket conn, JsonNode root, String requestId) {
        final SignAuthChallengeRequest request;
        try {
            request = objectMapper.treeToValue(root, SignAuthChallengeRequest.class);
        } catch (Exception e) {
            sendJson(conn, new ErrorMessage(requestId, ErrorCode.MALFORMED_REQUEST, "Esquema inválido para SIGN_AUTH_CHALLENGE."));
            return;
        }

        if (request.nonce() == null || request.nonce().isBlank()) {
            sendJson(conn, new ErrorMessage(requestId, ErrorCode.MALFORMED_REQUEST, "El campo 'nonce' es obligatorio."));
            return;
        }

        boolean waitForCard = Boolean.TRUE.equals(request.waitForCard());
        if (!waitForCard && !cardReaderManager.getStatus().cardPresent()) {
            sendJson(conn, new ErrorMessage(requestId, ErrorCode.CARD_NOT_PRESENT, "Inserte su DNIe en el lector para autenticarse."));
            return;
        }

        if (!hardwareOperationLock.tryAcquire()) {
            sendJson(conn, new ErrorMessage(
                    requestId,
                    ErrorCode.OPERATION_IN_PROGRESS,
                    STATION_BUSY_MESSAGE
            ));
            return;
        }
        activeOperationConnection.set(conn);
        activeOperationRequestId.set(requestId);

        try {
            cryptoWorkerExecutor.submit(() -> {
                try {
                    if (!conn.isOpen() || activeOperationConnection.get() != conn) {
                        logger.info("Client WebSocket disconnected before hardware operation started (requestId={}).", requestId);
                        return;
                    }
                    if (trayManager != null) trayManager.setBusyState(true);

                    String promptTitle = sanitizePlainTitle(
                            request.operationTitle(),
                            DEFAULT_AUTH_OPERATION_TITLE
                    );
                    String detailsHtml = (request.operationDescription() != null && !request.operationDescription().isBlank())
                            ? escapeHtml(request.operationDescription().trim())
                            : DEFAULT_AUTH_OPERATION_DESCRIPTION;

                    if (waitForCard && !cardReaderManager.getStatus().cardPresent()) {
                        CardWaitProvider.WaitOutcome waitOutcome = cardWaitProvider.waitForCard(
                                cardReaderManager,
                                promptTitle,
                                detailsHtml,
                                PIN_PROMPT_TIMEOUT_SECONDS
                        );
                        if (handleCardWaitAbortIfPresent(conn, requestId, waitOutcome)) {
                            return;
                        }
                        if (!conn.isOpen() || activeOperationConnection.get() != conn) {
                            logger.info("Client WebSocket disconnected before PIN prompt started (requestId={}).", requestId);
                            return;
                        }
                    }

                    PinPromptProvider.PinPromptResult pinPrompt = pinPromptProvider.requestPin(
                            promptTitle,
                            detailsHtml,
                            PIN_PROMPT_TIMEOUT_SECONDS
                    );

                    if (handlePinAbortIfPresent(
                            conn,
                            requestId,
                            pinPrompt,
                            "El DNIe fue retirado durante el ingreso del PIN.",
                            "Autenticación cancelada por el usuario."
                    )) {
                        return;
                    }

                    AuthChallengeResult result = cryptoService.signAuthChallenge(pinPrompt.pin(), request.nonce());
                    String wsConnId = connectionIds.getOrDefault(conn, "ws-killagent-unknown");
                    SignAuthChallengeResponse response = SignAuthChallengeResponse.success(
                            requestId,
                            result.nonce(),
                            result.signedNonce(),
                            result.clientCertificatePem(),
                            wsConnId,
                            result.metadata()
                    );
                    sendJson(conn, response);
                } catch (CryptoOperationException coe) {
                    logger.warn("Auth challenge failed [{}]: {}", coe.getErrorCode(), coe.getMessage());
                    sendJson(conn, new ErrorMessage(requestId, coe.getErrorCode(), coe.getMessage(), coe.getAttemptsRemaining()));
                } catch (Exception ex) {
                    logger.error("Unexpected error signing auth challenge: {}", ex.getMessage(), ex);
                    sendJson(conn, new ErrorMessage(requestId, ErrorCode.PKCS11_ERROR, "Error interno en operación criptográfica."));
                } finally {
                    releaseHardwareOperationLock(conn, requestId);
                }
            });
        } catch (RuntimeException rex) {
            releaseHardwareOperationLock(conn, requestId);
            throw rex;
        }
    }

    private void handleSignDocumentDigest(WebSocket conn, JsonNode root, String requestId) {
        final SignDocumentDigestRequest request;
        try {
            request = objectMapper.treeToValue(root, SignDocumentDigestRequest.class);
        } catch (Exception e) {
            sendJson(conn, new ErrorMessage(requestId, ErrorCode.MALFORMED_REQUEST, "Esquema inválido para SIGN_DOCUMENT_DIGEST."));
            return;
        }

        if (request.slotId() == null || request.slotId().isBlank()
                || request.documentHash() == null || request.documentHash().isBlank()) {
            sendJson(conn, new ErrorMessage(requestId, ErrorCode.MALFORMED_REQUEST, "Los campos 'slotId' y 'documentHash' son obligatorios."));
            return;
        }

        if (!cardReaderManager.getStatus().cardPresent()) {
            sendJson(conn, new ErrorMessage(requestId, ErrorCode.CARD_NOT_PRESENT, "Inserte su DNIe en el lector para firmar el documento."));
            return;
        }

        if (!hardwareOperationLock.tryAcquire()) {
            sendJson(conn, new ErrorMessage(
                    requestId,
                    ErrorCode.OPERATION_IN_PROGRESS,
                    STATION_BUSY_MESSAGE
            ));
            return;
        }
        activeOperationConnection.set(conn);
        activeOperationRequestId.set(requestId);

        try {
            cryptoWorkerExecutor.submit(() -> {
                try {
                    if (!conn.isOpen() || activeOperationConnection.get() != conn) {
                        logger.info("Client WebSocket disconnected before PIN prompt started (requestId={}).", requestId);
                        return;
                    }
                    if (trayManager != null) trayManager.setBusyState(true);

                    // Sanitize untrusted strings against Swing HTML tag injection
                    String safeTitle = escapeHtml(request.documentTitle() != null && !request.documentTitle().isBlank()
                            ? request.documentTitle()
                            : "Documento Institucional");
                    String safeHashPreview = escapeHtml(truncateHash(request.documentHash().trim()));
                    String safeRole = escapeHtml(request.signerRole() != null && !request.signerRole().isBlank()
                            ? request.signerRole()
                            : "SIGNER");

                    String detailsHtml = "Firma Digital PAdES-LTV: <b>" + safeTitle + "</b>"
                            + "<br>SHA-256: <tt>" + safeHashPreview + "</tt>"
                            + "<br>Rol del Firmante: <b>" + safeRole + "</b>";

                    PinPromptProvider.PinPromptResult pinPrompt = pinPromptProvider.requestPin(
                            "Firma Digital de Documento",
                            detailsHtml,
                            PIN_PROMPT_TIMEOUT_SECONDS
                    );

                    if (handlePinAbortIfPresent(
                            conn,
                            requestId,
                            pinPrompt,
                            "El DNIe fue retirado antes de completar la firma.",
                            "Firma de documento cancelada por el usuario."
                    )) {
                        return;
                    }

                    DocumentDigestResult result = cryptoService.signDocumentDigest(
                            pinPrompt.pin(),
                            request.slotId(),
                            request.documentHash()
                    );

                    SignDocumentDigestResponse response = SignDocumentDigestResponse.success(
                            requestId,
                            result.slotId(),
                            result.certificateDni(),
                            result.documentHash(),
                            result.signatureValue(),
                            result.signerSubjectDn(),
                            result.certificateSerialNumber(),
                            result.clientCertificatePem()
                    );
                    sendJson(conn, response);
                } catch (CryptoOperationException coe) {
                    logger.warn("Document digest signature failed [{}]: {}", coe.getErrorCode(), coe.getMessage());
                    sendJson(conn, new ErrorMessage(requestId, coe.getErrorCode(), coe.getMessage(), coe.getAttemptsRemaining()));
                } catch (Exception ex) {
                    logger.error("Unexpected error signing document digest: {}", ex.getMessage(), ex);
                    sendJson(conn, new ErrorMessage(requestId, ErrorCode.PKCS11_ERROR, "Error interno en firma digital de documento."));
                } finally {
                    releaseHardwareOperationLock(conn, requestId);
                }
            });
        } catch (RuntimeException rex) {
            releaseHardwareOperationLock(conn, requestId);
            throw rex;
        }
    }

    private boolean handleCardWaitAbortIfPresent(
            WebSocket conn,
            String requestId,
            CardWaitProvider.WaitOutcome waitOutcome
    ) {
        if (waitOutcome == CardWaitProvider.WaitOutcome.TIMEOUT) {
            sendJson(conn, new ErrorMessage(
                    requestId,
                    ErrorCode.CARD_NOT_PRESENT,
                    "Tiempo de espera agotado (30s): no se insertó ningún DNIe en la lectora."
            ));
            return true;
        }
        if (waitOutcome == CardWaitProvider.WaitOutcome.USER_CANCELLED) {
            sendJson(conn, new ErrorMessage(requestId, ErrorCode.USER_CANCELLED, "Operación cancelada por el usuario."));
            return true;
        }
        if (waitOutcome == CardWaitProvider.WaitOutcome.CLIENT_DISCONNECTED) {
            logger.info("Aborted card wait because client WebSocket disconnected (requestId={}).", requestId);
            return true;
        }
        if (waitOutcome != CardWaitProvider.WaitOutcome.CARD_READY) {
            sendJson(conn, new ErrorMessage(requestId, ErrorCode.USER_CANCELLED, "Operación cancelada por el usuario."));
            return true;
        }
        return false;
    }

    private boolean handlePinAbortIfPresent(
            WebSocket conn,
            String requestId,
            PinPromptProvider.PinPromptResult pinPrompt,
            String cardRemovedMessage,
            String cancelledMessage
    ) {
        PinPromptProvider.AbortReason abortReason = pinPrompt.abortReason();
        if (abortReason == PinPromptProvider.AbortReason.CARD_REMOVED) {
            sendJson(conn, new ErrorMessage(requestId, ErrorCode.CARD_NOT_PRESENT, cardRemovedMessage));
            return true;
        }
        if (abortReason == PinPromptProvider.AbortReason.TIMEOUT) {
            sendJson(conn, new ErrorMessage(
                    requestId,
                    ErrorCode.PIN_TIMEOUT,
                    "Tiempo de espera agotado (30s) para ingresar el PIN del DNIe."
            ));
            return true;
        }
        if (abortReason == PinPromptProvider.AbortReason.CLIENT_DISCONNECTED) {
            logger.info("Aborted cryptographic operation because client WebSocket disconnected (requestId={}).", requestId);
            return true;
        }
        if (!pinPrompt.isConfirmed()) {
            sendJson(conn, new ErrorMessage(requestId, ErrorCode.USER_CANCELLED, cancelledMessage));
            return true;
        }
        return false;
    }

    private void releaseHardwareOperationLock(WebSocket conn, String requestId) {
        activeOperationConnection.compareAndSet(conn, null);
        activeOperationRequestId.compareAndSet(requestId, null);
        hardwareOperationLock.release();
        if (trayManager != null) {
            trayManager.setBusyState(false);
        }
    }

    public int getActiveConnectionCount() {
        return connectionIds.size();
    }

    public boolean isHardwareOperationInProgress() {
        return hardwareOperationLock.availablePermits() == 0;
    }

    public boolean awaitStart(long timeout, TimeUnit unit) throws InterruptedException {
        return startedLatch.await(timeout, unit);
    }

    public void shutdownCleanly(int timeoutMs) {
        this.cardReaderManager.removeListener(this);
        this.cardWaitProvider.abortActiveWait(CardWaitProvider.WaitOutcome.CLIENT_DISCONNECTED);
        this.pinPromptProvider.abortActivePromptForCardRemoval();
        this.cryptoWorkerExecutor.shutdownNow();
        try {
            stop(timeoutMs);
        } catch (Exception e) {
            logger.debug("Notice stopping WebSocket server: {}", e.getMessage());
        }
    }

    private void sendJson(WebSocket conn, Object payload) {
        if (conn == null || !conn.isOpen()) {
            return;
        }
        try {
            String json = objectMapper.writeValueAsString(payload);
            conn.send(json);
        } catch (Exception e) {
            logger.error("Failed to serialize or send WebSocket payload: {}", e.getMessage());
        }
    }

    private void broadcastJson(Object payload) {
        try {
            String json = objectMapper.writeValueAsString(payload);
            broadcast(json);
        } catch (Exception e) {
            logger.error("Failed to broadcast hardware notification: {}", e.getMessage());
        }
    }

    private void notifyTrayConnectionCountChanged() {
        if (trayManager != null) {
            trayManager.updateStatusDisplay();
        }
    }

    private static String truncateHash(String hash) {
        if (hash == null || hash.length() <= 20) return hash;
        return hash.substring(0, 10) + "..." + hash.substring(hash.length() - 10);
    }

    private static String sanitizePlainTitle(String rawTitle, String defaultTitle) {
        if (rawTitle == null || rawTitle.isBlank()) {
            return defaultTitle;
        }
        String cleaned = rawTitle.replaceAll("[\\r\\n\\t\\p{Cntrl}]+", " ").trim();
        if (cleaned.isEmpty()) {
            return defaultTitle;
        }
        return cleaned.length() > 120 ? cleaned.substring(0, 120) : cleaned;
    }

    static String escapeHtml(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder(input.length() + 16);
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&#39;");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    @Override
    public void onError(WebSocket conn, Exception ex) {
        logger.error("WebSocket server error: {}", ex.getMessage(), ex);
    }

    @Override
    public void onStart() {
        startedLatch.countDown();
        String scheme = config.secureWss() ? "wss" : "ws";
        logger.info("KILLAgent Loopback Server listening strictly on {}://{}:{}",
                scheme, getAddress().getHostString(), getPort());
    }

    // --- HardwareListener Real-Time Push Notifications ---

    @Override
    public void onCardInserted(String readerName, CardType cardType) {
        logger.info("Broadcasting unsolicited CARD_INSERTED event (reader={}).", readerName);
        broadcastJson(new CardInsertedNotification(readerName));
    }

    @Override
    public void onCardRemoved(String readerName) {
        logger.info("Broadcasting unsolicited CARD_REMOVED (Kill-Switch) event to all active clients.");
        pinPromptProvider.abortActivePromptForCardRemoval();
        broadcastJson(new CardRemovedNotification());
    }

    @Override
    public void onReaderStatusChanged(boolean readerPresent, String readerName) {
        if (!readerPresent) {
            logger.info("Smart card reader unplugged; ensuring active PIN prompts are aborted.");
            pinPromptProvider.abortActivePromptForCardRemoval();
        }
        logger.info("Broadcasting unsolicited READER_STATUS_CHANGED event (readerPresent={}, reader={}).",
                readerPresent, readerName);
        broadcastJson(new ReaderStatusNotification(readerPresent, readerName));
    }
}
