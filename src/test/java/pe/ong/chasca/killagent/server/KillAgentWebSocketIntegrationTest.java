package pe.ong.chasca.killagent.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pe.ong.chasca.killagent.config.AgentConfig;
import pe.ong.chasca.killagent.crypto.CryptoService;
import pe.ong.chasca.killagent.hardware.CardReaderManager;
import pe.ong.chasca.killagent.security.SigningIntentPayload;
import pe.ong.chasca.killagent.security.SigningIntentVerifier;
import pe.ong.chasca.killagent.server.dto.SignedIntentEnvelope;
import pe.ong.chasca.killagent.testsupport.MutableTestHardwareProbe;
import pe.ong.chasca.killagent.testsupport.TestSoftTokenPkcs11Bridge;
import pe.ong.chasca.killagent.ui.CardWaitProvider;
import pe.ong.chasca.killagent.ui.PinPromptProvider;

import java.net.ServerSocket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class KillAgentWebSocketIntegrationTest {

    private static final String ALLOWED_ORIGIN = "http://localhost:5173";

    private final ObjectMapper mapper = new ObjectMapper();
    private int testPort;
    private MutableTestHardwareProbe hardwareProbe;
    private CardReaderManager readerManager;
    private KillAgentWebSocketServer server;
    private AtomicReference<PinPromptProvider.PinPromptResult> scriptedPinResponse;
    private AtomicInteger lastRequestedTimeoutSeconds;
    private AtomicReference<String> lastRequestedTitle;
    private AtomicReference<String> lastRequestedDetails;
    private AtomicReference<CompletableFuture<PinPromptProvider.PinPromptResult>> pendingBlockingPrompt;
    private AtomicReference<CountDownLatch> promptEnteredLatch;
    private AtomicReference<CountDownLatch> promptAbortedLatch;
    private AtomicReference<PinPromptProvider.AbortReason> lastAbortReason;
    private AtomicInteger pinPromptInvocationCount;

    private AtomicReference<CardWaitProvider.WaitOutcome> scriptedWaitOutcome;
    private AtomicInteger cardWaitInvocationCount;
    private AtomicInteger lastWaitTimeoutSeconds;
    private AtomicReference<String> lastWaitTitle;
    private AtomicReference<String> lastWaitDetails;
    private AtomicReference<CompletableFuture<CardWaitProvider.WaitOutcome>> pendingBlockingWait;
    private AtomicReference<CountDownLatch> waitEnteredLatch;
    private AtomicReference<CountDownLatch> waitAbortedLatch;
    private AtomicReference<CardWaitProvider.WaitOutcome> lastWaitAbortReason;
    private volatile boolean simulateCardInsertOnWaitReady;

    @BeforeEach
    void setUp() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            testPort = socket.getLocalPort();
        }

        AgentConfig config = new AgentConfig(
                "development",
                testPort,
                "127.0.0.1",
                false,
                "./keystore/loopback.p12",
                "changeit",
                Set.of(ALLOWED_ORIGIN, "https://chaska.ong.pe"),
                "bit4ipki.dll",
                "idplug-pkcs11.dll",
                "auto",
                false
        );

        hardwareProbe = new MutableTestHardwareProbe(true);
        readerManager = new CardReaderManager(config, hardwareProbe);
        readerManager.probeOnce(false);
        TestSoftTokenPkcs11Bridge pkcs11Bridge = new TestSoftTokenPkcs11Bridge(config, "71234567", "JUAN PEREZ GARCIA");
        CryptoService cryptoService = new CryptoService(config, readerManager, pkcs11Bridge);

        scriptedPinResponse = new AtomicReference<>(
                new PinPromptProvider.PinPromptResult(new char[]{'1', '2', '3', '4', '5', '6'}, PinPromptProvider.AbortReason.NONE)
        );
        lastRequestedTimeoutSeconds = new AtomicInteger(0);
        lastRequestedTitle = new AtomicReference<>();
        lastRequestedDetails = new AtomicReference<>();
        pendingBlockingPrompt = new AtomicReference<>();
        promptEnteredLatch = new AtomicReference<>();
        promptAbortedLatch = new AtomicReference<>();
        lastAbortReason = new AtomicReference<>();
        pinPromptInvocationCount = new AtomicInteger(0);

        scriptedWaitOutcome = new AtomicReference<>(CardWaitProvider.WaitOutcome.CARD_READY);
        cardWaitInvocationCount = new AtomicInteger(0);
        lastWaitTimeoutSeconds = new AtomicInteger(0);
        lastWaitTitle = new AtomicReference<>();
        lastWaitDetails = new AtomicReference<>();
        pendingBlockingWait = new AtomicReference<>();
        waitEnteredLatch = new AtomicReference<>();
        waitAbortedLatch = new AtomicReference<>();
        lastWaitAbortReason = new AtomicReference<>();
        simulateCardInsertOnWaitReady = true;

        PinPromptProvider programmaticPinProvider = new PinPromptProvider() {
            @Override
            public PinPromptResult requestPin(String title, String operationHtmlDetails) {
                pinPromptInvocationCount.incrementAndGet();
                lastRequestedTitle.set(title);
                lastRequestedDetails.set(operationHtmlDetails);
                PinPromptResult template = scriptedPinResponse.get();
                char[] copy = template.pin() != null ? template.pin().clone() : null;
                return new PinPromptResult(copy, template.abortReason());
            }

            @Override
            public PinPromptResult requestPin(String title, String operationHtmlDetails, int timeoutSeconds) {
                lastRequestedTimeoutSeconds.set(timeoutSeconds);
                lastRequestedTitle.set(title);
                lastRequestedDetails.set(operationHtmlDetails);
                CompletableFuture<PinPromptResult> pending = pendingBlockingPrompt.get();
                if (pending != null) {
                    pinPromptInvocationCount.incrementAndGet();
                    CountDownLatch entered = promptEnteredLatch.get();
                    if (entered != null) {
                        entered.countDown();
                    }
                    try {
                        return pending.get(5, TimeUnit.SECONDS);
                    } catch (Exception e) {
                        return new PinPromptResult(null, AbortReason.USER_CANCELLED);
                    }
                }
                return requestPin(title, operationHtmlDetails);
            }

            @Override
            public void abortActivePromptForCardRemoval() {
                abortActivePrompt(AbortReason.CARD_REMOVED);
            }

            @Override
            public void abortActivePrompt(AbortReason reason) {
                lastAbortReason.set(reason);
                CompletableFuture<PinPromptResult> pending = pendingBlockingPrompt.getAndSet(null);
                if (pending != null) {
                    pending.complete(new PinPromptResult(null, reason));
                }
                CountDownLatch aborted = promptAbortedLatch.get();
                if (aborted != null) {
                    aborted.countDown();
                }
            }
        };

        CardWaitProvider programmaticCardWaitProvider = new CardWaitProvider() {
            @Override
            public WaitOutcome waitForCard(
                    CardReaderManager rm,
                    String title,
                    String operationHtmlDetails,
                    int timeoutSeconds
            ) {
                cardWaitInvocationCount.incrementAndGet();
                lastWaitTimeoutSeconds.set(timeoutSeconds);
                lastWaitTitle.set(title);
                lastWaitDetails.set(operationHtmlDetails);
                CompletableFuture<WaitOutcome> pending = pendingBlockingWait.get();
                if (pending != null) {
                    CountDownLatch entered = waitEnteredLatch.get();
                    if (entered != null) {
                        entered.countDown();
                    }
                    try {
                        WaitOutcome outcome = pending.get(5, TimeUnit.SECONDS);
                        if (outcome == WaitOutcome.CARD_READY && simulateCardInsertOnWaitReady) {
                            hardwareProbe.insertCard();
                            rm.probeOnce(true);
                        }
                        return outcome;
                    } catch (Exception e) {
                        return WaitOutcome.USER_CANCELLED;
                    }
                }
                WaitOutcome outcome = scriptedWaitOutcome.get();
                if (outcome == WaitOutcome.CARD_READY && simulateCardInsertOnWaitReady) {
                    hardwareProbe.insertCard();
                    rm.probeOnce(true);
                }
                return outcome;
            }

            @Override
            public void abortActiveWait(WaitOutcome reason) {
                lastWaitAbortReason.set(reason);
                CompletableFuture<WaitOutcome> pending = pendingBlockingWait.getAndSet(null);
                if (pending != null) {
                    pending.complete(reason);
                }
                CountDownLatch aborted = waitAbortedLatch.get();
                if (aborted != null) {
                    aborted.countDown();
                }
            }
        };

        server = new KillAgentWebSocketServer(
                config,
                readerManager,
                cryptoService,
                null,
                programmaticPinProvider,
                programmaticCardWaitProvider
        );
        server.start();
        assertTrue(server.awaitStart(5, TimeUnit.SECONDS), "WebSocket server must start within 5s");
    }

    @AfterEach
    void tearDown() {
        if (pendingBlockingWait != null) {
            CompletableFuture<CardWaitProvider.WaitOutcome> pendingWait = pendingBlockingWait.getAndSet(null);
            if (pendingWait != null) {
                pendingWait.complete(CardWaitProvider.WaitOutcome.USER_CANCELLED);
            }
        }
        if (pendingBlockingPrompt != null) {
            CompletableFuture<PinPromptProvider.PinPromptResult> pending = pendingBlockingPrompt.getAndSet(null);
            if (pending != null) {
                pending.complete(new PinPromptProvider.PinPromptResult(null, PinPromptProvider.AbortReason.USER_CANCELLED));
            }
        }
        if (server != null) {
            server.shutdownCleanly(1000);
        }
        if (readerManager != null) {
            readerManager.stop();
        }
    }

    @Test
    void testUnauthorizedOriginIsRejectedAtHandshake() throws Exception {
        CountDownLatch closedLatch = new CountDownLatch(1);
        BlockingQueue<String> messages = new LinkedBlockingQueue<>();

        WebSocketClient attackerClient = createTestClient(
                "https://chaska.ong.pe.attacker.com",
                messages,
                closedLatch
        );

        attackerClient.connectBlocking(3, TimeUnit.SECONDS);
        assertTrue(closedLatch.await(3, TimeUnit.SECONDS), "Unauthorized connection must be closed immediately");
        assertTrue(messages.isEmpty(), "Attacker must never receive CONNECTION_ESTABLISHED");
    }

    @Test
    void testFullLifecycleHandshakeAuthSignDocumentSignAndKillSwitch() throws Exception {
        CountDownLatch closedLatch = new CountDownLatch(1);
        BlockingQueue<String> inbox = new LinkedBlockingQueue<>();

        WebSocketClient client = createTestClient(ALLOWED_ORIGIN, inbox, closedLatch);
        assertTrue(client.connectBlocking(3, TimeUnit.SECONDS));

        try {
            // 1. Verify unsolicited CONNECTION_ESTABLISHED handshake
            String welcomeRaw = inbox.poll(3, TimeUnit.SECONDS);
            assertNotNull(welcomeRaw);
            JsonNode welcome = mapper.readTree(welcomeRaw);
            assertEquals("CONNECTION_ESTABLISHED", welcome.get("type").asText());
            assertTrue(welcome.get("wsConnectionId").asText().startsWith("ws-killagent-"));
            assertTrue(welcome.get("hardwareStatus").get("cardPresent").asBoolean());

            // 2. Test SIGN_AUTH_CHALLENGE
            client.send("""
                    {
                      "type": "SIGN_AUTH_CHALLENGE",
                      "requestId": "req-auth-1002",
                      "nonce": "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01"
                    }
                    """);

            String authResRaw = inbox.poll(5, TimeUnit.SECONDS);
            assertNotNull(authResRaw);
            JsonNode authRes = mapper.readTree(authResRaw);
            assertEquals("SIGN_AUTH_CHALLENGE_RESPONSE", authRes.get("type").asText());
            assertEquals("req-auth-1002", authRes.get("requestId").asText());
            assertEquals("SUCCESS", authRes.get("status").asText());
            assertEquals("71234567", authRes.get("payload").get("metadata").get("dni").asText());
            assertEquals("Verificación de Seguridad DNIe", lastRequestedTitle.get());
            assertEquals("Autenticación Institucional Ch'aska (Verificación DNIe)", lastRequestedDetails.get());

            // 2b. Test SIGN_AUTH_CHALLENGE with custom operationTitle & HTML-sanitized operationDescription
            client.send("""
                    {
                      "type": "SIGN_AUTH_CHALLENGE",
                      "requestId": "req-auth-custom-1003",
                      "nonce": "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01",
                      "operationTitle": "Desbloqueo de Sesión",
                      "operationDescription": "Verificación <b>Step-Up</b> & <script>alert(1)</script>"
                    }
                    """);

            String customAuthResRaw = inbox.poll(5, TimeUnit.SECONDS);
            assertNotNull(customAuthResRaw);
            JsonNode customAuthRes = mapper.readTree(customAuthResRaw);
            assertEquals("SIGN_AUTH_CHALLENGE_RESPONSE", customAuthRes.get("type").asText());
            assertEquals("SUCCESS", customAuthRes.get("status").asText());
            assertEquals("Desbloqueo de Sesión", lastRequestedTitle.get());
            assertEquals(
                    "Verificación &lt;b&gt;Step-Up&lt;/b&gt; &amp; &lt;script&gt;alert(1)&lt;/script&gt;",
                    lastRequestedDetails.get()
            );

            // 3. Test SIGN_DOCUMENT_DIGEST
            client.send("""
                    {
                      "type": "SIGN_DOCUMENT_DIGEST",
                      "requestId": "req-doc-5501",
                      "slotId": "b18f8101-5e92-4293-8b7c-7a54911f32a0",
                      "documentHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                      "documentTitle": "Convenio de Cooperación Técnica 2026.pdf",
                      "signerRole": "SIGNER"
                    }
                    """);

            String docResRaw = inbox.poll(5, TimeUnit.SECONDS);
            assertNotNull(docResRaw);
            JsonNode docRes = mapper.readTree(docResRaw);
            assertEquals("SIGN_DOCUMENT_DIGEST_RESPONSE", docRes.get("type").asText());
            assertEquals("req-doc-5501", docRes.get("requestId").asText());
            assertEquals("SUCCESS", docRes.get("status").asText());
            assertEquals(
                    "CN=JUAN PEREZ GARCIA, SERIALNUMBER=DNI71234567, O=RENIEC, C=PE",
                    docRes.get("payload").get("signerSubjectDn").asText()
            );

            // 4. Test USER_CANCELLED error handling
            scriptedPinResponse.set(new PinPromptProvider.PinPromptResult(null, PinPromptProvider.AbortReason.USER_CANCELLED));
            client.send("""
                    {
                      "type": "SIGN_AUTH_CHALLENGE",
                      "requestId": "req-auth-cancel",
                      "nonce": "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01"
                    }
                    """);

            String cancelRaw = inbox.poll(3, TimeUnit.SECONDS);
            assertNotNull(cancelRaw);
            JsonNode cancelNode = mapper.readTree(cancelRaw);
            assertEquals("ERROR", cancelNode.get("type").asText());
            assertEquals("USER_CANCELLED", cancelNode.get("errorCode").asText());

            // 5. Test Real-Time Hardware Kill-Switch Push Notification (CARD_REMOVED & CARD_INSERTED)
            hardwareProbe.removeCard();
            readerManager.probeOnce(true);
            String removedRaw = inbox.poll(3, TimeUnit.SECONDS);
            assertNotNull(removedRaw);
            JsonNode removedNode = mapper.readTree(removedRaw);
            assertEquals("CARD_REMOVED", removedNode.get("type").asText());
            assertNotNull(removedNode.get("timestamp").asText());

            hardwareProbe.insertCard();
            readerManager.probeOnce(true);
            String insertedRaw = inbox.poll(3, TimeUnit.SECONDS);
            assertNotNull(insertedRaw);
            JsonNode insertedNode = mapper.readTree(insertedRaw);
            assertEquals("CARD_INSERTED", insertedNode.get("type").asText());
            assertTrue(insertedNode.get("readerName").asText().contains("Identiv"));
        } finally {
            client.closeBlocking();
        }
    }

    @Test
    void testPinTimeoutProducesPinTimeoutError() throws Exception {
        CountDownLatch closedLatch = new CountDownLatch(1);
        BlockingQueue<String> inbox = new LinkedBlockingQueue<>();

        WebSocketClient client = createTestClient(ALLOWED_ORIGIN, inbox, closedLatch);
        assertTrue(client.connectBlocking(3, TimeUnit.SECONDS));

        try {
            String welcomeRaw = inbox.poll(3, TimeUnit.SECONDS);
            assertNotNull(welcomeRaw);

            scriptedPinResponse.set(new PinPromptProvider.PinPromptResult(null, PinPromptProvider.AbortReason.TIMEOUT));

            client.send("""
                    {
                      "type": "SIGN_AUTH_CHALLENGE",
                      "requestId": "req-auth-timeout",
                      "nonce": "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01"
                    }
                    """);

            String authTimeoutRaw = inbox.poll(3, TimeUnit.SECONDS);
            assertNotNull(authTimeoutRaw);
            JsonNode authTimeoutNode = mapper.readTree(authTimeoutRaw);
            assertEquals("ERROR", authTimeoutNode.get("type").asText());
            assertEquals("req-auth-timeout", authTimeoutNode.get("requestId").asText());
            assertEquals("PIN_TIMEOUT", authTimeoutNode.get("errorCode").asText());
            assertEquals(30, lastRequestedTimeoutSeconds.get());

            client.send("""
                    {
                      "type": "SIGN_DOCUMENT_DIGEST",
                      "requestId": "req-doc-timeout",
                      "slotId": "b18f8101-5e92-4293-8b7c-7a54911f32a0",
                      "documentHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                      "documentTitle": "Acta de Directorio.pdf",
                      "signerRole": "SIGNER"
                    }
                    """);

            String docTimeoutRaw = inbox.poll(3, TimeUnit.SECONDS);
            assertNotNull(docTimeoutRaw);
            JsonNode docTimeoutNode = mapper.readTree(docTimeoutRaw);
            assertEquals("ERROR", docTimeoutNode.get("type").asText());
            assertEquals("req-doc-timeout", docTimeoutNode.get("requestId").asText());
            assertEquals("PIN_TIMEOUT", docTimeoutNode.get("errorCode").asText());
            assertEquals(30, lastRequestedTimeoutSeconds.get());
        } finally {
            client.closeBlocking();
        }
    }

    @Test
    void testClientDisconnectDuringBlockingPinPromptAbortsAndReleasesLock() throws Exception {
        CountDownLatch closedLatch1 = new CountDownLatch(1);
        BlockingQueue<String> inbox1 = new LinkedBlockingQueue<>();
        CountDownLatch closedLatch2 = new CountDownLatch(1);
        BlockingQueue<String> inbox2 = new LinkedBlockingQueue<>();

        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch aborted = new CountDownLatch(1);
        pendingBlockingPrompt.set(new CompletableFuture<>());
        promptEnteredLatch.set(entered);
        promptAbortedLatch.set(aborted);

        WebSocketClient client1 = createTestClient(ALLOWED_ORIGIN, inbox1, closedLatch1);
        WebSocketClient client2 = createTestClient(ALLOWED_ORIGIN, inbox2, closedLatch2);
        assertTrue(client1.connectBlocking(3, TimeUnit.SECONDS));
        assertTrue(client2.connectBlocking(3, TimeUnit.SECONDS));

        try {
            assertNotNull(inbox1.poll(3, TimeUnit.SECONDS));
            assertNotNull(inbox2.poll(3, TimeUnit.SECONDS));

            client1.send("""
                    {
                      "type": "SIGN_AUTH_CHALLENGE",
                      "requestId": "req-auth-disconnect",
                      "nonce": "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01"
                    }
                    """);

            assertTrue(entered.await(3, TimeUnit.SECONDS), "requestPin must enter blocking state");
            assertTrue(server.isHardwareOperationInProgress(), "hardwareOperationLock must be held while prompt blocks");

            // Confirm another client receives OPERATION_IN_PROGRESS while client1 holds the lock
            client2.send("""
                    {
                      "type": "SIGN_AUTH_CHALLENGE",
                      "requestId": "req-while-locked",
                      "nonce": "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01"
                    }
                    """);
            String lockedRaw = inbox2.poll(3, TimeUnit.SECONDS);
            assertNotNull(lockedRaw);
            JsonNode lockedNode = mapper.readTree(lockedRaw);
            assertEquals("ERROR", lockedNode.get("type").asText());
            assertEquals("OPERATION_IN_PROGRESS", lockedNode.get("errorCode").asText());
            assertEquals(
                    "Ya existe una solicitud de verificación con PIN activa en esta estación.",
                    lockedNode.get("message").asText()
            );

            // Simulate browser tab reload / close on client1 while PIN modal is open
            client1.closeBlocking();

            assertTrue(aborted.await(3, TimeUnit.SECONDS), "Closing client1 must invoke abortActivePrompt");
            assertEquals(PinPromptProvider.AbortReason.CLIENT_DISCONNECTED, lastAbortReason.get());

            long deadline = System.currentTimeMillis() + 2000;
            while (server.isHardwareOperationInProgress() && System.currentTimeMillis() < deadline) {
                Thread.sleep(5);
            }
            assertFalse(server.isHardwareOperationInProgress(), "hardwareOperationLock must be released after disconnect");

            // Subsequent WebSocket client can immediately run SIGN_AUTH_CHALLENGE without OPERATION_IN_PROGRESS
            client2.send("""
                    {
                      "type": "SIGN_AUTH_CHALLENGE",
                      "requestId": "req-after-disconnect",
                      "nonce": "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01"
                    }
                    """);
            String successRaw = inbox2.poll(5, TimeUnit.SECONDS);
            assertNotNull(successRaw);
            JsonNode successNode = mapper.readTree(successRaw);
            assertEquals("SIGN_AUTH_CHALLENGE_RESPONSE", successNode.get("type").asText());
            assertEquals("req-after-disconnect", successNode.get("requestId").asText());
            assertEquals("SUCCESS", successNode.get("status").asText());
        } finally {
            client1.closeBlocking();
            client2.closeBlocking();
        }
    }

    @Test
    void testCancelActiveOperationMessageAbortsBlockingPinPrompt() throws Exception {
        CountDownLatch closedLatch = new CountDownLatch(1);
        BlockingQueue<String> inbox = new LinkedBlockingQueue<>();

        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch aborted = new CountDownLatch(1);
        pendingBlockingPrompt.set(new CompletableFuture<>());
        promptEnteredLatch.set(entered);
        promptAbortedLatch.set(aborted);

        WebSocketClient client = createTestClient(ALLOWED_ORIGIN, inbox, closedLatch);
        assertTrue(client.connectBlocking(3, TimeUnit.SECONDS));

        try {
            assertNotNull(inbox.poll(3, TimeUnit.SECONDS));

            client.send("""
                    {
                      "type": "SIGN_AUTH_CHALLENGE",
                      "requestId": "req-to-cancel",
                      "nonce": "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01"
                    }
                    """);

            assertTrue(entered.await(3, TimeUnit.SECONDS), "requestPin must enter blocking state");

            client.send("""
                    {
                      "type": "CANCEL_ACTIVE_OPERATION",
                      "requestId": "req-cancel-cmd"
                    }
                    """);

            assertTrue(aborted.await(3, TimeUnit.SECONDS), "CANCEL_ACTIVE_OPERATION must invoke abortActivePrompt");
            assertEquals(PinPromptProvider.AbortReason.USER_CANCELLED, lastAbortReason.get());

            String cancelRaw = inbox.poll(3, TimeUnit.SECONDS);
            assertNotNull(cancelRaw);
            JsonNode cancelNode = mapper.readTree(cancelRaw);
            assertEquals("ERROR", cancelNode.get("type").asText());
            assertEquals("req-to-cancel", cancelNode.get("requestId").asText());
            assertEquals("USER_CANCELLED", cancelNode.get("errorCode").asText());
        } finally {
            client.closeBlocking();
        }
    }

    @Test
    void testReaderStatusChangedBroadcastAndPhysicalDisconnectNotification() throws Exception {
        CountDownLatch closedLatch = new CountDownLatch(1);
        BlockingQueue<String> inbox = new LinkedBlockingQueue<>();

        WebSocketClient client = createTestClient(ALLOWED_ORIGIN, inbox, closedLatch);
        assertTrue(client.connectBlocking(3, TimeUnit.SECONDS));

        try {
            assertNotNull(inbox.poll(3, TimeUnit.SECONDS)); // CONNECTION_ESTABLISHED

            // 1. Direct onReaderStatusChanged broadcast (connected + disconnected)
            server.onReaderStatusChanged(true, "Identiv uTrust 2700 R");
            String connectedRaw = inbox.poll(3, TimeUnit.SECONDS);
            assertNotNull(connectedRaw);
            JsonNode connectedNode = mapper.readTree(connectedRaw);
            assertEquals("READER_STATUS_CHANGED", connectedNode.get("type").asText());
            assertTrue(connectedNode.get("readerPresent").asBoolean());
            assertEquals("Identiv uTrust 2700 R", connectedNode.get("readerName").asText());
            assertNotNull(connectedNode.get("timestamp").asText());

            server.onReaderStatusChanged(false, null);
            String disconnectedRaw = inbox.poll(3, TimeUnit.SECONDS);
            assertNotNull(disconnectedRaw);
            JsonNode disconnectedNode = mapper.readTree(disconnectedRaw);
            assertEquals("READER_STATUS_CHANGED", disconnectedNode.get("type").asText());
            assertFalse(disconnectedNode.get("readerPresent").asBoolean());
            assertTrue(disconnectedNode.get("readerName").isNull());

            // 2. Disconnecting physical reader with card immediately emits CARD_REMOVED + READER_STATUS_CHANGED(false, null)
            hardwareProbe.disconnectReader();
            readerManager.probeOnce(true);
            String cardRemovedRaw = inbox.poll(3, TimeUnit.SECONDS);
            String readerOffRaw = inbox.poll(3, TimeUnit.SECONDS);
            assertNotNull(cardRemovedRaw);
            assertNotNull(readerOffRaw);
            assertEquals("CARD_REMOVED", mapper.readTree(cardRemovedRaw).get("type").asText());
            JsonNode readerOffNode = mapper.readTree(readerOffRaw);
            assertEquals("READER_STATUS_CHANGED", readerOffNode.get("type").asText());
            assertFalse(readerOffNode.get("readerPresent").asBoolean());
            assertTrue(readerOffNode.get("readerName").isNull());
        } finally {
            client.closeBlocking();
        }
    }

    @Test
    void testWaitForCardTransitionsToPinPromptWhenCardInserted() throws Exception {
        CountDownLatch closedLatch = new CountDownLatch(1);
        BlockingQueue<String> inbox = new LinkedBlockingQueue<>();

        WebSocketClient client = createTestClient(ALLOWED_ORIGIN, inbox, closedLatch);
        assertTrue(client.connectBlocking(3, TimeUnit.SECONDS));

        try {
            assertNotNull(inbox.poll(3, TimeUnit.SECONDS)); // CONNECTION_ESTABLISHED

            // Ensure cardPresent == false before sending SIGN_AUTH_CHALLENGE with waitForCard: true
            hardwareProbe.removeCard();
            readerManager.probeOnce(true);
            String removedRaw = inbox.poll(3, TimeUnit.SECONDS);
            assertNotNull(removedRaw);
            assertEquals("CARD_REMOVED", mapper.readTree(removedRaw).get("type").asText());

            scriptedWaitOutcome.set(CardWaitProvider.WaitOutcome.CARD_READY);
            simulateCardInsertOnWaitReady = true;

            client.send("""
                    {
                      "type": "SIGN_AUTH_CHALLENGE",
                      "requestId": "req-wait-success",
                      "nonce": "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01",
                      "operationTitle": "Inicio de Sesión",
                      "operationDescription": "Autenticación de usuario",
                      "waitForCard": true
                    }
                    """);

            // Consume CARD_INSERTED broadcast emitted when simulated card insertion completes wait
            String msg1 = inbox.poll(5, TimeUnit.SECONDS);
            String msg2 = inbox.poll(5, TimeUnit.SECONDS);
            assertNotNull(msg1);
            assertNotNull(msg2);
            JsonNode n1 = mapper.readTree(msg1);
            JsonNode n2 = mapper.readTree(msg2);
            JsonNode authRes = "SIGN_AUTH_CHALLENGE_RESPONSE".equals(n1.get("type").asText()) ? n1 : n2;

            assertEquals("SIGN_AUTH_CHALLENGE_RESPONSE", authRes.get("type").asText());
            assertEquals("req-wait-success", authRes.get("requestId").asText());
            assertEquals("SUCCESS", authRes.get("status").asText());
            assertEquals(1, cardWaitInvocationCount.get());
            assertEquals(30, lastWaitTimeoutSeconds.get());
            assertEquals("Inicio de Sesión", lastWaitTitle.get());
            assertEquals("Autenticación de usuario", lastWaitDetails.get());
            assertEquals(1, pinPromptInvocationCount.get());
        } finally {
            client.closeBlocking();
        }
    }

    @Test
    void testWaitForCardTimeoutReturnsCardNotPresentWithoutInvokingPinPrompt() throws Exception {
        CountDownLatch closedLatch = new CountDownLatch(1);
        BlockingQueue<String> inbox = new LinkedBlockingQueue<>();

        WebSocketClient client = createTestClient(ALLOWED_ORIGIN, inbox, closedLatch);
        assertTrue(client.connectBlocking(3, TimeUnit.SECONDS));

        try {
            assertNotNull(inbox.poll(3, TimeUnit.SECONDS)); // CONNECTION_ESTABLISHED

            hardwareProbe.removeCard();
            readerManager.probeOnce(true);
            assertNotNull(inbox.poll(3, TimeUnit.SECONDS)); // CARD_REMOVED

            scriptedWaitOutcome.set(CardWaitProvider.WaitOutcome.TIMEOUT);
            simulateCardInsertOnWaitReady = false;

            client.send("""
                    {
                      "type": "SIGN_AUTH_CHALLENGE",
                      "requestId": "req-wait-timeout",
                      "nonce": "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01",
                      "waitForCard": true
                    }
                    """);

            String errRaw = inbox.poll(5, TimeUnit.SECONDS);
            assertNotNull(errRaw);
            JsonNode errNode = mapper.readTree(errRaw);
            assertEquals("ERROR", errNode.get("type").asText());
            assertEquals("req-wait-timeout", errNode.get("requestId").asText());
            assertEquals("CARD_NOT_PRESENT", errNode.get("errorCode").asText());
            assertEquals(1, cardWaitInvocationCount.get());
            assertEquals(0, pinPromptInvocationCount.get());
        } finally {
            client.closeBlocking();
        }
    }

    @Test
    void testWaitForCardFalseOrOmittedFailsImmediatelyWithoutInvokingCardWaitProvider() throws Exception {
        CountDownLatch closedLatch = new CountDownLatch(1);
        BlockingQueue<String> inbox = new LinkedBlockingQueue<>();

        WebSocketClient client = createTestClient(ALLOWED_ORIGIN, inbox, closedLatch);
        assertTrue(client.connectBlocking(3, TimeUnit.SECONDS));

        try {
            assertNotNull(inbox.poll(3, TimeUnit.SECONDS)); // CONNECTION_ESTABLISHED

            hardwareProbe.removeCard();
            readerManager.probeOnce(true);
            assertNotNull(inbox.poll(3, TimeUnit.SECONDS)); // CARD_REMOVED

            // 1. Explicit waitForCard: false
            client.send("""
                    {
                      "type": "SIGN_AUTH_CHALLENGE",
                      "requestId": "req-no-wait-false",
                      "nonce": "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01",
                      "waitForCard": false
                    }
                    """);

            String errFalseRaw = inbox.poll(3, TimeUnit.SECONDS);
            assertNotNull(errFalseRaw);
            JsonNode errFalseNode = mapper.readTree(errFalseRaw);
            assertEquals("ERROR", errFalseNode.get("type").asText());
            assertEquals("req-no-wait-false", errFalseNode.get("requestId").asText());
            assertEquals("CARD_NOT_PRESENT", errFalseNode.get("errorCode").asText());

            // 2. Omitted waitForCard (defaults to false)
            client.send("""
                    {
                      "type": "SIGN_AUTH_CHALLENGE",
                      "requestId": "req-no-wait-omitted",
                      "nonce": "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01"
                    }
                    """);

            String errOmittedRaw = inbox.poll(3, TimeUnit.SECONDS);
            assertNotNull(errOmittedRaw);
            JsonNode errOmittedNode = mapper.readTree(errOmittedRaw);
            assertEquals("ERROR", errOmittedNode.get("type").asText());
            assertEquals("req-no-wait-omitted", errOmittedNode.get("requestId").asText());
            assertEquals("CARD_NOT_PRESENT", errOmittedNode.get("errorCode").asText());

            assertEquals(0, cardWaitInvocationCount.get());
            assertEquals(0, pinPromptInvocationCount.get());
        } finally {
            client.closeBlocking();
        }
    }

    @Test
    void testCancelAndDisconnectDuringBlockingCardWaitAbortAndReleaseLock() throws Exception {
        CountDownLatch closedLatch1 = new CountDownLatch(1);
        BlockingQueue<String> inbox1 = new LinkedBlockingQueue<>();
        CountDownLatch closedLatch2 = new CountDownLatch(1);
        BlockingQueue<String> inbox2 = new LinkedBlockingQueue<>();

        WebSocketClient client1 = createTestClient(ALLOWED_ORIGIN, inbox1, closedLatch1);
        WebSocketClient client2 = createTestClient(ALLOWED_ORIGIN, inbox2, closedLatch2);
        assertTrue(client1.connectBlocking(3, TimeUnit.SECONDS));
        assertTrue(client2.connectBlocking(3, TimeUnit.SECONDS));

        try {
            assertNotNull(inbox1.poll(3, TimeUnit.SECONDS));
            assertNotNull(inbox2.poll(3, TimeUnit.SECONDS));

            hardwareProbe.removeCard();
            readerManager.probeOnce(true);
            assertNotNull(inbox1.poll(3, TimeUnit.SECONDS));
            assertNotNull(inbox2.poll(3, TimeUnit.SECONDS));

            // 1. CANCEL_ACTIVE_OPERATION while WaitForCard is blocking
            CountDownLatch enteredCancel = new CountDownLatch(1);
            CountDownLatch abortedCancel = new CountDownLatch(1);
            pendingBlockingWait.set(new CompletableFuture<>());
            waitEnteredLatch.set(enteredCancel);
            waitAbortedLatch.set(abortedCancel);

            client1.send("""
                    {
                      "type": "SIGN_AUTH_CHALLENGE",
                      "requestId": "req-wait-cancel",
                      "nonce": "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01",
                      "waitForCard": true
                    }
                    """);
            assertTrue(enteredCancel.await(3, TimeUnit.SECONDS));
            client1.send("""
                    {
                      "type": "CANCEL_ACTIVE_OPERATION",
                      "requestId": "req-wait-cancel-cmd"
                    }
                    """);
            assertTrue(abortedCancel.await(3, TimeUnit.SECONDS));
            assertEquals(CardWaitProvider.WaitOutcome.USER_CANCELLED, lastWaitAbortReason.get());

            String cancelRaw = inbox1.poll(3, TimeUnit.SECONDS);
            assertNotNull(cancelRaw);
            JsonNode cancelNode = mapper.readTree(cancelRaw);
            assertEquals("USER_CANCELLED", cancelNode.get("errorCode").asText());

            // 2. Client WebSocket disconnect while WaitForCard is blocking releases lock
            long deadline = System.currentTimeMillis() + 2000;
            while (server.isHardwareOperationInProgress() && System.currentTimeMillis() < deadline) {
                Thread.sleep(5);
            }
            assertFalse(server.isHardwareOperationInProgress());

            CountDownLatch enteredDisconnect = new CountDownLatch(1);
            CountDownLatch abortedDisconnect = new CountDownLatch(1);
            pendingBlockingWait.set(new CompletableFuture<>());
            waitEnteredLatch.set(enteredDisconnect);
            waitAbortedLatch.set(abortedDisconnect);

            client1.send("""
                    {
                      "type": "SIGN_AUTH_CHALLENGE",
                      "requestId": "req-wait-disconnect",
                      "nonce": "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01",
                      "waitForCard": true
                    }
                    """);
            assertTrue(enteredDisconnect.await(3, TimeUnit.SECONDS));
            assertTrue(server.isHardwareOperationInProgress());

            client1.closeBlocking();
            assertTrue(abortedDisconnect.await(3, TimeUnit.SECONDS));
            assertEquals(CardWaitProvider.WaitOutcome.CLIENT_DISCONNECTED, lastWaitAbortReason.get());

            deadline = System.currentTimeMillis() + 2000;
            while (server.isHardwareOperationInProgress() && System.currentTimeMillis() < deadline) {
                Thread.sleep(5);
            }
            assertFalse(server.isHardwareOperationInProgress());
        } finally {
            client1.closeBlocking();
            client2.closeBlocking();
        }
    }

    @Test
    void testGetSigningCertificateWithoutPinOrCardNeverPromptsAndClearsOnRemoval() throws Exception {
        CountDownLatch closedLatch = new CountDownLatch(1);
        BlockingQueue<String> inbox = new LinkedBlockingQueue<>();

        WebSocketClient client = createTestClient(ALLOWED_ORIGIN, inbox, closedLatch);
        assertTrue(client.connectBlocking(3, TimeUnit.SECONDS));

        try {
            assertNotNull(inbox.poll(3, TimeUnit.SECONDS)); // CONNECTION_ESTABLISHED

            // 1. Card present, cache empty -> responds cleanly with null fields and 0 PIN prompts
            client.send("""
                    {
                      "type": "GET_SIGNING_CERTIFICATE",
                      "requestId": "req-cert-uncached"
                    }
                    """);
            JsonNode uncachedRes = mapper.readTree(inbox.poll(3, TimeUnit.SECONDS));
            assertEquals("SIGNING_CERTIFICATE_RESPONSE", uncachedRes.get("type").asText());
            assertEquals("req-cert-uncached", uncachedRes.get("requestId").asText());
            assertTrue(uncachedRes.get("certificatePem").isNull());
            assertTrue(uncachedRes.get("certificateDni").isNull());
            assertTrue(uncachedRes.get("certificateSerialNumber").isNull());
            assertEquals(0, pinPromptInvocationCount.get());
            assertEquals(0, cardWaitInvocationCount.get());

            // 2. Card removed -> still responds cleanly without prompting
            hardwareProbe.removeCard();
            readerManager.probeOnce(true);
            assertEquals("CARD_REMOVED", mapper.readTree(inbox.poll(3, TimeUnit.SECONDS)).get("type").asText());

            client.send("""
                    {
                      "type": "GET_SIGNING_CERTIFICATE",
                      "requestId": "req-cert-no-card"
                    }
                    """);
            JsonNode noCardRes = mapper.readTree(inbox.poll(3, TimeUnit.SECONDS));
            assertEquals("SIGNING_CERTIFICATE_RESPONSE", noCardRes.get("type").asText());
            assertTrue(noCardRes.get("certificatePem").isNull());
            assertEquals(0, pinPromptInvocationCount.get());
            assertEquals(0, cardWaitInvocationCount.get());

            // 3. Re-insert card, sign auth challenge once -> caches Non-Repudiation cert in RAM
            hardwareProbe.insertCard();
            readerManager.probeOnce(true);
            assertEquals("CARD_INSERTED", mapper.readTree(inbox.poll(3, TimeUnit.SECONDS)).get("type").asText());

            client.send("""
                    {
                      "type": "SIGN_AUTH_CHALLENGE",
                      "requestId": "req-auth-warm-cache",
                      "nonce": "a4f891e204b7c9103f8a12d4e567890123456789abcdef0123456789abcdef01"
                    }
                    """);
            JsonNode authRes = mapper.readTree(inbox.poll(5, TimeUnit.SECONDS));
            assertEquals("SUCCESS", authRes.get("status").asText());
            assertEquals(1, pinPromptInvocationCount.get());

            // 4. Subsequent GET_SIGNING_CERTIFICATE returns cached cert without triggering a 2nd PIN dialog
            client.send("""
                    {
                      "type": "GET_SIGNING_CERTIFICATE",
                      "requestId": "req-cert-cached"
                    }
                    """);
            JsonNode cachedRes = mapper.readTree(inbox.poll(3, TimeUnit.SECONDS));
            assertEquals("SIGNING_CERTIFICATE_RESPONSE", cachedRes.get("type").asText());
            assertEquals("req-cert-cached", cachedRes.get("requestId").asText());
            assertTrue(cachedRes.get("certificatePem").asText().contains("BEGIN CERTIFICATE"));
            assertEquals("71234567", cachedRes.get("certificateDni").asText());
            assertFalse(cachedRes.get("certificateSerialNumber").asText().isBlank());
            assertEquals(1, pinPromptInvocationCount.get(), "GET_SIGNING_CERTIFICATE must NEVER prompt for PIN");

            // 5. Removing card immediately clears cached certificate
            hardwareProbe.removeCard();
            readerManager.probeOnce(true);
            assertEquals("CARD_REMOVED", mapper.readTree(inbox.poll(3, TimeUnit.SECONDS)).get("type").asText());

            client.send("""
                    {
                      "type": "GET_SIGNING_CERTIFICATE",
                      "requestId": "req-cert-after-removal"
                    }
                    """);
            JsonNode afterRemovalRes = mapper.readTree(inbox.poll(3, TimeUnit.SECONDS));
            assertEquals("SIGNING_CERTIFICATE_RESPONSE", afterRemovalRes.get("type").asText());
            assertTrue(afterRemovalRes.get("certificatePem").isNull());
            assertEquals(1, pinPromptInvocationCount.get());
        } finally {
            client.closeBlocking();
        }
    }

    @Test
    void testSignedIntentVerificationValidTamperedExpiredReplayAndE6InWebSocket() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        KeyPair kp = kpg.generateKeyPair();
        String pubB64 = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());

        int intentPort;
        try (ServerSocket s = new ServerSocket(0)) {
            intentPort = s.getLocalPort();
        }

        AgentConfig intentConfig = new AgentConfig(
                "development",
                intentPort,
                "127.0.0.1",
                false,
                "./keystore/loopback.p12",
                "changeit",
                Set.of(ALLOWED_ORIGIN),
                "bit4ipki.dll",
                "idplug-pkcs11.dll",
                "auto",
                false,
                AgentConfig.DocumentDigestSignMode.PADES_DIGEST_INFO,
                true,
                true,
                "stable",
                AgentConfig.DEFAULT_UPDATE_MANIFEST_URL,
                6,
                "",
                AgentConfig.DEFAULT_UPDATE_ALLOWED_HOSTS,
                pubB64,
                true
        );

        MutableTestHardwareProbe localProbe = new MutableTestHardwareProbe(true);
        CardReaderManager localReaderManager = new CardReaderManager(intentConfig, localProbe);
        localReaderManager.probeOnce(false);
        CryptoService localCrypto = new CryptoService(
                intentConfig,
                localReaderManager,
                new TestSoftTokenPkcs11Bridge(intentConfig, "71234567", "JUAN PEREZ GARCIA")
        );

        AtomicInteger localPinPrompts = new AtomicInteger(0);
        AtomicReference<String> localPinDetails = new AtomicReference<>();
        PinPromptProvider localPinProvider = new PinPromptProvider() {
            @Override
            public PinPromptResult requestPin(String title, String operationHtmlDetails) {
                localPinPrompts.incrementAndGet();
                localPinDetails.set(operationHtmlDetails);
                return new PinPromptResult(new char[]{'1', '2', '3', '4', '5', '6'}, AbortReason.NONE);
            }

            @Override
            public PinPromptResult requestPin(String title, String operationHtmlDetails, int timeoutSeconds) {
                return requestPin(title, operationHtmlDetails);
            }

            @Override
            public void abortActivePromptForCardRemoval() {
            }

            @Override
            public void abortActivePrompt(AbortReason reason) {
            }
        };

        KillAgentWebSocketServer intentServer = new KillAgentWebSocketServer(
                intentConfig,
                localReaderManager,
                localCrypto,
                null,
                localPinProvider
        );
        intentServer.start();
        assertTrue(intentServer.awaitStart(5, TimeUnit.SECONDS));

        BlockingQueue<String> inbox = new LinkedBlockingQueue<>();
        CountDownLatch closedLatch = new CountDownLatch(1);
        WebSocketClient client = new WebSocketClient(
                URI.create("ws://127.0.0.1:" + intentPort),
                Map.of("Origin", ALLOWED_ORIGIN)
        ) {
            @Override
            public void onOpen(ServerHandshake handshakedata) {}

            @Override
            public void onMessage(String message) {
                inbox.offer(message);
            }

            @Override
            public void onClose(int code, String reason, boolean remote) {
                closedLatch.countDown();
            }

            @Override
            public void onError(Exception ex) {}
        };

        try {
            assertTrue(client.connectBlocking(3, TimeUnit.SECONDS));
            assertNotNull(inbox.poll(3, TimeUnit.SECONDS)); // CONNECTION_ESTABLISHED

            String docHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            String slotId = "slot-signed-001";
            String futureIso = Instant.now().plusSeconds(300).toString();

            // 1. Missing signingIntent when requireSignedIntent=true -> INVALID_SIGNING_INTENT
            client.send("""
                    {
                      "type": "SIGN_DOCUMENT_DIGEST",
                      "requestId": "req-missing-intent",
                      "slotId": "%s",
                      "documentHash": "%s",
                      "documentTitle": "Fake.pdf",
                      "signerRole": "SIGNER"
                    }
                    """.formatted(slotId, docHash));
            JsonNode missingRes = mapper.readTree(inbox.poll(3, TimeUnit.SECONDS));
            assertEquals("ERROR", missingRes.get("type").asText());
            assertEquals("INVALID_SIGNING_INTENT", missingRes.get("errorCode").asText());
            assertEquals(0, localPinPrompts.get());

            // 2. Valid Ed25519 signingIntent for SIGN_DOCUMENT_DIGEST -> SUCCESS, and WYSIWYS uses signed fields only
            SigningIntentPayload validDocPayload = new SigningIntentPayload(
                    "intent-ws-doc-1",
                    SigningIntentVerifier.OPERATION_SIGN_DOCUMENT_DIGEST,
                    slotId,
                    docHash,
                    "Resolución Oficial Firmada.pdf",
                    "DIRECTOR_EJECUTIVO",
                    "71234567",
                    futureIso
            );
            SignedIntentEnvelope validDocEnvelope = signIntent(validDocPayload, kp.getPrivate(), "kid-ws-1");
            String envelopeJson = mapper.writeValueAsString(validDocEnvelope);

            client.send("""
                    {
                      "type": "SIGN_DOCUMENT_DIGEST",
                      "requestId": "req-valid-intent",
                      "slotId": "%s",
                      "documentHash": "%s",
                      "documentTitle": "SPOOFED_TITLE_ATTACKER.pdf",
                      "signerRole": "SPOOFED_ROLE",
                      "signingIntent": %s
                    }
                    """.formatted(slotId, docHash, envelopeJson));
            JsonNode validDocRes = mapper.readTree(inbox.poll(5, TimeUnit.SECONDS));
            assertEquals("SIGN_DOCUMENT_DIGEST_RESPONSE", validDocRes.get("type").asText());
            assertEquals("SUCCESS", validDocRes.get("status").asText());
            assertEquals(1, localPinPrompts.get());
            assertTrue(localPinDetails.get().contains("Resolución Oficial Firmada.pdf"));
            assertTrue(localPinDetails.get().contains("DIRECTOR_EJECUTIVO"));
            assertFalse(localPinDetails.get().contains("SPOOFED_TITLE_ATTACKER.pdf"));
            assertFalse(localPinDetails.get().contains("SPOOFED_ROLE"));

            // 3. Replay of the same intentId -> INVALID_SIGNING_INTENT (PIN prompt NOT called)
            client.send("""
                    {
                      "type": "SIGN_DOCUMENT_DIGEST",
                      "requestId": "req-replay-intent",
                      "slotId": "%s",
                      "documentHash": "%s",
                      "signingIntent": %s
                    }
                    """.formatted(slotId, docHash, envelopeJson));
            JsonNode replayRes = mapper.readTree(inbox.poll(3, TimeUnit.SECONDS));
            assertEquals("ERROR", replayRes.get("type").asText());
            assertEquals("INVALID_SIGNING_INTENT", replayRes.get("errorCode").asText());
            assertEquals(1, localPinPrompts.get());

            // 4. Tampered signature -> INVALID_SIGNING_INTENT
            byte[] sigBytes = Base64.getUrlDecoder().decode(validDocEnvelope.signatureBase64Url());
            sigBytes[0] ^= 0x1A;
            SignedIntentEnvelope tamperedEnvelope = new SignedIntentEnvelope(
                    validDocEnvelope.payloadBase64Url(),
                    Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes),
                    "Ed25519",
                    "kid-ws-1"
            );
            client.send("""
                    {
                      "type": "SIGN_DOCUMENT_DIGEST",
                      "requestId": "req-tampered-intent",
                      "slotId": "%s",
                      "documentHash": "%s",
                      "signingIntent": %s
                    }
                    """.formatted(slotId, docHash, mapper.writeValueAsString(tamperedEnvelope)));
            JsonNode tamperedRes = mapper.readTree(inbox.poll(3, TimeUnit.SECONDS));
            assertEquals("INVALID_SIGNING_INTENT", tamperedRes.get("errorCode").asText());
            assertEquals(1, localPinPrompts.get());

            // 5. Expired intent -> INVALID_SIGNING_INTENT
            SigningIntentPayload expiredPayload = new SigningIntentPayload(
                    "intent-ws-expired",
                    SigningIntentVerifier.OPERATION_SIGN_DOCUMENT_DIGEST,
                    slotId,
                    docHash,
                    "Expired.pdf",
                    "SIGNER",
                    "71234567",
                    Instant.now().minusSeconds(30).toString()
            );
            client.send("""
                    {
                      "type": "SIGN_DOCUMENT_DIGEST",
                      "requestId": "req-expired-intent",
                      "slotId": "%s",
                      "documentHash": "%s",
                      "signingIntent": %s
                    }
                    """.formatted(slotId, docHash, mapper.writeValueAsString(signIntent(expiredPayload, kp.getPrivate(), "kid-ws-1"))));
            JsonNode expiredRes = mapper.readTree(inbox.poll(3, TimeUnit.SECONDS));
            assertEquals("INVALID_SIGNING_INTENT", expiredRes.get("errorCode").asText());
            assertEquals(1, localPinPrompts.get());

            // 6. E6 substitution: outer documentHash differs from signed intent -> INVALID_SIGNING_INTENT
            SigningIntentPayload e6HashPayload = new SigningIntentPayload(
                    "intent-ws-e6-hash",
                    SigningIntentVerifier.OPERATION_SIGN_DOCUMENT_DIGEST,
                    slotId,
                    docHash,
                    "Legit.pdf",
                    "SIGNER",
                    "71234567",
                    futureIso
            );
            client.send("""
                    {
                      "type": "SIGN_DOCUMENT_DIGEST",
                      "requestId": "req-e6-hash",
                      "slotId": "%s",
                      "documentHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                      "signingIntent": %s
                    }
                    """.formatted(slotId, mapper.writeValueAsString(signIntent(e6HashPayload, kp.getPrivate(), "kid-ws-1"))));
            JsonNode e6HashRes = mapper.readTree(inbox.poll(3, TimeUnit.SECONDS));
            assertEquals("INVALID_SIGNING_INTENT", e6HashRes.get("errorCode").asText());
            assertEquals(1, localPinPrompts.get());

            // 7. E6 substitution: outer slotId differs from signed intent -> INVALID_SIGNING_INTENT
            SigningIntentPayload e6SlotPayload = new SigningIntentPayload(
                    "intent-ws-e6-slot",
                    SigningIntentVerifier.OPERATION_SIGN_DOCUMENT_DIGEST,
                    slotId,
                    docHash,
                    "Legit.pdf",
                    "SIGNER",
                    "71234567",
                    futureIso
            );
            client.send("""
                    {
                      "type": "SIGN_DOCUMENT_DIGEST",
                      "requestId": "req-e6-slot",
                      "slotId": "slot-attacker-999",
                      "documentHash": "%s",
                      "signingIntent": %s
                    }
                    """.formatted(docHash, mapper.writeValueAsString(signIntent(e6SlotPayload, kp.getPrivate(), "kid-ws-1"))));
            JsonNode e6SlotRes = mapper.readTree(inbox.poll(3, TimeUnit.SECONDS));
            assertEquals("INVALID_SIGNING_INTENT", e6SlotRes.get("errorCode").asText());
            assertEquals(1, localPinPrompts.get());

            // 8. Valid Ed25519 signingIntent for SIGN_AUTH_CHALLENGE -> SUCCESS
            String authNonce = "nonce-auth-signed-999";
            SigningIntentPayload authPayload = new SigningIntentPayload(
                    "intent-ws-auth-1",
                    SigningIntentVerifier.OPERATION_SIGN_AUTH_CHALLENGE,
                    null,
                    authNonce,
                    null,
                    null,
                    "71234567",
                    futureIso
            );
            client.send("""
                    {
                      "type": "SIGN_AUTH_CHALLENGE",
                      "requestId": "req-valid-auth-intent",
                      "nonce": "%s",
                      "signingIntent": %s
                    }
                    """.formatted(authNonce, mapper.writeValueAsString(signIntent(authPayload, kp.getPrivate(), "kid-ws-1"))));
            JsonNode authRes = mapper.readTree(inbox.poll(5, TimeUnit.SECONDS));
            assertEquals("SIGN_AUTH_CHALLENGE_RESPONSE", authRes.get("type").asText());
            assertEquals("SUCCESS", authRes.get("status").asText());
            assertEquals(2, localPinPrompts.get());
        } finally {
            client.closeBlocking();
            intentServer.shutdownCleanly(1000);
            localReaderManager.stop();
        }
    }

    private SignedIntentEnvelope signIntent(
            SigningIntentPayload payload,
            PrivateKey privateKey,
            String keyId
    ) throws Exception {
        byte[] jsonBytes = mapper.writeValueAsBytes(payload);
        String payloadB64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(jsonBytes);
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(privateKey);
        signer.update(payloadB64Url.getBytes(StandardCharsets.UTF_8));
        String sigB64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
        return new SignedIntentEnvelope(payloadB64Url, sigB64Url, "Ed25519", keyId);
    }

    private WebSocketClient createTestClient(
            String originHeader,
            BlockingQueue<String> inbox,
            CountDownLatch closedLatch
    ) {
        return new WebSocketClient(
                URI.create("ws://127.0.0.1:" + testPort),
                Map.of("Origin", originHeader)
        ) {
            @Override
            public void onOpen(ServerHandshake handshakedata) {
            }

            @Override
            public void onMessage(String message) {
                inbox.offer(message);
            }

            @Override
            public void onClose(int code, String reason, boolean remote) {
                closedLatch.countDown();
            }

            @Override
            public void onError(Exception ex) {
            }
        };
    }
}

