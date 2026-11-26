package pe.ong.chasca.killagent.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import pe.ong.chasca.killagent.hardware.CardType;
import pe.ong.chasca.killagent.hardware.HardwareStatus;
import pe.ong.chasca.killagent.server.dto.*;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class WebSocketProtocolSerializationTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void testConnectionEstablishedSerialization() throws Exception {
        HardwareStatus status = new HardwareStatus(true, true, "Identiv uTrust 2700 R", CardType.DNIE_3_0, false);
        ConnectionEstablishedMessage msg = new ConnectionEstablishedMessage("ws-killagent-123", "1.0.0", status);

        String json = mapper.writeValueAsString(msg);
        assertTrue(json.contains("\"type\":\"CONNECTION_ESTABLISHED\""));
        assertTrue(json.contains("\"wsConnectionId\":\"ws-killagent-123\""));
        assertTrue(json.contains("\"cardType\":\"DNIE_3_0\""));
    }

    @Test
    void testCardNotificationsSerialization() throws Exception {
        CardInsertedNotification inserted = new CardInsertedNotification("Identiv Reader");
        String jsonInserted = mapper.writeValueAsString(inserted);
        assertTrue(jsonInserted.contains("\"type\":\"CARD_INSERTED\""));
        assertTrue(jsonInserted.contains("Identiv Reader"));

        CardRemovedNotification removed = new CardRemovedNotification();
        String jsonRemoved = mapper.writeValueAsString(removed);
        assertTrue(jsonRemoved.contains("\"type\":\"CARD_REMOVED\""));

        ReaderStatusNotification readerConnected = new ReaderStatusNotification(true, "Identiv uTrust 2700 R");
        String jsonConnected = mapper.writeValueAsString(readerConnected);
        assertTrue(jsonConnected.contains("\"type\":\"READER_STATUS_CHANGED\""));
        assertTrue(jsonConnected.contains("\"readerPresent\":true"));
        assertTrue(jsonConnected.contains("\"readerName\":\"Identiv uTrust 2700 R\""));
        assertNotNull(readerConnected.timestamp());

        ReaderStatusNotification readerDisconnected = new ReaderStatusNotification(false, null);
        String jsonDisconnected = mapper.writeValueAsString(readerDisconnected);
        assertTrue(jsonDisconnected.contains("\"type\":\"READER_STATUS_CHANGED\""));
        assertTrue(jsonDisconnected.contains("\"readerPresent\":false"));
        assertTrue(jsonDisconnected.contains("\"readerName\":null"));
    }

    @Test
    void testSignAuthChallengeSerialization() throws Exception {
        SignAuthChallengeResponse res = SignAuthChallengeResponse.success(
                "req-1",
                "nonce123",
                "sigB64",
                "-----BEGIN CERTIFICATE-----\n...",
                "ws-id",
                Map.of("dni", "71234567")
        );

        String json = mapper.writeValueAsString(res);
        assertTrue(json.contains("\"type\":\"SIGN_AUTH_CHALLENGE_RESPONSE\""));
        assertTrue(json.contains("\"status\":\"SUCCESS\""));
        assertTrue(json.contains("\"dni\":\"71234567\""));
    }

    @Test
    void testSignAuthChallengeRequestBackwardCompatibleAndWithMetadata() throws Exception {
        String legacyJson = """
                {
                  "type": "SIGN_AUTH_CHALLENGE",
                  "requestId": "req-legacy",
                  "nonce": "abcdef01"
                }
                """;
        SignAuthChallengeRequest legacyReq = mapper.readValue(legacyJson, SignAuthChallengeRequest.class);
        assertEquals("SIGN_AUTH_CHALLENGE", legacyReq.type());
        assertEquals("req-legacy", legacyReq.requestId());
        assertEquals("abcdef01", legacyReq.nonce());
        assertNull(legacyReq.operationTitle());
        assertNull(legacyReq.operationDescription());
        assertNull(legacyReq.waitForCard());

        String customJson = """
                {
                  "type": "SIGN_AUTH_CHALLENGE",
                  "requestId": "req-custom",
                  "nonce": "abcdef02",
                  "operationTitle": "Desbloqueo de Sesión",
                  "operationDescription": "Confirmar identidad para desbloquear",
                  "waitForCard": true,
                  "extraUnknownField": "ignored"
                }
                """;
        SignAuthChallengeRequest customReq = mapper.readValue(customJson, SignAuthChallengeRequest.class);
        assertEquals("Desbloqueo de Sesión", customReq.operationTitle());
        assertEquals("Confirmar identidad para desbloquear", customReq.operationDescription());
        assertEquals(Boolean.TRUE, customReq.waitForCard());

        String noWaitJson = """
                {
                  "type": "SIGN_AUTH_CHALLENGE",
                  "requestId": "req-nowait",
                  "nonce": "abcdef03",
                  "waitForCard": false
                }
                """;
        SignAuthChallengeRequest noWaitReq = mapper.readValue(noWaitJson, SignAuthChallengeRequest.class);
        assertEquals(Boolean.FALSE, noWaitReq.waitForCard());
    }

    @Test
    void testErrorMessageSerialization() throws Exception {
        ErrorMessage err = new ErrorMessage("req-2", ErrorCode.PIN_INCORRECT, "El PIN ingresado es incorrecto.", 2);
        String json = mapper.writeValueAsString(err);
        assertTrue(json.contains("\"type\":\"ERROR\""));
        assertTrue(json.contains("\"errorCode\":\"PIN_INCORRECT\""));
        assertTrue(json.contains("\"attemptsRemaining\":2"));

        ErrorMessage intentErr = new ErrorMessage("req-3", ErrorCode.INVALID_SIGNING_INTENT, "Firma Ed25519 inválida.");
        String intentJson = mapper.writeValueAsString(intentErr);
        assertTrue(intentJson.contains("\"errorCode\":\"INVALID_SIGNING_INTENT\""));
    }

    @Test
    void testSigningCertificateResponseSerializationIncludesNulls() throws Exception {
        SigningCertificateResponseMessage emptyRes =
                new SigningCertificateResponseMessage("req-cert-1", null, null, null);
        String json = mapper.writeValueAsString(emptyRes);
        assertTrue(json.contains("\"type\":\"SIGNING_CERTIFICATE_RESPONSE\""));
        assertTrue(json.contains("\"requestId\":\"req-cert-1\""));
        assertTrue(json.contains("\"certificatePem\":null"));
        assertTrue(json.contains("\"certificateDni\":null"));
        assertTrue(json.contains("\"certificateSerialNumber\":null"));
    }

    @Test
    void testSignDocumentDigestRequestWithOptionalSigningIntent() throws Exception {
        String json = """
                {
                  "type": "SIGN_DOCUMENT_DIGEST",
                  "requestId": "req-doc-1",
                  "slotId": "slot-1",
                  "documentHash": "abcd",
                  "documentTitle": "Doc.pdf",
                  "signerRole": "SIGNER",
                  "signingIntent": {
                    "payloadBase64Url": "eyJpbnRlbnRJZCI6IjEifQ",
                    "signatureBase64Url": "c2ln",
                    "algorithm": "Ed25519",
                    "keyId": "k1"
                  }
                }
                """;
        SignDocumentDigestRequest req = mapper.readValue(json, SignDocumentDigestRequest.class);
        assertNotNull(req.signingIntent());
        assertEquals("Ed25519", req.signingIntent().algorithm());
        assertEquals("k1", req.signingIntent().keyId());
    }
}

