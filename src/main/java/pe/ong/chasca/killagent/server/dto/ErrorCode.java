package pe.ong.chasca.killagent.server.dto;

/**
 * Standardized error taxonomy for KILLAgent WebSocket protocol responses.
 */
public enum ErrorCode {
    PIN_INCORRECT,
    PIN_LOCKED,
    PIN_TIMEOUT,
    CARD_NOT_PRESENT,
    USER_CANCELLED,
    PKCS11_ERROR,
    CERTIFICATE_EXPIRED,
    OPERATION_IN_PROGRESS,
    UNAUTHORIZED_ORIGIN,
    INVALID_SIGNING_INTENT,
    MALFORMED_REQUEST,
    INTERNAL_SERVER_ERROR
}
