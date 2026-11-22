package pe.ong.chasca.killagent.crypto;

import pe.ong.chasca.killagent.server.dto.ErrorCode;

import javax.security.auth.login.FailedLoginException;
import java.util.Locale;

/**
 * Typed cryptographic exception mapping hardware/PKCS#11 failures directly
 * to protocol-compliant ErrorCodes and remaining PIN attempt counts.
 */
public class CryptoOperationException extends Exception {

    private final ErrorCode errorCode;
    private final Integer attemptsRemaining;

    public CryptoOperationException(ErrorCode errorCode, String message) {
        this(errorCode, message, null, null);
    }

    public CryptoOperationException(ErrorCode errorCode, String message, Integer attemptsRemaining) {
        this(errorCode, message, attemptsRemaining, null);
    }

    public CryptoOperationException(ErrorCode errorCode, String message, Integer attemptsRemaining, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        this.attemptsRemaining = attemptsRemaining;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }

    public Integer getAttemptsRemaining() {
        return attemptsRemaining;
    }

    /**
     * Translates low-level JCA / SunPKCS11 exceptions (CKR_* error tokens) into structured CryptoOperationExceptions.
     */
    public static CryptoOperationException fromPkcs11Exception(Throwable throwable, Integer fallbackAttempts) {
        if (throwable instanceof CryptoOperationException coe) {
            return coe;
        }

        Throwable cursor = throwable;
        StringBuilder diagnosticChain = new StringBuilder();
        boolean failedLoginSeen = false;

        while (cursor != null) {
            if (cursor instanceof FailedLoginException) {
                failedLoginSeen = true;
            }
            if (cursor.getMessage() != null) {
                diagnosticChain.append(cursor.getMessage()).append(" | ");
            }
            cursor = cursor.getCause();
        }

        String upper = diagnosticChain.toString().toUpperCase(Locale.ROOT);

        if (upper.contains("CKR_PIN_LOCKED") || upper.contains("PIN_LOCKED") || upper.contains("CKR_PIN_EXPIRED")) {
            return new CryptoOperationException(
                    ErrorCode.PIN_LOCKED,
                    "El PIN del DNIe se encuentra bloqueado. Acuda a una agencia RENIEC o utilice su código PUK.",
                    0,
                    throwable
            );
        }

        if (failedLoginSeen
                || upper.contains("CKR_PIN_INCORRECT")
                || upper.contains("CKR_PIN_INVALID")
                || upper.contains("CKR_PIN_LEN_RANGE")
                || upper.contains("PIN_INCORRECT")) {
            String msg = (fallbackAttempts != null && fallbackAttempts > 0)
                    ? "El PIN ingresado es incorrecto. Quedan " + fallbackAttempts + " intentos restantes."
                    : "El PIN ingresado es incorrecto.";
            return new CryptoOperationException(ErrorCode.PIN_INCORRECT, msg, fallbackAttempts, throwable);
        }

        if (upper.contains("CKR_TOKEN_NOT_PRESENT")
                || upper.contains("CKR_DEVICE_REMOVED")
                || upper.contains("CKR_TOKEN_NOT_RECOGNIZED")
                || upper.contains("TOKEN HAS BEEN REMOVED")
                || upper.contains("NO TOKEN PRESENT")) {
            return new CryptoOperationException(
                    ErrorCode.CARD_NOT_PRESENT,
                    "No se detectó el chip del DNIe en el lector inteligente.",
                    null,
                    throwable
            );
        }

        return new CryptoOperationException(
                ErrorCode.PKCS11_ERROR,
                "Fallo en subsistema criptográfico PKCS#11: " + (throwable.getMessage() != null ? throwable.getMessage() : throwable.getClass().getSimpleName()),
                null,
                throwable
        );
    }
}

