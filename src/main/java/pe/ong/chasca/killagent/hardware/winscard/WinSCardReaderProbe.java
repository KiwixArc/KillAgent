package pe.ong.chasca.killagent.hardware.winscard;

import com.sun.jna.Memory;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.BaseTSD;
import com.sun.jna.ptr.IntByReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pe.ong.chasca.killagent.hardware.HardwareProbe;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Native Windows WinSCard ({@code Winscard.dll}) hardware monitor using JNA.
 * <p>
 * Solves two root-cause bugs in OpenJDK {@code javax.smartcardio}:
 * <ul>
 *     <li>Releasing and re-establishing {@code SCARDCONTEXT} immediately whenever Windows stops or
 *     restarts {@code SCardSvr} on USB reader removal/re-insertion.</li>
 *     <li>Reading card presence and ATR directly from {@code SCARD_READERSTATE} without opening a
 *     competing {@code SCardConnect} session that could interfere with {@code idplug-pkcs11.dll}.</li>
 * </ul>
 */
public final class WinSCardReaderProbe implements HardwareProbe {

    private static final Logger logger = LoggerFactory.getLogger(WinSCardReaderProbe.class);
    private static final int DEFAULT_WAIT_MS = 350;
    private static final int ERROR_BACKOFF_MS = 300;

    private final WinSCardApi api;
    private final Object operationLock = new Object();

    private volatile BaseTSD.ULONG_PTR hContext;
    private final Map<String, Integer> knownReaderStates = new LinkedHashMap<>();
    private int lastPnpEventState = WinSCardApi.SCARD_STATE_UNAWARE;
    private boolean pnpSupported = true;
    private volatile boolean closed = false;

    public WinSCardReaderProbe() {
        this(WinSCardApi.load());
    }

    public WinSCardReaderProbe(WinSCardApi api) {
        this.api = Objects.requireNonNull(api, "WinSCardApi must not be null");
    }

    @Override
    public Snapshot probe() {
        synchronized (operationLock) {
            if (closed) {
                return Snapshot.empty();
            }

            BaseTSD.ULONG_PTR ctx = ensureContext();
            if (ctx == null) {
                return Snapshot.empty();
            }

            List<String> readerNames = listReaders(ctx);
            if (readerNames == null) {
                // Context invalidated by service/handle fault; already released cleanly
                return Snapshot.empty();
            }
            if (readerNames.isEmpty()) {
                knownReaderStates.clear();
                return Snapshot.empty();
            }

            return queryReadersState(ctx, readerNames, true);
        }
    }

    private Snapshot queryReadersState(BaseTSD.ULONG_PTR ctx, List<String> readerNames, boolean allowRelistOnMissingReader) {
        WinSCardApi.SCARD_READERSTATE[] states = allocateReaderStates(readerNames.size());
        for (int i = 0; i < readerNames.size(); i++) {
            states[i].szReader = new WString(readerNames.get(i));
            states[i].pvUserData = null;
            states[i].dwCurrentState = WinSCardApi.SCARD_STATE_UNAWARE;
            states[i].dwEventState = 0;
            states[i].cbAtr = 0;
        }

        int rc = api.SCardGetStatusChange(ctx, 0, states, readerNames.size());
        if (isServiceOrHandleError(rc)) {
            invalidateContext("SCardGetStatusChange(probe)", rc);
            return Snapshot.empty();
        }
        if (rc == WinSCardApi.SCARD_E_UNKNOWN_READER || rc == WinSCardApi.SCARD_E_READER_UNAVAILABLE) {
            knownReaderStates.clear();
            if (allowRelistOnMissingReader) {
                List<String> refreshed = listReaders(ctx);
                if (refreshed != null && !refreshed.isEmpty()) {
                    return queryReadersState(ctx, refreshed, false);
                }
            }
            logger.debug("Reader unavailable during SCardGetStatusChange probe: {}", WinSCardApi.formatError(rc));
            return Snapshot.empty();
        }
        if (rc != WinSCardApi.SCARD_S_SUCCESS && rc != WinSCardApi.SCARD_E_TIMEOUT) {
            logger.debug("SCardGetStatusChange(probe) returned unexpected status: {}", WinSCardApi.formatError(rc));
            return Snapshot.empty();
        }

        List<ReaderSnapshot> snapshots = new ArrayList<>(readerNames.size());
        Map<String, Integer> updatedStates = new LinkedHashMap<>();

        for (int i = 0; i < readerNames.size(); i++) {
            String name = readerNames.get(i);
            int eventState = states[i].dwEventState;

            if ((eventState & (WinSCardApi.SCARD_STATE_UNKNOWN | WinSCardApi.SCARD_STATE_UNAVAILABLE)) != 0) {
                continue;
            }

            updatedStates.put(name, eventState & ~WinSCardApi.SCARD_STATE_CHANGED);

            boolean cardPresent = (eventState & WinSCardApi.SCARD_STATE_PRESENT) != 0;
            byte[] atrBytes = new byte[0];
            if (cardPresent && states[i].cbAtr > 0) {
                int len = Math.min(states[i].cbAtr, WinSCardApi.MAX_ATR_LENGTH);
                atrBytes = Arrays.copyOf(states[i].rgbAtr, len);
            }
            snapshots.add(new ReaderSnapshot(name, cardPresent, atrBytes));
        }

        knownReaderStates.clear();
        knownReaderStates.putAll(updatedStates);
        return new Snapshot(snapshots);
    }

    @Override
    public void waitForChange(int timeoutMs) throws InterruptedException {
        if (closed) {
            return;
        }
        int effectiveTimeout = Math.max(50, Math.min(timeoutMs, DEFAULT_WAIT_MS));

        BaseTSD.ULONG_PTR ctx;
        boolean hasReaders;
        synchronized (operationLock) {
            if (closed) {
                return;
            }
            ctx = ensureContext();
            hasReaders = !knownReaderStates.isEmpty();
        }

        if (ctx == null) {
            Thread.sleep(Math.min(effectiveTimeout, ERROR_BACKOFF_MS));
            return;
        }

        if (!hasReaders) {
            waitForReaderPlugIn(ctx, effectiveTimeout);
        } else {
            waitForReaderOrCardChange(ctx, effectiveTimeout);
        }
    }

    private void waitForReaderPlugIn(BaseTSD.ULONG_PTR expectedCtx, int effectiveTimeout) throws InterruptedException {
        if (!pnpSupported) {
            Thread.sleep(Math.min(effectiveTimeout, ERROR_BACKOFF_MS));
            return;
        }

        boolean needBackoffSleep = false;
        synchronized (operationLock) {
            if (closed || hContext != expectedCtx) {
                return;
            }
            if (lastPnpEventState == WinSCardApi.SCARD_STATE_UNAWARE) {
                if (!primePnpState(expectedCtx)) {
                    needBackoffSleep = true;
                }
            }
            if (!needBackoffSleep && pnpSupported && hContext == expectedCtx) {
                WinSCardApi.SCARD_READERSTATE[] pnpStates = allocateReaderStates(1);
                pnpStates[0].szReader = new WString(WinSCardApi.PNP_NOTIFICATION_READER);
                pnpStates[0].pvUserData = null;
                pnpStates[0].dwCurrentState = lastPnpEventState;

                int rc = api.SCardGetStatusChange(expectedCtx, effectiveTimeout, pnpStates, 1);
                if (isServiceOrHandleError(rc)) {
                    invalidateContext("SCardGetStatusChange(PnP)", rc);
                    needBackoffSleep = true;
                } else if (rc == WinSCardApi.SCARD_S_SUCCESS) {
                    int evt = pnpStates[0].dwEventState;
                    if (isPnpUnsupportedState(evt)) {
                        pnpSupported = false;
                        needBackoffSleep = true;
                    } else {
                        lastPnpEventState = evt & ~WinSCardApi.SCARD_STATE_CHANGED;
                        if ((evt & WinSCardApi.SCARD_STATE_CHANGED) == 0) {
                            needBackoffSleep = true;
                        }
                    }
                } else if (rc != WinSCardApi.SCARD_E_TIMEOUT && rc != WinSCardApi.SCARD_E_CANCELLED) {
                    needBackoffSleep = true;
                }
            }
        }

        if (needBackoffSleep && !closed) {
            Thread.sleep(Math.min(effectiveTimeout, ERROR_BACKOFF_MS));
        }
    }

    private void waitForReaderOrCardChange(BaseTSD.ULONG_PTR expectedCtx, int effectiveTimeout) throws InterruptedException {
        boolean needErrorSleep = false;
        synchronized (operationLock) {
            if (closed || hContext != expectedCtx || knownReaderStates.isEmpty()) {
                return;
            }

            if (pnpSupported && lastPnpEventState == WinSCardApi.SCARD_STATE_UNAWARE) {
                if (!primePnpState(expectedCtx)) {
                    // Service/context fault invalidated hContext -> return immediately so probe() emits disconnect
                    if (hContext == null) {
                        return;
                    }
                }
            }

            int readerCount = knownReaderStates.size();
            boolean includePnp = pnpSupported;
            int totalEntries = readerCount + (includePnp ? 1 : 0);
            WinSCardApi.SCARD_READERSTATE[] states = allocateReaderStates(totalEntries);

            int idx = 0;
            for (Map.Entry<String, Integer> entry : knownReaderStates.entrySet()) {
                states[idx].szReader = new WString(entry.getKey());
                states[idx].pvUserData = null;
                states[idx].dwCurrentState = entry.getValue();
                idx++;
            }
            if (includePnp) {
                states[idx].szReader = new WString(WinSCardApi.PNP_NOTIFICATION_READER);
                states[idx].pvUserData = null;
                states[idx].dwCurrentState = lastPnpEventState;
            }

            int rc = api.SCardGetStatusChange(expectedCtx, effectiveTimeout, states, totalEntries);
            if (isServiceOrHandleError(rc)) {
                invalidateContext("SCardGetStatusChange(wait)", rc);
                return;
            }
            if (rc == WinSCardApi.SCARD_E_UNKNOWN_READER || rc == WinSCardApi.SCARD_E_READER_UNAVAILABLE) {
                return;
            }
            if (rc == WinSCardApi.SCARD_S_SUCCESS && includePnp) {
                int pnpEvt = states[totalEntries - 1].dwEventState;
                if (isPnpUnsupportedState(pnpEvt)) {
                    pnpSupported = false;
                } else {
                    lastPnpEventState = pnpEvt & ~WinSCardApi.SCARD_STATE_CHANGED;
                }
            } else if (rc != WinSCardApi.SCARD_S_SUCCESS
                    && rc != WinSCardApi.SCARD_E_TIMEOUT
                    && rc != WinSCardApi.SCARD_E_CANCELLED) {
                needErrorSleep = true;
            }
        }

        if (needErrorSleep && !closed) {
            Thread.sleep(Math.min(effectiveTimeout, 100));
        }
    }

    private boolean primePnpState(BaseTSD.ULONG_PTR ctx) {
        WinSCardApi.SCARD_READERSTATE[] pnpInit = allocateReaderStates(1);
        pnpInit[0].szReader = new WString(WinSCardApi.PNP_NOTIFICATION_READER);
        pnpInit[0].pvUserData = null;
        pnpInit[0].dwCurrentState = WinSCardApi.SCARD_STATE_UNAWARE;

        int rc = api.SCardGetStatusChange(ctx, 0, pnpInit, 1);
        if (isServiceOrHandleError(rc)) {
            invalidateContext("SCardGetStatusChange(PnP-init)", rc);
            return false;
        }
        if (rc == WinSCardApi.SCARD_S_SUCCESS) {
            int evt = pnpInit[0].dwEventState;
            if (isPnpUnsupportedState(evt)) {
                pnpSupported = false;
                return false;
            }
            lastPnpEventState = evt & ~WinSCardApi.SCARD_STATE_CHANGED;
            return true;
        }
        return false;
    }

    private static boolean isPnpUnsupportedState(int eventState) {
        return (eventState & (WinSCardApi.SCARD_STATE_UNKNOWN
                | WinSCardApi.SCARD_STATE_UNAVAILABLE
                | WinSCardApi.SCARD_STATE_IGNORE)) != 0;
    }

    private BaseTSD.ULONG_PTR ensureContext() {
        if (closed) {
            return null;
        }
        if (hContext != null && hContext.longValue() != 0L) {
            return hContext;
        }

        BaseTSD.ULONG_PTRByReference phContext = new BaseTSD.ULONG_PTRByReference();
        int rc = api.SCardEstablishContext(WinSCardApi.SCARD_SCOPE_USER, null, null, phContext);
        if (rc == WinSCardApi.SCARD_S_SUCCESS) {
            BaseTSD.ULONG_PTR ctx = phContext.getValue();
            if (ctx != null && ctx.longValue() != 0L) {
                hContext = ctx;
                lastPnpEventState = WinSCardApi.SCARD_STATE_UNAWARE;
                knownReaderStates.clear();
                logger.debug("Established fresh WinSCard context (hContext=0x{}).",
                        Long.toHexString(ctx.longValue()));
                return hContext;
            }
        }

        if (isServiceOrHandleError(rc)) {
            logger.debug("WinSCard Resource Manager inactive ({}); will retry.", WinSCardApi.formatError(rc));
        } else {
            logger.warn("SCardEstablishContext failed: {}", WinSCardApi.formatError(rc));
        }
        return null;
    }

    private List<String> listReaders(BaseTSD.ULONG_PTR ctx) {
        IntByReference pcchReaders = new IntByReference(0);
        int rc = api.SCardListReaders(ctx, null, null, pcchReaders);
        if (rc == WinSCardApi.SCARD_E_NO_READERS_AVAILABLE) {
            return List.of();
        }
        if (isServiceOrHandleError(rc)) {
            invalidateContext("SCardListReaders(size)", rc);
            return null;
        }
        if (rc != WinSCardApi.SCARD_S_SUCCESS) {
            logger.debug("SCardListReaders(size) returned: {}", WinSCardApi.formatError(rc));
            return List.of();
        }

        int cch = pcchReaders.getValue();
        if (cch <= 1) {
            return List.of();
        }

        for (int attempt = 0; attempt < 2; attempt++) {
            Memory buffer = new Memory((long) cch * Character.BYTES);
            IntByReference bufChars = new IntByReference(cch);
            rc = api.SCardListReaders(ctx, null, buffer, bufChars);
            if (rc == WinSCardApi.SCARD_E_INSUFFICIENT_BUFFER) {
                cch = Math.max(bufChars.getValue(), cch * 2);
                continue;
            }
            if (rc == WinSCardApi.SCARD_E_NO_READERS_AVAILABLE) {
                return List.of();
            }
            if (isServiceOrHandleError(rc)) {
                invalidateContext("SCardListReaders(read)", rc);
                return null;
            }
            if (rc != WinSCardApi.SCARD_S_SUCCESS) {
                logger.debug("SCardListReaders(read) returned: {}", WinSCardApi.formatError(rc));
                return List.of();
            }

            int actualChars = Math.min(cch, Math.max(0, bufChars.getValue()));
            if (actualChars <= 1) {
                return List.of();
            }
            return parseMultiStringUtf16(buffer.getCharArray(0, actualChars));
        }
        return List.of();
    }

    private void invalidateContext(String reason, int errorCode) {
        BaseTSD.ULONG_PTR toRelease = hContext;
        hContext = null;
        knownReaderStates.clear();
        lastPnpEventState = WinSCardApi.SCARD_STATE_UNAWARE;

        if (toRelease != null && toRelease.longValue() != 0L) {
            try {
                int rc = api.SCardReleaseContext(toRelease);
                logger.debug("Released WinSCard context ({}: {}), releaseRc={}",
                        reason, WinSCardApi.formatError(errorCode), WinSCardApi.formatError(rc));
            } catch (Throwable t) {
                logger.debug("Ignoring error releasing WinSCard context: {}", t.getMessage());
            }
        }
    }

    @Override
    public void cancelPendingWait() {
        BaseTSD.ULONG_PTR ctx = hContext;
        if (ctx != null && ctx.longValue() != 0L) {
            try {
                api.SCardCancel(ctx);
            } catch (Throwable ignored) {
            }
        }
    }

    @Override
    public void close() {
        closed = true;
        cancelPendingWait();
        synchronized (operationLock) {
            invalidateContext("close", WinSCardApi.SCARD_S_SUCCESS);
        }
    }

    static boolean isServiceOrHandleError(int rc) {
        return rc == WinSCardApi.SCARD_E_NO_SERVICE
                || rc == WinSCardApi.SCARD_E_SERVICE_STOPPED
                || rc == WinSCardApi.SCARD_E_INVALID_HANDLE
                || rc == WinSCardApi.SCARD_E_COMM_DATA_LOST
                || rc == WinSCardApi.SCARD_E_SYSTEM_CANCELLED;
    }

    static List<String> parseMultiStringUtf16(char[] chars) {
        if (chars == null || chars.length == 0) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        int start = 0;
        for (int i = 0; i < chars.length; i++) {
            if (chars[i] == '\0') {
                if (i == start) {
                    break;
                }
                String entry = new String(chars, start, i - start).trim();
                if (!entry.isEmpty()) {
                    result.add(entry);
                }
                start = i + 1;
            }
        }
        if (start < chars.length) {
            String trailing = new String(chars, start, chars.length - start).trim();
            if (!trailing.isEmpty()) {
                result.add(trailing);
            }
        }
        return List.copyOf(result);
    }

    private static WinSCardApi.SCARD_READERSTATE[] allocateReaderStates(int count) {
        WinSCardApi.SCARD_READERSTATE template = new WinSCardApi.SCARD_READERSTATE();
        return (WinSCardApi.SCARD_READERSTATE[]) template.toArray(count);
    }
}
