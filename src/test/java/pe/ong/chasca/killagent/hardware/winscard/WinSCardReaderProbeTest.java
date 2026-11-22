package pe.ong.chasca.killagent.hardware.winscard;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.BaseTSD;
import com.sun.jna.ptr.IntByReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import pe.ong.chasca.killagent.hardware.HardwareProbe;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class WinSCardReaderProbeTest {

    @Test
    void testParseMultiStringUtf16() {
        char[] single = "Identiv uTrust 2700 R 0\0\0".toCharArray();
        assertEquals(List.of("Identiv uTrust 2700 R 0"), WinSCardReaderProbe.parseMultiStringUtf16(single));

        char[] multiple = "Reader One 0\0Reader Two 1\0\0".toCharArray();
        assertEquals(List.of("Reader One 0", "Reader Two 1"), WinSCardReaderProbe.parseMultiStringUtf16(multiple));

        char[] empty = "\0\0".toCharArray();
        assertTrue(WinSCardReaderProbe.parseMultiStringUtf16(empty).isEmpty());
    }

    @Test
    void testServiceStoppedReleasesContextAndReestablishesOnRecovery() {
        byte[] atr = HexFormat.of().parseHex("3B7F96000080318065B085040120120FFF829000");
        AtomicLong nextContextHandle = new AtomicLong(100L);
        AtomicInteger phase = new AtomicInteger(0);
        List<Long> establishedHandles = new ArrayList<>();
        List<Long> releasedHandles = new ArrayList<>();

        WinSCardApi fakeApi = new WinSCardApi() {
            @Override
            public int SCardEstablishContext(int dwScope, Pointer pvReserved1, Pointer pvReserved2, BaseTSD.ULONG_PTRByReference phContext) {
                long handle = nextContextHandle.getAndAdd(100L);
                establishedHandles.add(handle);
                phContext.setValue(new BaseTSD.ULONG_PTR(handle));
                return SCARD_S_SUCCESS;
            }

            @Override
            public int SCardReleaseContext(BaseTSD.ULONG_PTR hContext) {
                releasedHandles.add(hContext.longValue());
                return SCARD_S_SUCCESS;
            }

            @Override
            public int SCardListReaders(BaseTSD.ULONG_PTR hContext, WString mszGroups, Pointer mszReaders, IntByReference pcchReaders) {
                if (phase.get() == 1) {
                    return SCARD_E_SERVICE_STOPPED;
                }
                char[] multi = "Identiv uTrust 2700 R 0\0\0".toCharArray();
                if (mszReaders == null) {
                    pcchReaders.setValue(multi.length);
                    return SCARD_S_SUCCESS;
                }
                mszReaders.write(0, multi, 0, multi.length);
                pcchReaders.setValue(multi.length);
                return SCARD_S_SUCCESS;
            }

            @Override
            public int SCardGetStatusChange(BaseTSD.ULONG_PTR hContext, int dwTimeout, SCARD_READERSTATE[] rgReaderStates, int cReaders) {
                for (int i = 0; i < cReaders; i++) {
                    rgReaderStates[i].dwEventState = SCARD_STATE_CHANGED | SCARD_STATE_PRESENT;
                    rgReaderStates[i].cbAtr = atr.length;
                    System.arraycopy(atr, 0, rgReaderStates[i].rgbAtr, 0, atr.length);
                }
                return SCARD_S_SUCCESS;
            }

            @Override
            public int SCardCancel(BaseTSD.ULONG_PTR hContext) {
                return SCARD_S_SUCCESS;
            }
        };

        try (WinSCardReaderProbe probe = new WinSCardReaderProbe(fakeApi)) {
            // Phase 0: Initial reader + card detection using context 100
            HardwareProbe.Snapshot s1 = probe.probe();
            assertEquals(1, s1.readers().size());
            assertEquals("Identiv uTrust 2700 R 0", s1.readers().getFirst().name());
            assertTrue(s1.readers().getFirst().cardPresent());
            assertArrayEquals(atr, s1.readers().getFirst().atrBytes());
            assertEquals(List.of(100L), establishedHandles);
            assertTrue(releasedHandles.isEmpty());

            // Phase 1: Windows stops SCardSvr -> releases handle 100 immediately & returns empty snapshot
            phase.set(1);
            HardwareProbe.Snapshot s2 = probe.probe();
            assertTrue(s2.readers().isEmpty());
            assertEquals(List.of(100L), releasedHandles);

            // Phase 2: SCardSvr restarts after reader re-plug -> establishes fresh handle 200
            phase.set(2);
            HardwareProbe.Snapshot s3 = probe.probe();
            assertEquals(1, s3.readers().size());
            assertTrue(s3.readers().getFirst().cardPresent());
            assertEquals(List.of(100L, 200L), establishedHandles);
        }

        // close() cleanly releases active handle 200
        assertEquals(List.of(100L, 200L), releasedHandles);
    }

    @Test
    void testWaitForChangeReleasesContextOnServiceStoppedDuringWait() throws Exception {
        byte[] atr = HexFormat.of().parseHex("3B7F96000080318065B085040120120FFF829000");
        AtomicLong nextContextHandle = new AtomicLong(300L);
        AtomicInteger waitCalls = new AtomicInteger(0);
        List<Long> releasedHandles = new ArrayList<>();

        WinSCardApi fakeApi = new WinSCardApi() {
            @Override
            public int SCardEstablishContext(int dwScope, Pointer pvReserved1, Pointer pvReserved2, BaseTSD.ULONG_PTRByReference phContext) {
                phContext.setValue(new BaseTSD.ULONG_PTR(nextContextHandle.getAndAdd(100L)));
                return SCARD_S_SUCCESS;
            }

            @Override
            public int SCardReleaseContext(BaseTSD.ULONG_PTR hContext) {
                releasedHandles.add(hContext.longValue());
                return SCARD_S_SUCCESS;
            }

            @Override
            public int SCardListReaders(BaseTSD.ULONG_PTR hContext, WString mszGroups, Pointer mszReaders, IntByReference pcchReaders) {
                if (hContext.longValue() == 300L && waitCalls.get() > 0) {
                    return SCARD_E_NO_SERVICE;
                }
                char[] multi = "Reader X 0\0\0".toCharArray();
                if (mszReaders == null) {
                    pcchReaders.setValue(multi.length);
                    return SCARD_S_SUCCESS;
                }
                mszReaders.write(0, multi, 0, multi.length);
                pcchReaders.setValue(multi.length);
                return SCARD_S_SUCCESS;
            }

            @Override
            public int SCardGetStatusChange(BaseTSD.ULONG_PTR hContext, int dwTimeout, SCARD_READERSTATE[] rgReaderStates, int cReaders) {
                if (dwTimeout == 0) {
                    for (int i = 0; i < cReaders; i++) {
                        rgReaderStates[i].dwEventState = SCARD_STATE_CHANGED | SCARD_STATE_PRESENT;
                        rgReaderStates[i].cbAtr = atr.length;
                        System.arraycopy(atr, 0, rgReaderStates[i].rgbAtr, 0, atr.length);
                    }
                    return SCARD_S_SUCCESS;
                }
                waitCalls.incrementAndGet();
                return SCARD_E_NO_SERVICE;
            }

            @Override
            public int SCardCancel(BaseTSD.ULONG_PTR hContext) {
                return SCARD_S_SUCCESS;
            }
        };

        try (WinSCardReaderProbe probe = new WinSCardReaderProbe(fakeApi)) {
            assertEquals(1, probe.probe().readers().size());
            probe.waitForChange(350);
            assertEquals(List.of(300L), releasedHandles, "Invalid handle must be released immediately on SCARD_E_NO_SERVICE");
            // Next probe transparently establishes handle 400
            assertEquals(1, probe.probe().readers().size());
        }
        assertEquals(List.of(300L, 400L), releasedHandles);
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void testNativeWinscardDllLoadsAndProbesWithoutJnaAlignmentErrorsOnWindows() throws Exception {
        WinSCardApi api = WinSCardApi.load();
        assertNotNull(api);

        WinSCardApi.SCARD_READERSTATE struct = new WinSCardApi.SCARD_READERSTATE();
        int expectedSize = Native.POINTER_SIZE == 8 ? 64 : 56;
        assertEquals(expectedSize, struct.size(), "SCARD_READERSTATE native struct size must match Windows ABI");

        // Direct native WinSCard call smoke verification (handles both running and stopped SCardSvr cleanly)
        BaseTSD.ULONG_PTRByReference phContext = new BaseTSD.ULONG_PTRByReference();
        int establishRc = api.SCardEstablishContext(WinSCardApi.SCARD_SCOPE_USER, null, null, phContext);
        assertTrue(
                establishRc == WinSCardApi.SCARD_S_SUCCESS
                        || establishRc == WinSCardApi.SCARD_E_NO_SERVICE
                        || establishRc == WinSCardApi.SCARD_E_SERVICE_STOPPED,
                "Unexpected SCardEstablishContext code: " + WinSCardApi.formatError(establishRc)
        );
        if (establishRc == WinSCardApi.SCARD_S_SUCCESS && phContext.getValue() != null) {
            BaseTSD.ULONG_PTR ctx = phContext.getValue();
            try {
                IntByReference pcch = new IntByReference(0);
                int listRc = api.SCardListReaders(ctx, null, null, pcch);
                assertTrue(
                        listRc == WinSCardApi.SCARD_S_SUCCESS
                                || listRc == WinSCardApi.SCARD_E_NO_READERS_AVAILABLE
                                || listRc == WinSCardApi.SCARD_E_NO_SERVICE
                                || listRc == WinSCardApi.SCARD_E_SERVICE_STOPPED,
                        "Unexpected SCardListReaders code: " + WinSCardApi.formatError(listRc)
                );
            } finally {
                api.SCardReleaseContext(ctx);
            }
        }

        try (WinSCardReaderProbe probe = new WinSCardReaderProbe(api)) {
            HardwareProbe.Snapshot snapshot = assertDoesNotThrow(probe::probe);
            assertNotNull(snapshot);
            assertNotNull(snapshot.readers());
            assertDoesNotThrow(() -> probe.waitForChange(60));
        }
    }
}
