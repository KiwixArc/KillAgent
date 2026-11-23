package pe.ong.chasca.killagent.hardware;

import org.junit.jupiter.api.Test;
import pe.ong.chasca.killagent.config.AgentConfig;

import javax.smartcardio.CardException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class CardReaderManagerTest {

        private static final byte[] DNIE_3_ATR = HexFormat.of().parseHex("3B7F96000080318065B085040120120FFF829000");
        private static final byte[] DNIE_2_ATR = HexFormat.of().parseHex("3B7E94000080318065B085040120120FFF829000");

        private static AgentConfig createConfig() {
                return new AgentConfig(
                                "production",
                                3000,
                                "127.0.0.1",
                                false,
                                "./keystore/loopback.p12",
                                "changeit",
                                Set.of("http://localhost:5173"),
                                "bit4ipki.dll",
                                "idplug-pkcs11.dll",
                                "auto",
                                false);
        }

        private static HardwareProbe scriptedProbe(AtomicReference<HardwareProbe.Snapshot> ref,
                        AtomicInteger probeCount) {
                return new HardwareProbe() {
                        @Override
                        public Snapshot probe() {
                                probeCount.incrementAndGet();
                                return ref.get();
                        }

                        @Override
                        public void waitForChange(int timeoutMs) {
                        }
                };
        }

        @Test
        void testReaderDisconnectWithCardCleansStateAndEmitsCardRemovedBeforeReaderDisconnected() {
                AtomicReference<HardwareProbe.Snapshot> snapshotRef = new AtomicReference<>(
                                new HardwareProbe.Snapshot(List.of(
                                                new HardwareProbe.ReaderSnapshot("Identiv uTrust 2700 R 0", true,
                                                                DNIE_3_ATR))));
                AtomicInteger probeCount = new AtomicInteger();

                CardReaderManager manager = new CardReaderManager(
                                createConfig(),
                                scriptedProbe(snapshotRef, probeCount));
                List<String> events = new ArrayList<>();
                manager.addListener(recordingListener(events));

                // 1. Reader + card detected
                manager.probeOnce(true);
                HardwareStatus activeStatus = manager.getStatus();
                assertTrue(activeStatus.readerPresent());
                assertTrue(activeStatus.cardPresent());
                assertEquals("Identiv uTrust 2700 R 0", activeStatus.readerName());
                assertEquals(CardType.DNIE_3_0, activeStatus.cardType());
                assertEquals(List.of(
                                "READER_STATUS:true:Identiv uTrust 2700 R 0",
                                "CARD_INSERTED:Identiv uTrust 2700 R 0:DNIE_3_0"), events);

                manager.updateDetectedCardholderIdentity("71234567", "JUAN PEREZ GARCIA");
                assertEquals("71234567", manager.getActiveCardholderDni());
                assertEquals("JUAN PEREZ GARCIA", manager.getActiveCardholderName());

                // 2. Physical USB disconnect (or SCardSvr stopped) -> empty snapshot
                events.clear();
                snapshotRef.set(HardwareProbe.Snapshot.empty());
                manager.probeOnce(true);

                HardwareStatus cleared = manager.getStatus();
                assertFalse(cleared.readerPresent());
                assertFalse(cleared.cardPresent());
                assertNull(cleared.readerName());
                assertEquals(CardType.NONE, cleared.cardType());
                assertEquals("", manager.getLastDetectedAtrHex());
                assertNull(manager.getActiveCardholderDni());
                assertNull(manager.getActiveCardholderName());

                assertEquals(List.of(
                                "CARD_REMOVED:Identiv uTrust 2700 R 0",
                                "READER_STATUS:false:null"), events);
        }

        @Test
        void testReaderReconnectAndCardInsertionEmitsReaderAndCardEvents() {
                AtomicReference<HardwareProbe.Snapshot> snapshotRef = new AtomicReference<>(
                                HardwareProbe.Snapshot.empty());
                AtomicInteger probeCount = new AtomicInteger();

                CardReaderManager manager = new CardReaderManager(
                                createConfig(),
                                scriptedProbe(snapshotRef, probeCount));
                List<String> events = new ArrayList<>();
                manager.addListener(recordingListener(events));

                // 1. Initially disconnected
                manager.probeOnce(true);
                assertTrue(events.isEmpty());
                assertFalse(manager.getStatus().readerPresent());

                // 2. Reader plugged in without card
                snapshotRef.set(new HardwareProbe.Snapshot(List.of(
                                new HardwareProbe.ReaderSnapshot("ACS ACR39U ICC Reader 0", false, new byte[0]))));
                manager.probeOnce(true);
                assertTrue(manager.getStatus().readerPresent());
                assertFalse(manager.getStatus().cardPresent());
                assertEquals("ACS ACR39U ICC Reader 0", manager.getStatus().readerName());
                assertEquals(List.of("READER_STATUS:true:ACS ACR39U ICC Reader 0"), events);

                // 3. DNIe 3.0 inserted into reconnected reader
                events.clear();
                snapshotRef.set(new HardwareProbe.Snapshot(List.of(
                                new HardwareProbe.ReaderSnapshot("ACS ACR39U ICC Reader 0", true, DNIE_3_ATR))));
                manager.probeOnce(true);
                HardwareStatus cardReady = manager.getStatus();
                assertTrue(cardReady.readerPresent());
                assertTrue(cardReady.cardPresent());
                assertEquals(CardType.DNIE_3_0, cardReady.cardType());
                assertEquals(List.of("CARD_INSERTED:ACS ACR39U ICC Reader 0:DNIE_3_0"), events);

                // 4. Subsequent unplug -> reconnect with card already inserted
                events.clear();
                snapshotRef.set(HardwareProbe.Snapshot.empty());
                manager.probeOnce(true);
                assertEquals(List.of(
                                "CARD_REMOVED:ACS ACR39U ICC Reader 0",
                                "READER_STATUS:false:null"), events);

                events.clear();
                snapshotRef.set(new HardwareProbe.Snapshot(List.of(
                                new HardwareProbe.ReaderSnapshot("ACS ACR39U ICC Reader 0", true, DNIE_3_ATR))));
                manager.probeOnce(true);
                assertEquals(List.of(
                                "READER_STATUS:true:ACS ACR39U ICC Reader 0",
                                "CARD_INSERTED:ACS ACR39U ICC Reader 0:DNIE_3_0"), events);
        }

        @Test
        void testPcscCauseChainFaultDetection() {
                CardException noReadersEx = new CardException(
                                "list() failed",
                                new RuntimeException(
                                                "sun.security.smartcardio.PCSCException: SCARD_E_NO_READERS_AVAILABLE"));
                assertEquals(
                                JavaSmartCardIoProbe.PcscFaultType.NO_READERS,
                                JavaSmartCardIoProbe.classifyPcscFault(noReadersEx));

                CardException serviceStoppedEx = new CardException(
                                "waitForChange() failed",
                                new IllegalStateException("wrapper", new RuntimeException("SCARD_E_SERVICE_STOPPED")));
                assertEquals(
                                JavaSmartCardIoProbe.PcscFaultType.SERVICE_OR_HANDLE_INVALID,
                                JavaSmartCardIoProbe.classifyPcscFault(serviceStoppedEx));

                assertEquals(
                                JavaSmartCardIoProbe.PcscFaultType.SERVICE_OR_HANDLE_INVALID,
                                JavaSmartCardIoProbe.classifyPcscFault(
                                                new CardException("err", new RuntimeException("SCARD_E_NO_SERVICE"))));
                assertEquals(
                                JavaSmartCardIoProbe.PcscFaultType.SERVICE_OR_HANDLE_INVALID,
                                JavaSmartCardIoProbe.classifyPcscFault(new CardException("err",
                                                new RuntimeException("SCARD_E_INVALID_HANDLE"))));
                assertEquals(
                                JavaSmartCardIoProbe.PcscFaultType.READER_UNAVAILABLE,
                                JavaSmartCardIoProbe.classifyPcscFault(new CardException("err",
                                                new RuntimeException("SCARD_E_READER_UNAVAILABLE"))));
                assertEquals(
                                JavaSmartCardIoProbe.PcscFaultType.NONE,
                                JavaSmartCardIoProbe.classifyPcscFault(new CardException("generic error")));
        }

        @Test
        void testSwitchingActiveReaderWithCardEmitsKillSwitchBeforeNewReaderReady() {
                AtomicReference<HardwareProbe.Snapshot> snapshotRef = new AtomicReference<>(
                                new HardwareProbe.Snapshot(List.of(
                                                new HardwareProbe.ReaderSnapshot("Reader A 0", true, DNIE_3_ATR))));
                AtomicInteger probeCount = new AtomicInteger();

                CardReaderManager manager = new CardReaderManager(
                                createConfig(),
                                scriptedProbe(snapshotRef, probeCount));
                List<String> events = new ArrayList<>();
                manager.addListener(recordingListener(events));

                manager.probeOnce(true);
                events.clear();

                // Physical switch from Reader A (with card) to empty Reader B
                snapshotRef.set(new HardwareProbe.Snapshot(List.of(
                                new HardwareProbe.ReaderSnapshot("Reader B 0", false, new byte[0]))));
                manager.probeOnce(true);

                HardwareStatus status = manager.getStatus();
                assertTrue(status.readerPresent());
                assertFalse(status.cardPresent());
                assertFalse(status.isMock());
                assertEquals("Reader B 0", status.readerName());
                assertEquals(CardType.NONE, status.cardType());
                assertEquals(List.of(
                                "CARD_REMOVED:Reader A 0",
                                "READER_STATUS:true:Reader B 0"), events);
        }

        @Test
        void testInitiallyEmptyProbeStartsCleanWithoutMockFallback() {
                AtomicReference<HardwareProbe.Snapshot> snapshotRef = new AtomicReference<>(
                                HardwareProbe.Snapshot.empty());
                AtomicInteger probeCount = new AtomicInteger();

                CardReaderManager manager = new CardReaderManager(
                                createConfig(),
                                scriptedProbe(snapshotRef, probeCount));
                manager.probeOnce(false);

                HardwareStatus status = manager.getStatus();
                assertFalse(status.readerPresent());
                assertFalse(status.cardPresent());
                assertFalse(status.isMock());
                assertNull(status.readerName());
                assertEquals(CardType.NONE, status.cardType());
        }

        @Test
        void testProbeExceptionClearsCachedReaderStateInsteadOfLeavingStaleCache() {
                AtomicInteger calls = new AtomicInteger();
                HardwareProbe flakyProbe = new HardwareProbe() {
                        @Override
                        public Snapshot probe() {
                                if (calls.incrementAndGet() == 1) {
                                        return new Snapshot(
                                                        List.of(new ReaderSnapshot("USB Reader 0", true, DNIE_3_ATR)));
                                }
                                throw new IllegalStateException("SCARD_E_SERVICE_STOPPED");
                        }

                        @Override
                        public void waitForChange(int timeoutMs) {
                        }
                };

                CardReaderManager manager = new CardReaderManager(createConfig(), flakyProbe);
                List<String> events = new ArrayList<>();
                manager.addListener(recordingListener(events));

                manager.probeOnce(true);
                assertTrue(manager.getStatus().readerPresent());
                assertTrue(manager.getStatus().cardPresent());

                events.clear();
                manager.probeOnce(true);
                assertFalse(manager.getStatus().readerPresent());
                assertFalse(manager.getStatus().cardPresent());
                assertNull(manager.getStatus().readerName());
                assertEquals(List.of(
                                "CARD_REMOVED:USB Reader 0",
                                "READER_STATUS:false:null"), events);
        }

        @Test
        void testAtrClassificationDnie2AndDnie3() {
                CardReaderManager manager = new CardReaderManager(
                                createConfig(),
                                scriptedProbe(new AtomicReference<>(HardwareProbe.Snapshot.empty()),
                                                new AtomicInteger()));

                assertEquals(CardType.DNIE_3_0, manager.classifyAtrHex(DNIE_3_ATR));
                assertEquals(CardType.DNIE_2_0, manager.classifyAtrHex(DNIE_2_ATR));
                assertEquals(CardType.DNIE_3_0, manager.classifyAtrHex(new byte[0]));
                assertEquals("UNAVAILABLE", manager.getLastDetectedAtrHex());
        }

        private static HardwareListener recordingListener(List<String> events) {
                return new HardwareListener() {
                        @Override
                        public void onCardInserted(String readerName, CardType cardType) {
                                events.add("CARD_INSERTED:" + readerName + ":" + cardType);
                        }

                        @Override
                        public void onCardRemoved(String readerName) {
                                events.add("CARD_REMOVED:" + readerName);
                        }

                        @Override
                        public void onReaderStatusChanged(boolean readerPresent, String readerName) {
                                events.add("READER_STATUS:" + readerPresent + ":" + readerName);
                        }
                };
        }
}
