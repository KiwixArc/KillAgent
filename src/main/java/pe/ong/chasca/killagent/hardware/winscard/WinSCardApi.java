package pe.ong.chasca.killagent.hardware.winscard;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.BaseTSD;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;

/**
 * Direct JNA bindings to Windows {@code Winscard.dll} (PC/SC Resource Manager).
 * Bypasses OpenJDK {@code sun.security.smartcardio.PCSCTerminals}'s static {@code contextId}
 * so {@code SCARDCONTEXT} handles can be cleanly released and re-established whenever Windows
 * stops or restarts {@code SCardSvr} on USB reader disconnect/reconnect.
 */
public interface WinSCardApi extends StdCallLibrary {

    int SCARD_SCOPE_USER = 0;
    int SCARD_SCOPE_TERMINAL = 1;
    int SCARD_SCOPE_SYSTEM = 2;

    int SCARD_S_SUCCESS = 0x00000000;
    int SCARD_E_CANCELLED = 0x80100002;
    int SCARD_E_INVALID_HANDLE = 0x80100003;
    int SCARD_E_INVALID_PARAMETER = 0x80100004;
    int SCARD_E_INSUFFICIENT_BUFFER = 0x80100008;
    int SCARD_E_UNKNOWN_READER = 0x80100009;
    int SCARD_E_TIMEOUT = 0x8010000A;
    int SCARD_E_SHARING_VIOLATION = 0x8010000B;
    int SCARD_E_NO_SMARTCARD = 0x8010000C;
    int SCARD_E_SYSTEM_CANCELLED = 0x80100012;
    int SCARD_E_READER_UNAVAILABLE = 0x80100017;
    int SCARD_E_NO_SERVICE = 0x8010001D;
    int SCARD_E_SERVICE_STOPPED = 0x8010001E;
    int SCARD_E_NO_READERS_AVAILABLE = 0x8010002E;
    int SCARD_E_COMM_DATA_LOST = 0x8010002F;
    int SCARD_W_REMOVED_CARD = 0x80100069;

    int SCARD_STATE_UNAWARE = 0x00000000;
    int SCARD_STATE_IGNORE = 0x00000001;
    int SCARD_STATE_CHANGED = 0x00000002;
    int SCARD_STATE_UNKNOWN = 0x00000004;
    int SCARD_STATE_UNAVAILABLE = 0x00000008;
    int SCARD_STATE_EMPTY = 0x00000010;
    int SCARD_STATE_PRESENT = 0x00000020;
    int SCARD_STATE_ATRMATCH = 0x00000040;
    int SCARD_STATE_EXCLUSIVE = 0x00000080;
    int SCARD_STATE_INUSE = 0x00000100;
    int SCARD_STATE_MUTE = 0x00000200;
    int SCARD_STATE_UNPOWERED = 0x00000400;

    int MAX_ATR_LENGTH = 36;
    String PNP_NOTIFICATION_READER = "\\\\?PnP?\\Notification";

    /**
     * Native {@code SCARD_READERSTATEW} structure aligned for both 32-bit and 64-bit Windows.
     */
    @Structure.FieldOrder({"szReader", "pvUserData", "dwCurrentState", "dwEventState", "cbAtr", "rgbAtr"})
    class SCARD_READERSTATE extends Structure {
        public WString szReader;
        public Pointer pvUserData;
        public int dwCurrentState;
        public int dwEventState;
        public int cbAtr;
        public byte[] rgbAtr = new byte[MAX_ATR_LENGTH];

        public SCARD_READERSTATE() {
            super();
        }

        public SCARD_READERSTATE(Pointer p) {
            super(p);
        }
    }

    int SCardEstablishContext(
            int dwScope,
            Pointer pvReserved1,
            Pointer pvReserved2,
            BaseTSD.ULONG_PTRByReference phContext
    );

    int SCardReleaseContext(BaseTSD.ULONG_PTR hContext);

    int SCardListReaders(
            BaseTSD.ULONG_PTR hContext,
            WString mszGroups,
            Pointer mszReaders,
            IntByReference pcchReaders
    );

    int SCardGetStatusChange(
            BaseTSD.ULONG_PTR hContext,
            int dwTimeout,
            SCARD_READERSTATE[] rgReaderStates,
            int cReaders
    );

    int SCardCancel(BaseTSD.ULONG_PTR hContext);

    static WinSCardApi load() {
        return Native.load("Winscard", WinSCardApi.class, W32APIOptions.UNICODE_OPTIONS);
    }

    static String formatError(int code) {
        return switch (code) {
            case SCARD_S_SUCCESS -> "SCARD_S_SUCCESS (0x00000000)";
            case SCARD_E_CANCELLED -> "SCARD_E_CANCELLED (0x80100002)";
            case SCARD_E_INVALID_HANDLE -> "SCARD_E_INVALID_HANDLE (0x80100003)";
            case SCARD_E_INVALID_PARAMETER -> "SCARD_E_INVALID_PARAMETER (0x80100004)";
            case SCARD_E_INSUFFICIENT_BUFFER -> "SCARD_E_INSUFFICIENT_BUFFER (0x80100008)";
            case SCARD_E_UNKNOWN_READER -> "SCARD_E_UNKNOWN_READER (0x80100009)";
            case SCARD_E_TIMEOUT -> "SCARD_E_TIMEOUT (0x8010000A)";
            case SCARD_E_SHARING_VIOLATION -> "SCARD_E_SHARING_VIOLATION (0x8010000B)";
            case SCARD_E_NO_SMARTCARD -> "SCARD_E_NO_SMARTCARD (0x8010000C)";
            case SCARD_E_SYSTEM_CANCELLED -> "SCARD_E_SYSTEM_CANCELLED (0x80100012)";
            case SCARD_E_READER_UNAVAILABLE -> "SCARD_E_READER_UNAVAILABLE (0x80100017)";
            case SCARD_E_NO_SERVICE -> "SCARD_E_NO_SERVICE (0x8010001D)";
            case SCARD_E_SERVICE_STOPPED -> "SCARD_E_SERVICE_STOPPED (0x8010001E)";
            case SCARD_E_NO_READERS_AVAILABLE -> "SCARD_E_NO_READERS_AVAILABLE (0x8010002E)";
            case SCARD_E_COMM_DATA_LOST -> "SCARD_E_COMM_DATA_LOST (0x8010002F)";
            case SCARD_W_REMOVED_CARD -> "SCARD_W_REMOVED_CARD (0x80100069)";
            default -> String.format("0x%08X", code);
        };
    }
}
