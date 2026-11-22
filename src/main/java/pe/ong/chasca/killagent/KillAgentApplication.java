package pe.ong.chasca.killagent;

import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.WinReg;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pe.ong.chasca.killagent.config.AgentConfig;
import pe.ong.chasca.killagent.config.ConfigurationLoader;
import pe.ong.chasca.killagent.crypto.CryptoService;
import pe.ong.chasca.killagent.hardware.CardReaderManager;
import pe.ong.chasca.killagent.hardware.mock.MockHardwareService;
import pe.ong.chasca.killagent.hardware.pkcs11.Pkcs11Bridge;
import pe.ong.chasca.killagent.security.SingleInstanceLock;
import pe.ong.chasca.killagent.server.KillAgentWebSocketServer;
import pe.ong.chasca.killagent.ui.PinPromptProvider;
import pe.ong.chasca.killagent.ui.SwingPinPromptProvider;
import pe.ong.chasca.killagent.ui.SystemTrayManager;

import javax.swing.*;
import java.awt.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * KILLAgent entrypoint and lifecycle coordinator.
 * Lightweight, zero-footprint desktop background daemon (< 45 MB idle RAM, < 500 ms startup)
 * serving as the Zero Trust physical hardware anchor for the Ch'asca platform on Windows.
 */
public class KillAgentApplication {

    private static final Logger logger = LoggerFactory.getLogger(KillAgentApplication.class);
    private static final String WIN_PERSONALIZE_REG_KEY =
            "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize";
    private static final String WIN_LIGHT_THEME_VALUE = "AppsUseLightTheme";

    private static final AtomicBoolean shuttingDown = new AtomicBoolean(false);

    private static SingleInstanceLock instanceLock;
    private static AgentConfig activeConfig;
    private static CardReaderManager cardReaderManager;
    private static Pkcs11Bridge pkcs11Bridge;
    private static MockHardwareService mockHardwareService;
    private static CryptoService cryptoService;
    private static PinPromptProvider pinPromptProvider;
    private static SystemTrayManager trayManager;
    private static volatile KillAgentWebSocketServer server;

    public static void main(String[] args) {
        long startNanos = System.nanoTime();
        System.setProperty("sun.java2d.dpiaware", "true");

        boolean forceStart = hasArg(args, "--force", "-f");
        boolean stopOnly = hasArg(args, "--stop", "--kill", "-k");

        instanceLock = new SingleInstanceLock();

        // Handle --stop / --kill command
        if (stopOnly) {
            handleStopCommand();
            return;
        }

        // Handle --force: terminate existing instance before starting
        if (forceStart) {
            handleForceTermination();
        }

        // 1. Acquire OS single-instance lock
        if (!instanceLock.tryAcquire()) {
            handleDuplicateInstanceDetected();
            return;
        }

        logger.info("Starting KILLAgent Zero Trust Desktop Daemon (PID: {})...", ProcessHandle.current().pid());

        try {
            // 2. Load hierarchical configuration (System Env -> .env -> config.properties)
            activeConfig = ConfigurationLoader.load();

            // 3. Configure FlatLaf Windows 11 Look & Feel (light, dark, or auto Windows Registry sync)
            setupTheme(activeConfig.uiTheme());

            // 4. Initialize Hardware, PKCS#11, Sandbox (dev-only), and Crypto services
            cardReaderManager = new CardReaderManager(activeConfig);
            pkcs11Bridge = new Pkcs11Bridge(activeConfig);
            mockHardwareService = activeConfig.isDevelopment() ? new MockHardwareService(activeConfig) : null;
            cryptoService = new CryptoService(activeConfig, cardReaderManager, pkcs11Bridge, mockHardwareService);
            pinPromptProvider = new SwingPinPromptProvider();

            // 5. Initialize Windows System Tray
            trayManager = new SystemTrayManager(
                    activeConfig,
                    cardReaderManager,
                    pkcs11Bridge,
                    mockHardwareService,
                    cryptoService,
                    pinPromptProvider,
                    KillAgentApplication::restartServer,
                    KillAgentApplication::exitApplication
            );
            trayManager.setActiveConnectionsSupplier(() -> server != null ? server.getActiveConnectionCount() : 0);
            SwingUtilities.invokeLater(trayManager::initialize);

            // 6. Start Loopback WebSocket / WSS Server
            startServer();

            // 7. Start PC/SC WinSCard hardware monitoring thread
            cardReaderManager.start();

            // 8. Register idempotent JVM shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(KillAgentApplication::shutdown, "killagent-shutdown-hook"));

            // 9. Start interactive console listener (allows typing 'q' or 'stop' in terminal to exit cleanly)
            startConsoleInputListener();

            long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000L;
            logger.info("KILLAgent daemon operational in {} ms (Target SLA: < 500 ms).", elapsedMs);
            System.out.println("[KILLAgent] En ejecución en la bandeja del sistema (System Tray).");
            System.out.println("[KILLAgent] Para detener: presione Ctrl+C, escriba 'q' y Enter, o clic derecho en el icono -> Salir.");
        } catch (Throwable fatal) {
            logger.error("Fatal error during KILLAgent startup: {}", fatal.getMessage(), fatal);
            shutdown();
            System.exit(1);
        }
    }

    private static boolean hasArg(String[] args, String... flags) {
        if (args == null) return false;
        for (String a : args) {
            for (String f : flags) {
                if (f.equalsIgnoreCase(a)) return true;
            }
        }
        return false;
    }

    private static void handleStopCommand() {
        Optional<Long> pidOpt = instanceLock.getActiveInstancePid();
        if (pidOpt.isPresent()) {
            long pid = pidOpt.get();
            System.out.println("[KILLAgent] Deteniendo instancia activa (PID: " + pid + ")...");
            boolean killed = instanceLock.killActiveInstance(true);
            if (killed) {
                System.out.println("[KILLAgent] Instancia detenida exitosamente.");
            } else {
                System.out.println("[KILLAgent] No se pudo detener el proceso o ya no estaba en ejecución.");
            }
        } else {
            System.out.println("[KILLAgent] No se detectó ninguna instancia previa activa en esta estación.");
        }
    }

    private static void handleForceTermination() {
        Optional<Long> pidOpt = instanceLock.getActiveInstancePid();
        if (pidOpt.isPresent()) {
            long pid = pidOpt.get();
            logger.info("Flag --force detectado. Finalizando instancia previa (PID: {})...", pid);
            instanceLock.killActiveInstance(true);
            try {
                Thread.sleep(500); // Allow OS to release port and file handles
            } catch (InterruptedException ignored) {
            }
        }
    }

    private static void handleDuplicateInstanceDetected() {
        Optional<Long> pidOpt = instanceLock.getActiveInstancePid();
        String pidStr = pidOpt.map(String::valueOf).orElse("desconocido");

        logger.warn("Another instance of KILLAgent is already running on this workstation (PID: {}). Exiting.", pidStr);
        System.err.println("\n[AVISO] Ya existe una instancia de KILLAgent ejecutándose en segundo plano (PID: " + pidStr + ").");
        System.err.println("Opciones para gestionarla:");
        System.err.println("  1. Haz clic derecho en el icono de KILLAgent en la barra de tareas (junto al reloj) y selecciona 'Salir'.");
        System.err.println("  2. Para reiniciar forzosamente: java -jar target\\killagent-1.0.0-SNAPSHOT.jar --force");
        System.err.println("  3. Para detener la instancia actual: java -jar target\\killagent-1.0.0-SNAPSHOT.jar --stop");
        System.err.println("  4. O desde PowerShell: Stop-Process -Id " + pidStr + " -Force\n");

        if (!GraphicsEnvironment.isHeadless()) {
            Toolkit.getDefaultToolkit().beep();
        }
    }

    private static void startConsoleInputListener() {
        Thread consoleThread = new Thread(() -> {
            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                String line;
                while (!shuttingDown.get() && (line = reader.readLine()) != null) {
                    line = line.trim().toLowerCase();
                    if ("q".equals(line) || "quit".equals(line) || "exit".equals(line) || "stop".equals(line)) {
                        logger.info("Comando de parada recibido desde consola. Cerrando daemon...");
                        exitApplication();
                        break;
                    }
                }
            } catch (Exception ignored) {
            }
        }, "killagent-console-listener");
        consoleThread.setDaemon(true);
        consoleThread.start();
    }

    private static synchronized void startServer() {
        try {
            server = new KillAgentWebSocketServer(
                    activeConfig,
                    cardReaderManager,
                    cryptoService,
                    trayManager,
                    pinPromptProvider
            );
            server.start();
        } catch (Exception e) {
            logger.error("Failed to bind WebSocket loopback server: {}", e.getMessage(), e);
        }
    }

    private static synchronized void restartServer() {
        logger.info("Restarting KILLAgent WebSocket loopback server...");
        if (server != null) {
            server.shutdownCleanly(1000);
            server = null;
        }
        startServer();
        if (trayManager != null) {
            trayManager.updateStatusDisplay();
        }
    }

    private static void exitApplication() {
        shutdown();
        System.exit(0);
    }

    public static void shutdown() {
        if (!shuttingDown.compareAndSet(false, true)) {
            return;
        }
        logger.info("Executing clean KILLAgent daemon shutdown sequence...");

        if (pinPromptProvider != null) {
            pinPromptProvider.abortActivePromptForCardRemoval();
        }
        if (cardReaderManager != null) {
            cardReaderManager.stop();
        }
        if (server != null) {
            server.shutdownCleanly(1000);
            server = null;
        }
        if (pkcs11Bridge != null) {
            pkcs11Bridge.cleanup();
        }
        if (trayManager != null) {
            trayManager.shutdown();
        }
        if (instanceLock != null) {
            instanceLock.close();
        }

        logger.info("KILLAgent daemon terminated cleanly.");
    }

    private static void setupTheme(String themePreference) {
        try {
            boolean useLight;
            if ("light".equalsIgnoreCase(themePreference)) {
                useLight = true;
            } else if ("dark".equalsIgnoreCase(themePreference)) {
                useLight = false;
            } else {
                // 'auto': Sync dynamically with Windows 10/11 OS theme preference
                useLight = isWindowsLightThemeEnabled();
            }

            if (useLight) {
                FlatLightLaf.setup();
            } else {
                FlatDarkLaf.setup();
            }
            logger.debug("UI theme initialized (mode={}).", useLight ? "Light" : "Dark");
        } catch (Exception e) {
            logger.warn("Could not initialize FlatLaf theme: {}", e.getMessage());
        }
    }

    private static boolean isWindowsLightThemeEnabled() {
        try {
            String os = System.getProperty("os.name", "").toLowerCase();
            if (os.contains("win") && Advapi32Util.registryValueExists(
                    WinReg.HKEY_CURRENT_USER,
                    WIN_PERSONALIZE_REG_KEY,
                    WIN_LIGHT_THEME_VALUE
            )) {
                int val = Advapi32Util.registryGetIntValue(
                        WinReg.HKEY_CURRENT_USER,
                        WIN_PERSONALIZE_REG_KEY,
                        WIN_LIGHT_THEME_VALUE
                );
                return val != 0;
            }
        } catch (Throwable t) {
            logger.debug("Could not read Windows theme registry preference; defaulting to Dark theme.");
        }
        return false;
    }
}
