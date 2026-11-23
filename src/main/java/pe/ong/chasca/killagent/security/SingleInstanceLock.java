package pe.ong.chasca.killagent.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pe.ong.chasca.killagent.config.AppPaths;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * OS-level file channel lock preventing duplicate KILLAgent daemon instances
 * from colliding on the loopback port or contesting exclusive PC/SC card sessions.
 * Also maintains a companion PID file for easy operational diagnostics and clean process management.
 */
public final class SingleInstanceLock implements AutoCloseable {

    private static final Logger logger = LoggerFactory.getLogger(SingleInstanceLock.class);

    private final Path lockFilePath;
    private final Path pidFilePath;
    private FileChannel channel;
    private FileLock fileLock;

    public SingleInstanceLock() {
        this(resolveDefaultLockPath());
    }

    public SingleInstanceLock(Path lockFilePath) {
        this.lockFilePath = lockFilePath;
        this.pidFilePath = resolvePidFilePath(lockFilePath);
    }

    /**
     * Attempts to acquire an exclusive OS-level process lock.
     *
     * @return true if this process is the sole active instance; false if another instance is already running.
     */
    public boolean tryAcquire() {
        try {
            Path parent = lockFilePath.getParent();
            if (parent != null && !Files.exists(parent)) {
                Files.createDirectories(parent);
            }

            channel = FileChannel.open(
                    lockFilePath,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE
            );

            fileLock = channel.tryLock();
            if (fileLock == null) {
                closeChannelQuietly();
                return false;
            }

            // Write current PID to lock channel and non-locked companion PID file
            long currentPid = ProcessHandle.current().pid();
            String pidInfo = "PID=" + currentPid + System.lineSeparator();
            channel.truncate(0);
            channel.write(ByteBuffer.wrap(pidInfo.getBytes(StandardCharsets.UTF_8)));
            channel.force(true);

            writePidFile(currentPid);
            return true;
        } catch (OverlappingFileLockException e) {
            closeChannelQuietly();
            return false;
        } catch (IOException e) {
            logger.warn("Could not acquire single-instance lock at {}: {}", lockFilePath, e.getMessage());
            closeChannelQuietly();
            return false;
        }
    }

    /**
     * Reads the PID of the currently running KILLAgent instance from the companion PID file.
     */
    public Optional<Long> getActiveInstancePid() {
        if (!Files.exists(pidFilePath)) {
            return Optional.empty();
        }
        try {
            String content = Files.readString(pidFilePath, StandardCharsets.UTF_8).trim();
            if (content.startsWith("PID=")) {
                content = content.substring(4).trim();
            }
            long pid = Long.parseLong(content);
            return Optional.of(pid);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    /**
     * Attempts to terminate any previously running instance associated with this lock file.
     */
    public boolean killActiveInstance(boolean force) {
        Optional<Long> pidOpt = getActiveInstancePid();
        if (pidOpt.isEmpty()) {
            return false;
        }
        long pid = pidOpt.get();
        if (pid == ProcessHandle.current().pid()) {
            return false;
        }

        Optional<ProcessHandle> handleOpt = ProcessHandle.of(pid);
        if (handleOpt.isEmpty() || !handleOpt.get().isAlive()) {
            deletePidFileQuietly();
            return false;
        }

        ProcessHandle handle = handleOpt.get();
        logger.info("Attempting to terminate existing KILLAgent instance (PID: {})...", pid);
        if (force) {
            handle.destroyForcibly();
        } else {
            handle.destroy();
        }

        try {
            boolean exited = handle.onExit().get(3, TimeUnit.SECONDS).isAlive() == false;
            if (exited) {
                logger.info("Previous instance (PID: {}) successfully terminated.", pid);
                deletePidFileQuietly();
                return true;
            }
        } catch (Exception e) {
            logger.warn("Could not gracefully terminate PID {}; attempting force kill...", pid);
            handle.destroyForcibly();
        }
        return false;
    }

    @Override
    public void close() {
        try {
            if (fileLock != null && fileLock.isValid()) {
                fileLock.release();
            }
        } catch (IOException e) {
            logger.debug("Error releasing file lock: {}", e.getMessage());
        } finally {
            fileLock = null;
            closeChannelQuietly();
            deletePidFileQuietly();
        }
    }

    private void writePidFile(long pid) {
        try {
            Files.writeString(
                    pidFilePath,
                    String.valueOf(pid),
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE
            );
        } catch (Exception e) {
            logger.debug("Could not write companion PID file: {}", e.getMessage());
        }
    }

    private void deletePidFileQuietly() {
        try {
            Files.deleteIfExists(pidFilePath);
        } catch (Exception ignored) {
        }
    }

    private void closeChannelQuietly() {
        if (channel != null) {
            try {
                channel.close();
            } catch (IOException ignored) {
            } finally {
                channel = null;
            }
        }
    }

    private static Path resolvePidFilePath(Path lockPath) {
        String filename = lockPath.getFileName().toString();
        int dot = filename.lastIndexOf('.');
        String base = (dot > 0) ? filename.substring(0, dot) : filename;
        return lockPath.resolveSibling(base + ".pid");
    }

    private static Path resolveDefaultLockPath() {
        return AppPaths.lockFile();
    }
}
