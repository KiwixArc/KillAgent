package pe.ong.chasca.killagent.ui;

import com.formdev.flatlaf.extras.FlatSVGIcon;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.InputStream;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Central asset manager that loads vector (.svg) and raster (.png) UI assets
 * from classpath resources (/assets/icons/ and /assets/images/) with high-DPI scaling
 * and procedural fallbacks.
 */
public final class AssetManager {

    private static final Logger logger = LoggerFactory.getLogger(AssetManager.class);
    private static final Map<String, Image> cache = new ConcurrentHashMap<>();

    private AssetManager() {}

    /**
     * Resolves a System Tray icon corresponding to the specified state.
     * Priority:
     * 1. Vector SVG in /assets/icons/tray-*.svg
     * 2. Raster PNG in /assets/icons/tray-*.png
     * 3. Procedural Killa/Ch'asca rendering via TrayIconFactory
     */
    public static Image getTrayIcon(TrayIconFactory.TrayState state) {
        String baseName = switch (state) {
            case NO_READER -> "tray-no-reader";
            case NO_CARD -> "tray-no-card";
            case CARD_READY -> "tray-card-ready";
            case BUSY_SIGNING -> "tray-busy";
            case MOCK_SANDBOX -> "tray-sandbox";
        };

        // 1. Try native SVG vector asset first
        Image svgImg = loadSvgImage("/assets/icons/" + baseName + ".svg", 32, 32);
        if (svgImg != null) {
            return svgImg;
        }

        // 2. Try PNG raster asset
        Image pngImg = loadCachedImage("/assets/icons/" + baseName + ".png", 32, 32);
        if (pngImg != null) {
            return pngImg;
        }

        // 3. Fallback to procedural Killa/Ch'asca icon
        return TrayIconFactory.createIcon(state);
    }

    /**
     * Returns the application branding icon (app-icon.svg or app-icon.png).
     */
    public static Image getAppIcon() {
        Image svg = loadSvgImage("/assets/icons/app-icon.svg", 64, 64);
        if (svg != null) {
            return svg;
        }
        Image png = loadCachedImage("/assets/icons/app-icon.png", 64, 64);
        if (png != null) {
            return png;
        }
        return TrayIconFactory.createIcon(TrayIconFactory.TrayState.CARD_READY);
    }

    /**
     * Returns the branding logo scaled comfortably for dialog headers.
     */
    public static ImageIcon getBrandLogo() {
        Image svg = loadSvgImage("/assets/images/brand-logo.svg", 160, 40);
        if (svg != null) {
            return new ImageIcon(svg);
        }

        Image img = loadCachedImage("/assets/images/brand-logo.png", -1, -1);
        if (img != null) {
            int targetWidth = 160;
            int w = img.getWidth(null);
            int h = img.getHeight(null);
            int targetHeight = (w > 0 && h > 0) ? (h * targetWidth) / w : 40;
            Image scaled = img.getScaledInstance(targetWidth, targetHeight, Image.SCALE_SMOOTH);
            return new ImageIcon(scaled);
        }
        return null;
    }

    /**
     * Returns the Ch'asca Zero Trust shield badge for security modals.
     */
    public static ImageIcon getShieldBadge(int size) {
        Image svg = loadSvgImage("/assets/images/shield-badge.svg", size, size);
        if (svg != null) {
            return new ImageIcon(svg);
        }
        Image png = loadCachedImage("/assets/images/shield-badge.png", size, size);
        return png != null ? new ImageIcon(png) : null;
    }

    /**
     * Renders a vector .svg resource from classpath into a high-DPI Image.
     */
    public static Image loadSvgImage(String resourcePath, int width, int height) {
        String cacheKey = "SVG_" + resourcePath + "_" + width + "x" + height;
        return cache.computeIfAbsent(cacheKey, key -> {
            try (InputStream is = AssetManager.class.getResourceAsStream(resourcePath)) {
                if (is != null) {
                    FlatSVGIcon icon = new FlatSVGIcon(is);
                    if (width > 0 && height > 0) {
                        icon = icon.derive(width, height);
                    }
                    BufferedImage buffered = new BufferedImage(
                            icon.getIconWidth(),
                            icon.getIconHeight(),
                            BufferedImage.TYPE_INT_ARGB
                    );
                    Graphics2D g2 = buffered.createGraphics();
                    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                    icon.paintIcon(null, g2, 0, 0);
                    g2.dispose();
                    logger.debug("Rendered SVG vector asset: {} ({}x{})", resourcePath, width, height);
                    return buffered;
                }
            } catch (Exception e) {
                logger.debug("Could not render SVG asset {}: {}", resourcePath, e.getMessage());
            }
            return null;
        });
    }

    /**
     * Loads a raster image (.png) from classpath with optional scaling and caching.
     */
    public static Image loadCachedImage(String resourcePath, int targetWidth, int targetHeight) {
        String cacheKey = "RASTER_" + resourcePath + "_" + targetWidth + "x" + targetHeight;
        return cache.computeIfAbsent(cacheKey, key -> {
            try (InputStream is = AssetManager.class.getResourceAsStream(resourcePath)) {
                if (is != null) {
                    BufferedImage img = ImageIO.read(is);
                    if (img != null) {
                        logger.debug("Loaded raster asset from: {}", resourcePath);
                        if (targetWidth > 0 && targetHeight > 0 && (img.getWidth() != targetWidth || img.getHeight() != targetHeight)) {
                            return img.getScaledInstance(targetWidth, targetHeight, Image.SCALE_SMOOTH);
                        }
                        return img;
                    }
                }
            } catch (Exception e) {
                logger.debug("Raster asset {} not found or failed to load: {}", resourcePath, e.getMessage());
            }
            return null;
        });
    }
}
