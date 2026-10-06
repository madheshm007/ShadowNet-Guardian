package com.shadownetguardian.constants;

/**
 * Weights used by the ten-detector weighted heuristic engine.
 * The maximum possible contribution is exactly 100 points.
 */
public final class DetectionWeights {
    private DetectionWeights() {
    }

    public static final int HTTPS = 10;
    public static final int KEYWORD = 10;
    public static final int URL_LENGTH = 8;
    public static final int IP_ADDRESS = 15;
    public static final int ENTROPY = 10;
    public static final int OBFUSCATION = 10;
    public static final int SUBDOMAIN = 7;
    public static final int SUSPICIOUS_TLD = 5;
    public static final int DOMAIN_SIMILARITY = 15;
    public static final int USER_INFO = 10;

    public static final int TOTAL = HTTPS + KEYWORD + URL_LENGTH + IP_ADDRESS
            + ENTROPY + OBFUSCATION + SUBDOMAIN + SUSPICIOUS_TLD
            + DOMAIN_SIMILARITY + USER_INFO;
}
