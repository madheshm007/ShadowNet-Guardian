package com.shadownetguardian.detectors;

import com.shadownetguardian.constants.DetectionWeights;
import com.shadownetguardian.model.DetectionResult;
import com.shadownetguardian.model.ParsedUrl;

import java.util.regex.Pattern;

/**
 * Detects common URL obfuscation signals without making any network request.
 */
public class ObfuscationDetector implements ThreatDetector {
    private static final int WEIGHT = DetectionWeights.OBFUSCATION;
    private static final Pattern PERCENT_ENCODING = Pattern.compile("%[0-9a-fA-F]{2}");
    private static final Pattern HEX_ESCAPE = Pattern.compile("(?:0x[0-9a-fA-F]+|\\\\x[0-9a-fA-F]{2})");
    private static final Pattern REPEATED_PATH_SEPARATOR = Pattern.compile("(?:/{2,}|\\\\{2,}|\\.{3,}|-{3,})");

    @Override
    public String getName() {
        return "Obfuscation Detector";
    }

    @Override
    public int getMaxWeight() {
        return WEIGHT;
    }

    @Override
    public DetectionResult analyze(ParsedUrl parsedUrl) {
        String originalUrl = parsedUrl.getOriginalUrl();
        String pathAndQuery = parsedUrl.getPath()
                + (parsedUrl.getQuery().isEmpty() ? "" : "?" + parsedUrl.getQuery());

        int signals = 0;
        StringBuilder reason = new StringBuilder();

        if (PERCENT_ENCODING.matcher(originalUrl).find()) {
            signals++;
            reason.append("percent-encoded characters; ");
        }
        if (HEX_ESCAPE.matcher(originalUrl).find()) {
            signals++;
            reason.append("hex escape pattern; ");
        }
        // Check only the path/query so the normal https:// scheme is not
        // incorrectly treated as an obfuscation signal.
        if (REPEATED_PATH_SEPARATOR.matcher(pathAndQuery).find()) {
            signals++;
            reason.append("repeated separators in path/query; ");
        }

        int score = Math.min(WEIGHT, signals * 5);
        if (score > 0) {
            return new DetectionResult(getName(), true, score,
                    "Possible URL obfuscation: " + reason.toString().replaceAll("; $", ""));
        }
        return new DetectionResult(getName(), false, 0, "No configured obfuscation pattern detected");
    }
}
