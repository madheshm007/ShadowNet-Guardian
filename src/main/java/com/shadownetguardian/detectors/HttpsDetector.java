package com.shadownetguardian.detectors;

import com.shadownetguardian.constants.DetectionWeights;
import com.shadownetguardian.model.DetectionResult;
import com.shadownetguardian.model.ParsedUrl;

public class HttpsDetector implements ThreatDetector {
    private static final int WEIGHT = DetectionWeights.HTTPS;

    @Override
    public String getName() {
        return "HTTPS Detector";
    }

    @Override
    public int getMaxWeight() {
        return WEIGHT;
    }

    @Override
    public DetectionResult analyze(ParsedUrl parsedUrl) {
        if ("http".equalsIgnoreCase(parsedUrl.getScheme())) {
            return new DetectionResult(getName(), true, WEIGHT,
                    "Uses explicitly insecure HTTP scheme");
        }
        if ("https".equalsIgnoreCase(parsedUrl.getScheme())) {
            return new DetectionResult(getName(), false, 0, "Uses HTTPS");
        }
        return new DetectionResult(getName(), false, 0, "Scheme is unavailable because the URL is invalid");
    }
}
