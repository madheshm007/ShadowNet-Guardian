package com.shadownetguardian.detectors;

import com.shadownetguardian.constants.DetectionWeights;
import com.shadownetguardian.model.DetectionResult;
import com.shadownetguardian.model.ParsedUrl;

public class UrlLengthDetector implements ThreatDetector {
    private static final int WEIGHT = DetectionWeights.URL_LENGTH;
    private static final int THRESHOLD = 100;

    @Override
    public String getName() {
        return "URL Length Detector";
    }

    @Override
    public int getMaxWeight() {
        return WEIGHT;
    }

    @Override
    public DetectionResult analyze(ParsedUrl parsedUrl) {
        int length = parsedUrl.getOriginalUrl().length();
        if (length > THRESHOLD) {
            return new DetectionResult(getName(), true, WEIGHT,
                    "URL length is " + length + " characters, above the " + THRESHOLD + "-character threshold");
        }
        return new DetectionResult(getName(), false, 0,
                "URL length is " + length + " characters");
    }
}
