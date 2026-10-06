package com.shadownetguardian.detectors;

import com.shadownetguardian.constants.DetectionWeights;
import com.shadownetguardian.model.DetectionResult;
import com.shadownetguardian.model.ParsedUrl;

public class UserInfoDetector implements ThreatDetector {
    private static final int WEIGHT = DetectionWeights.USER_INFO;

    @Override
    public String getName() {
        return "User-Info Detector";
    }

    @Override
    public int getMaxWeight() {
        return WEIGHT;
    }

    @Override
    public DetectionResult analyze(ParsedUrl parsedUrl) {
        if (!parsedUrl.getUserInfo().isEmpty()) {
            return new DetectionResult(getName(), true, WEIGHT,
                    "URL contains user-info before the host, which can make the destination misleading");
        }
        return new DetectionResult(getName(), false, 0, "No user-info component found");
    }
}
