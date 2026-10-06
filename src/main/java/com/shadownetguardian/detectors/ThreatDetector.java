package com.shadownetguardian.detectors;

import com.shadownetguardian.model.ParsedUrl;
import com.shadownetguardian.model.DetectionResult;

public interface ThreatDetector {
    String getName();
    int getMaxWeight();
    DetectionResult analyze(ParsedUrl parsedUrl);
}
