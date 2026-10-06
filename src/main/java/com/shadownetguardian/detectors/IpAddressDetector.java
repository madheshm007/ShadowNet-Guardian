package com.shadownetguardian.detectors;

import com.shadownetguardian.constants.DetectionWeights;
import com.shadownetguardian.model.DetectionResult;
import com.shadownetguardian.model.ParsedUrl;

public class IpAddressDetector implements ThreatDetector {
    private static final int WEIGHT = DetectionWeights.IP_ADDRESS;
    private static final String IPV4_PATTERN = "^(?:\\d{1,3}\\.){3}\\d{1,3}$";
    private static final String IPV6_PATTERN = "^\\[?(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\\]?$";

    @Override
    public String getName() {
        return "IP Address Detector";
    }

    @Override
    public int getMaxWeight() {
        return WEIGHT;
    }

    @Override
    public DetectionResult analyze(ParsedUrl parsedUrl) {
        String host = parsedUrl.getHost();
        if (host == null || host.isEmpty()) {
            return new DetectionResult(getName(), false, 0, "No host available");
        }

        if (isValidIpv4(host) || host.matches(IPV6_PATTERN)) {
            return new DetectionResult(getName(), true, WEIGHT,
                    "Host is a raw IP address");
        }

        return new DetectionResult(getName(), false, 0, "Host is a domain name");
    }

    private boolean isValidIpv4(String host) {
        if (!host.matches(IPV4_PATTERN)) {
            return false;
        }
        String[] octets = host.split("\\.");
        for (String octet : octets) {
            try {
                if (Integer.parseInt(octet) > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }
}
