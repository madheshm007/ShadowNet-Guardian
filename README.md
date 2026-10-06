# ShadowNet Guardian – Phishing URL Detection System

## Title & Problem Statement
**ShadowNet Guardian** is a terminal-based Java application designed to analyze URLs and determine their likelihood of being a phishing attempt. Phishing attacks frequently rely on obfuscated URLs, misleading subdomains, typosquatting, and unencrypted connections. Relying on simple lists of known bad URLs is insufficient; a heuristic approach is needed to evaluate zero-day phishing links based on their structural characteristics.

## Objectives
- Provide a robust, offline, static analysis tool for URL risk assessment.
- Demonstrate modern Java 21 Object-Oriented Programming (OOP) principles.
- Use a Weighted Heuristic Engine rather than brittle if/else chains.
- Store historical analysis data using MySQL and JDBC.
- Generate professional PDF reports of scan results.

## Features
- **Heuristic Engine:** Uses 10 independent detectors to evaluate URLs.
- **Weighted Scoring:** Different threats contribute different weights to a final capped score (0-100).
- **Clear Classifications:** SAFE (0-30), SUSPICIOUS (31-60), PHISHING (61-100).
- **Persistent Storage:** MySQL database integration for scan history.
- **Reporting:** Automated PDF generation via iText.

## Architecture
```
User -> CLI -> ThreatAnalysisEngine -> List<ThreatDetector> -> Aggregation -> Result
Result -> MySQL (JDBC)
Result -> PDF (iText)
```

## Detection Methodology
The system uses the following independent detectors:
1. **HttpsDetector:** Flags missing HTTPS encryption.
2. **KeywordDetector:** Looks for sensitive terms (e.g., login, bank).
3. **UrlLengthDetector:** Penalizes excessively long URLs hiding payloads.
4. **IpAddressDetector:** Flags raw IPs used as hosts.
5. **EntropyDetector:** Calculates Shannon entropy to find high randomness (DGA).
6. **SpecialCharacterDetector:** Checks for excessive `@`, `-`, or `%` usage.
7. **SubdomainDetector:** Flags excessive subdomain depth or brand misuse.
8. **SuspiciousTldDetector:** Checks against a list of frequently abused TLDs.
9. **DomainSimilarityDetector:** Uses Levenshtein distance for typosquatting detection.
10. **ObfuscationDetector:** Flags heavy percent-encoding or base64-like strings.

## OOP Concepts Demonstrated
- **Interface & Polymorphism:** `ThreatDetector` interface implemented by all 10 detectors.
- **Encapsulation:** Model classes (`ScanResult`, `DetectionResult`) use private fields and getters.
- **Composition:** `ThreatAnalysisEngine` composes a list of `ThreatDetector` instances.
- **Open/Closed Principle:** New detectors can be added by implementing the interface and registering them in the engine, without modifying existing detector logic.
- **Single Responsibility Principle:** Separated CLI (`Main`, `ConsoleFormatter`), Database (`ScanHistoryRepository`), and PDF (`PdfReportGenerator`) layers.

## Database Setup
1. Ensure MySQL is running locally on port 3306.
2. Create the database: `CREATE DATABASE shadow_net_guardian;`
3. Update `application.properties` (or use ENV vars) with your DB credentials if they differ from root/password.

## Dependencies
- Java 21
- Maven
- MySQL Connector/J
- iText 7 Core (PDF)
- JUnit 5

## How to Run
1. `mvn clean package`
2. `java -jar target/shadownet-guardian-1.0.0-SNAPSHOT-jar-with-dependencies.jar`

## Limitations
- **Static Analysis Only:** The system does not resolve DNS, check active threat feeds (like Google Safe Browsing), or fetch page content. It relies entirely on the URL string structure.
- **Heuristic False Positives:** A legitimate site might trigger alerts (e.g., a long URL on a `.xyz` domain without HTTPS). The system assigns a probability score, not a definitive truth.
