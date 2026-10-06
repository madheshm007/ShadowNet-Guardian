package com.shadownetguardian.model;

import java.net.URI;
import java.net.URISyntaxException;

public class ParsedUrl {
    private final String originalUrl;
    private String scheme;
    private String host;
    private String path;
    private String query;
    private String userInfo;
    private boolean valid;

    public ParsedUrl(String url) {
        this.originalUrl = url != null ? url.trim() : "";
        parse();
    }

    private void parse() {
        scheme = "";
        host = "";
        path = "";
        query = "";
        userInfo = "";
        valid = false;

        if (originalUrl.isEmpty()) {
            return;
        }

        String urlToParse = originalUrl;
        if (!urlToParse.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*")) {
            urlToParse = "http://" + urlToParse;
        }

        try {
            URI uri = new URI(urlToParse);
            this.scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase() : "";
            this.host = uri.getHost() != null ? uri.getHost().toLowerCase() : "";
            this.path = uri.getPath() != null ? uri.getPath() : "";
            this.query = uri.getQuery() != null ? uri.getQuery() : "";
            this.userInfo = uri.getUserInfo() != null ? uri.getUserInfo() : "";

            // ShadowNet Guardian analyzes web URLs only. A parsed URI must
            // have an HTTP(S) scheme and a non-empty host to be considered valid.
            this.valid = ("http".equals(scheme) || "https".equals(scheme))
                    && !host.isEmpty();
        } catch (URISyntaxException e) {
            this.valid = false;
        }
    }

    public String getOriginalUrl() { return originalUrl; }
    public String getScheme() { return scheme; }
    public String getHost() { return host; }
    public String getPath() { return path; }
    public String getQuery() { return query; }
    public String getUserInfo() { return userInfo; }
    public boolean isValid() { return valid; }
}
