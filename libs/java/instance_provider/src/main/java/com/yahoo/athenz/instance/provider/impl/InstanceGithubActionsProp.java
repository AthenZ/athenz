package com.yahoo.athenz.instance.provider.impl;

import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;

import com.nimbusds.jose.proc.SecurityContext;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class InstanceGithubActionsProp {

    private final Map<String, Prop> properties = new HashMap<>();

    // Inner class to hold property data
    private static class Prop {
        String audience;
        String enterprise;
        Set<String> dnsSuffixes;
        String jwksUri;
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

        Prop(String dnsSuffix, String audience, String enterprise, String jwksUri) {
            dnsSuffixes = Set.of(dnsSuffix.split(","));
            this.audience = audience;
            this.enterprise = enterprise;
            this.jwksUri = jwksUri;
            this.jwtProcessor = JwtsHelper.getJWTProcessor(new JwtsSigningKeyResolver(jwksUri, null));
        }
    }

    // No-argument constructor
    public InstanceGithubActionsProp() {
    }

    // Method to add properties
    public void addProperties(String issuer, String providerDnsSuffix, String audience, String enterprise, String jwksUri) {
        if (issuer == null || providerDnsSuffix == null || audience == null || jwksUri == null) {
            throw new IllegalArgumentException("One of the required properties is null");
        }
        properties.put(issuer, new Prop(providerDnsSuffix, audience, enterprise, jwksUri));
    }

    public Boolean hasIssuer(String issuer) {
        if (issuer == null || issuer.isEmpty()) {
            return false;
        }
        return properties.containsKey(issuer);
    }

    // Getter methods
    public Set<String> getDnsSuffixes(String issuer) {
        if (!properties.containsKey(issuer)) {
            return null;
        }
        return properties.get(issuer).dnsSuffixes;
    }

    public String getAudience(String issuer) {
        if (!properties.containsKey(issuer)) {
            return null;
        }
        return properties.get(issuer).audience;
    }

    public String getEnterprise(String issuer) {
        if (!properties.containsKey(issuer)) {
            return null;
        }
        return properties.get(issuer).enterprise;
    }

    public Boolean hasEnterprise (String issuer) {
        String enterprise = getEnterprise(issuer);
        return enterprise != null && !enterprise.isEmpty();
    }

    public String getJwksUri(String issuer) {
        if (!properties.containsKey(issuer)) {
            return null;
        }
        return properties.get(issuer).jwksUri;
    }

    public ConfigurableJWTProcessor<SecurityContext> getJwtProcessor(String issuer) {
        if (!properties.containsKey(issuer)) {
            return null;
        }
        return properties.get(issuer).jwtProcessor;
    }
}
