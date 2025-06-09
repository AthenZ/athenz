package com.yahoo.athenz.instance.provider.impl;

import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;

import com.nimbusds.jose.proc.SecurityContext;

import java.util.HashMap;
import java.util.Map;

public class InstanceGithubActionsProp {

    private final Map<String, Prop> properties = new HashMap<>();

    // Inner class to hold property data
    private static class Prop {
        String providerDnsSuffix;
        String audience;
        String enterprise;
        String jwksUri;
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

        Prop(String providerDnsSuffix, String audience, String enterprise, String jwksUri) {
            this.providerDnsSuffix = providerDnsSuffix;
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
    // TODO: Add DNS Suffixes TOO?
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
    public String getProviderDnsSuffix(String issuer) {
        if (!properties.containsKey(issuer)) {
            return null;
        }
        return properties.get(issuer).providerDnsSuffix;
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
        return getEnterprise(issuer) != null && !getEnterprise(issuer).isEmpty();
    }

    public String getJwksUri(String issuer) {
        if (!properties.containsKey(issuer)) {
            return null;
        }
        return properties.get(issuer).jwksUri;
    }

    public boolean hasInitializedJwtProcessor() {
        return properties.values().stream()
            .anyMatch(prop -> prop.jwtProcessor != null);
    }

    public ConfigurableJWTProcessor<SecurityContext> getJwtProcessor(String issuer) {
        if (!properties.containsKey(issuer)) {
            return null;
        }
        return properties.get(issuer).jwtProcessor;
    }
}
