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
    public void addProperties(String issuer, String providerDnsSuffix, String audience, String enterprise, String jwksUri) {
        if (issuer == null || providerDnsSuffix == null || audience == null || jwksUri == null) {
            throw new IllegalArgumentException("One of the required properties is null");
        }
        properties.put(issuer, new Prop(providerDnsSuffix, audience, enterprise, jwksUri));
    }

    // Getter methods
    public String getProviderDnsSuffix(String issuer) {
        return getPropertyData(issuer).providerDnsSuffix;
    }

    public String getAudience(String issuer) {
        return getPropertyData(issuer).audience;
    }

    public String getEnterprise(String issuer) {
        return getPropertyData(issuer).enterprise;
    }

    public String getJwksUri(String issuer) {
        return getPropertyData(issuer).jwksUri;
    }

    public ConfigurableJWTProcessor<SecurityContext> getJwtProcessor(String issuer) {
        return getPropertyData(issuer).jwtProcessor;
    }

    // Private method to retrieve PropertyData
    private Prop getPropertyData(String issuer) {
        Prop data = properties.get(issuer);
        if (data == null) {
            throw new IllegalArgumentException("No properties found for issuer: " + issuer);
        }
        return data;
    }
}
