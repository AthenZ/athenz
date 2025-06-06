package com.yahoo.athenz.instance.provider.impl;

import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.nimbusds.jose.proc.SecurityContext;

public class InstanceGithubActionsConfig {
    private String issuer = "";
    private String providerDnsSuffix = "";
    private String audience = "";
    private String enterprise = "";
    private String jwksUri = "";
    private ConfigurableJWTProcessor<SecurityContext> jwtProcessor = null;

    public InstanceGithubActionsConfig(String issuer, String providerDnsSuffix, String audience, String enterprise, String jwksUri) {
        if (issuer == null || providerDnsSuffix == null || audience == null || jwksUri == null) {
            throw new IllegalArgumentException("One of the required properties is null");
        }
        this.issuer = issuer;
        this.providerDnsSuffix = providerDnsSuffix;
        this.audience = audience;
        this.enterprise = enterprise;
        this.jwksUri = jwksUri;
        this.jwtProcessor = JwtsHelper.getJWTProcessor(new JwtsSigningKeyResolver(jwksUri, null));
    }


    public String getProviderDnsSuffix() {
        return providerDnsSuffix;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getAudience() {
        return audience;
    }

    public String getEnterprise() {
        return enterprise;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public ConfigurableJWTProcessor<SecurityContext> getJwtProcessor() {
        return jwtProcessor;
    }
}
