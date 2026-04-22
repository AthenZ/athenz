/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yahoo.athenz.auth.impl;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Authority that validates OIDC ID tokens (signed JWTs) from an external OpenID
 * Connect provider and creates Athenz user principals. This allows an Athenz
 * service (typically the UI) to forward an end user's ID token to ZMS in the
 * {@code Authorization: Bearer} header and have ZMS API calls attributed to the
 * individual user rather than a service identity.
 *
 * <p>Configuration via system properties (default prefix
 * {@value #DEFAULT_PROPERTY_PREFIX}; subclasses may override
 * {@link #propertyPrefix()} to namespace a second instance):
 *
 * <ul>
 *   <li>{@code athenz.auth.oidc.issuer} (required): OIDC issuer URL. Must use
 *       {@code https://}. Used for both OIDC discovery
 *       ({@code /.well-known/openid-configuration}) and verification of the
 *       JWT {@code iss} claim. The value is preserved as configured for exact
 *       {@code iss} matching; a trailing slash is only appended when building
 *       the discovery URL.</li>
 *   <li>{@code athenz.auth.oidc.audience} (required): Expected {@code aud}
 *       claim value, typically the OIDC client ID.</li>
 *   <li>{@code athenz.auth.oidc.email_domain} (required when
 *       {@code claim_mapping=email}): Email domain stripped from the email
 *       claim to derive the username. Compared case-insensitively.</li>
 *   <li>{@code athenz.auth.oidc.claim_mapping} (optional, default
 *       {@code email}): JWT claim used to derive the Athenz username. If set
 *       to {@code email}, the configured domain is stripped and the
 *       {@code email_verified} claim (when present) must be {@code true}.
 *       Any other value is used as the username verbatim (lowercased).</li>
 *   <li>{@code athenz.auth.oidc.domain} (optional, default {@code user}):
 *       Athenz domain for the resulting principal.</li>
 *   <li>{@code athenz.auth.oidc.name} (optional, default derived from the
 *       issuer host): Short name used in the authority ID, which takes the
 *       form {@code Auth-OIDC-{name}}.</li>
 *   <li>{@code athenz.auth.oidc.username_pattern} (optional, default
 *       {@value #DEFAULT_USERNAME_PATTERN}): Regex that the final username
 *       must match. The pattern is applied <em>after</em> the username is
 *       lowercased, so character classes should target lowercase characters.
 *       The default is a strict Athenz-style identifier; deployments with
 *       dotted or underscored usernames (for example from Okta or Azure AD)
 *       should loosen it, e.g. to {@code [a-z0-9][a-z0-9._-]*}. An invalid
 *       regex causes initialization to fail.</li>
 * </ul>
 *
 * <p>Tokens that produce a username not matching the configured pattern
 * (after claim extraction and, when applicable, domain stripping) are
 * rejected.
 *
 * <p><b>Coexistence with other Bearer authorities.</b> Athenz dispatches
 * credentials to each configured authority in order; each authority returns
 * {@code null} for tokens it does not recognise. This class performs an early
 * unverified parse of the JWT to check the {@code iss} claim before consulting
 * the JWKS endpoint, so tokens issued by other providers (for example Athenz
 * access tokens handled by {@link ServiceAccessTokenAuthority}) are quickly
 * passed through without key resolution or log noise.
 *
 * <p><b>Multiple OIDC providers.</b> To support more than one external
 * provider, configure a trivial subclass per provider and override
 * {@link #propertyPrefix()} so each instance reads its own system properties:
 *
 * <pre>
 *     public class OktaOIDCAuthority extends OIDCAuthority {
 *         &#064;Override protected String propertyPrefix() {
 *             return "athenz.auth.oidc.okta";
 *         }
 *     }
 * </pre>
 *
 * Then register both classes in {@code athenz.zms.authority_classes}.
 *
 * @see ServiceAccessTokenAuthority
 * @see UserAuthority
 */
public class OIDCAuthority implements Authority {

    private static final Logger LOG = LoggerFactory.getLogger(OIDCAuthority.class);

    public static final String DEFAULT_PROPERTY_PREFIX = "athenz.auth.oidc";

    public static final String PROP_ISSUER           = "issuer";
    public static final String PROP_AUDIENCE         = "audience";
    public static final String PROP_EMAIL_DOMAIN     = "email_domain";
    public static final String PROP_CLAIM_MAPPING    = "claim_mapping";
    public static final String PROP_DOMAIN           = "domain";
    public static final String PROP_NAME             = "name";
    public static final String PROP_USERNAME_PATTERN = "username_pattern";

    public static final String DEFAULT_CLAIM_MAPPING    = "email";
    public static final String DEFAULT_DOMAIN           = "user";
    public static final String DEFAULT_USERNAME_PATTERN = "[a-z][a-z0-9]*";

    public static final String BEARER_PREFIX  = "Bearer ";

    static final String EMAIL_CLAIM           = "email";
    static final String EMAIL_VERIFIED_CLAIM  = "email_verified";

    private String issuer;
    private String audience;
    private String emailDomain;
    private String claimMapping;
    private String principalDomain;
    private String authorityId;
    private Pattern validUsernamePattern;
    private ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    /**
     * @return the system-property prefix this authority reads its configuration
     *     from. Subclasses override this to support multiple OIDC provider
     *     instances in a single ZMS deployment.
     */
    protected String propertyPrefix() {
        return DEFAULT_PROPERTY_PREFIX;
    }

    @Override
    public void initialize() {

        final String prefix = propertyPrefix();
        issuer          = System.getProperty(prefix + "." + PROP_ISSUER);
        audience        = System.getProperty(prefix + "." + PROP_AUDIENCE);
        emailDomain     = System.getProperty(prefix + "." + PROP_EMAIL_DOMAIN);
        claimMapping    = System.getProperty(prefix + "." + PROP_CLAIM_MAPPING, DEFAULT_CLAIM_MAPPING);
        principalDomain = System.getProperty(prefix + "." + PROP_DOMAIN, DEFAULT_DOMAIN);
        final String configuredName = System.getProperty(prefix + "." + PROP_NAME);

        if (issuer == null || issuer.isEmpty()) {
            throw new IllegalStateException("Required property " + prefix + "." + PROP_ISSUER + " is not set");
        }
        if (!issuer.startsWith("https://")) {
            throw new IllegalStateException("Property " + prefix + "." + PROP_ISSUER
                    + " must use https scheme (got: " + issuer + ")");
        }
        // Keep the configured issuer as-is for exact iss-claim comparison:
        // OIDC providers differ in trailing-slash convention (Google and Okta
        // omit it; JumpCloud and Auth0 include it) and the iss claim must
        // match the issuer string byte-for-byte.
        final String discoveryIssuer = issuer.endsWith("/") ? issuer : issuer + "/";
        if (audience == null || audience.isEmpty()) {
            throw new IllegalStateException("Required property " + prefix + "." + PROP_AUDIENCE + " is not set");
        }
        if (EMAIL_CLAIM.equals(claimMapping)) {
            if (emailDomain == null || emailDomain.isEmpty()) {
                throw new IllegalStateException("Property " + prefix + "." + PROP_EMAIL_DOMAIN
                        + " is required when " + PROP_CLAIM_MAPPING + "=" + EMAIL_CLAIM);
            }
            emailDomain = emailDomain.toLowerCase(Locale.ROOT);
        }

        // An explicitly empty property value falls back to the default. Without
        // this guard, Pattern.compile("") produces a pattern that matches only
        // the empty string, which would silently reject every authentication.
        final String configuredPattern = System.getProperty(prefix + "." + PROP_USERNAME_PATTERN);
        final String patternSource = (configuredPattern == null || configuredPattern.isEmpty())
                ? DEFAULT_USERNAME_PATTERN : configuredPattern;
        try {
            validUsernamePattern = Pattern.compile(patternSource);
        } catch (PatternSyntaxException e) {
            throw new IllegalStateException("Invalid regex for " + prefix + "." + PROP_USERNAME_PATTERN
                    + ": " + patternSource + " (" + e.getDescription() + ")", e);
        }

        authorityId = "Auth-OIDC-" +
                ((configuredName != null && !configuredName.isEmpty()) ? configuredName : deriveNameFromIssuer(issuer));

        if (jwtProcessor == null) {
            final String discoveryUrl = discoveryIssuer + ".well-known/openid-configuration";
            final String jwksUri = new JwtsHelper().extractJwksUri(discoveryUrl, null);
            if (jwksUri == null) {
                throw new IllegalStateException("Failed to discover JWKS URI from " + discoveryUrl);
            }
            final JwtsSigningKeyResolver keyResolver = new JwtsSigningKeyResolver(jwksUri, null, true);
            jwtProcessor = JwtsHelper.getJWTProcessor(keyResolver);
        }

        LOG.info("{} initialized: issuer={}, audience={}, claimMapping={}, principalDomain={}",
                authorityId, issuer, audience, claimMapping, principalDomain);
    }

    /**
     * Derive a short authority name from the issuer host by taking the
     * second-to-last dotted label (e.g. {@code oauth.id.jumpcloud.com} ->
     * {@code jumpcloud}, {@code accounts.google.com} -> {@code google}). Falls
     * back to the full host when it has fewer than two labels or when the URL
     * cannot be parsed.
     *
     * <p>This heuristic picks the wrong label for issuer hosts under multi-part
     * ccTLDs (for example {@code login.example.co.uk} yields {@code co}).
     * Operators in that situation should set the
     * {@code athenz.auth.oidc.name} property explicitly.
     */
    static String deriveNameFromIssuer(String issuer) {
        String host;
        try {
            host = new URI(issuer).getHost();
        } catch (URISyntaxException e) {
            host = null;
        }
        if (host == null || host.isEmpty()) {
            return "default";
        }
        final String[] labels = host.split("\\.");
        if (labels.length < 2) {
            return host.toLowerCase(Locale.ROOT);
        }
        return labels[labels.length - 2].toLowerCase(Locale.ROOT);
    }

    // Visible for testing.
    void setJwtProcessor(ConfigurableJWTProcessor<SecurityContext> jwtProcessor) {
        this.jwtProcessor = jwtProcessor;
    }

    void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    void setAudience(String audience) {
        this.audience = audience;
    }

    void setEmailDomain(String emailDomain) {
        this.emailDomain = emailDomain;
    }

    void setClaimMapping(String claimMapping) {
        this.claimMapping = claimMapping;
    }

    void setPrincipalDomain(String principalDomain) {
        this.principalDomain = principalDomain;
    }

    void setAuthorityId(String authorityId) {
        this.authorityId = authorityId;
    }

    void setValidUsernamePattern(Pattern validUsernamePattern) {
        this.validUsernamePattern = validUsernamePattern;
    }

    @Override
    public String getID() {
        return authorityId;
    }

    @Override
    public String getDomain() {
        return principalDomain;
    }

    @Override
    public String getHeader() {
        return "Authorization";
    }

    @Override
    public String getAuthenticateChallenge() {
        return "Bearer realm=\"athenz\"";
    }

    /**
     * Returns {@code true} because a validated OIDC ID token is itself the
     * credential; unlike {@link UserAuthority}, no subsequent NToken exchange
     * is required before the principal may authorize actions.
     */
    @Override
    public boolean allowAuthorization() {
        return true;
    }

    @Override
    public Principal authenticate(String creds, String remoteAddr, String httpMethod, StringBuilder errMsg) {

        errMsg = errMsg == null ? new StringBuilder(512) : errMsg;

        if (creds == null || !creds.startsWith(BEARER_PREFIX)) {
            errMsg.append(authorityId).append(": credentials do not start with 'Bearer '");
            return null;
        }

        final String token = creds.substring(BEARER_PREFIX.length());
        if (token.isEmpty()) {
            errMsg.append(authorityId).append(": no token after 'Bearer '");
            return null;
        }

        // Pre-parse to check issuer before full JWKS validation. This avoids
        // unnecessary key resolution and log noise for tokens issued by other
        // Bearer authorities (for example ServiceAccessTokenAuthority).
        try {
            final SignedJWT parsed = SignedJWT.parse(token);
            final String tokenIssuer = parsed.getJWTClaimsSet().getIssuer();
            if (!issuer.equals(tokenIssuer)) {
                errMsg.append(authorityId).append(": issuer mismatch (token issuer: ")
                        .append(tokenIssuer).append(")");
                return null;
            }
        } catch (ParseException e) {
            errMsg.append(authorityId).append(": failed to parse JWT: ").append(e.getMessage());
            return null;
        }

        final JWTClaimsSet claims;
        try {
            claims = jwtProcessor.process(token, null);
        } catch (Exception e) {
            errMsg.append(authorityId).append(": JWT validation failed: ").append(e.getMessage());
            return null;
        }

        if (claims.getAudience() == null || !claims.getAudience().contains(audience)) {
            errMsg.append(authorityId).append(": token audience ").append(claims.getAudience())
                    .append(" does not contain expected: ").append(audience);
            return null;
        }

        final String username = extractUsername(claims, errMsg);
        if (username == null) {
            return null;
        }

        final long issueTime = claims.getIssueTime() != null ? claims.getIssueTime().getTime() / 1000 : 0;

        final Principal principal = SimplePrincipal.create(principalDomain, username, creds, issueTime, this);
        if (principal == null) {
            errMsg.append(authorityId).append(": failed to create principal for user: ").append(username);
            return null;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("{}: authenticated {}.{} from {}", authorityId, principalDomain, username, remoteAddr);
        }

        return principal;
    }

    private String extractUsername(JWTClaimsSet claims, StringBuilder errMsg) {

        final String rawValue;
        try {
            rawValue = claims.getStringClaim(claimMapping);
        } catch (ParseException e) {
            errMsg.append(authorityId).append(": failed to parse claim '").append(claimMapping)
                    .append("': ").append(e.getMessage());
            return null;
        }

        if (rawValue == null || rawValue.isEmpty()) {
            errMsg.append(authorityId).append(": missing claim '").append(claimMapping).append("'");
            return null;
        }

        final String username;
        if (EMAIL_CLAIM.equals(claimMapping)) {
            try {
                final Boolean emailVerified = claims.getBooleanClaim(EMAIL_VERIFIED_CLAIM);
                if (emailVerified != null && !emailVerified) {
                    errMsg.append(authorityId).append(": email not verified for: ").append(rawValue);
                    return null;
                }
            } catch (ParseException e) {
                errMsg.append(authorityId).append(": failed to parse ").append(EMAIL_VERIFIED_CLAIM)
                        .append(" claim: ").append(e.getMessage());
                return null;
            }

            final String emailLower = rawValue.toLowerCase(Locale.ROOT);
            if (!emailLower.endsWith(emailDomain)) {
                errMsg.append(authorityId).append(": email '").append(rawValue)
                        .append("' does not end with '").append(emailDomain).append("'");
                return null;
            }
            username = emailLower.substring(0, emailLower.length() - emailDomain.length());
        } else {
            username = rawValue.toLowerCase(Locale.ROOT);
        }

        if (username.isEmpty() || !validUsernamePattern.matcher(username).matches()) {
            errMsg.append(authorityId).append(": invalid username '").append(username)
                    .append("' from claim '").append(claimMapping).append("' value: ").append(rawValue);
            return null;
        }

        return username;
    }
}
