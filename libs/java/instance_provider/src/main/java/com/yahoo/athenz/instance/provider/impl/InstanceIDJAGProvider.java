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
package com.yahoo.athenz.instance.provider.impl;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigLong;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.common.server.util.config.ConfigManagerSingleton.CONFIG_MANAGER;

/**
 * Instance provider for workloads that authenticate with an Identity Assertion
 * JWT Authorization Grant (ID-JAG) token as their attestation data. The token
 * carries an <code>act</code> claim describing the delegation chain, e.g.
 * <pre>
 *   "act": {
 *     "act": {
 *       "sub": "clientsvcid1234355",
 *       "sub_profile": "service"
 *     },
 *     "sub": "aiclientid12tsy8084bo8FU1d8",
       "sub_profile": "ai_agent"
 *   },
 *   "aud": "https://audience.athenz.io",
 *   "client_id": "aiclientid12tsy8084bo8FU1d8"
 * </pre>
 * The provider validates the token issuer and audience against its configured
 * values, requires the outermost actor to carry the configured
 * <code>sub_profile</code> value, and requires the <code>client_id</code> claim
 * to match the <code>sub</code> field of that actor. The requested identity must
 * be in the configured domain and its service name must be the client id.
 */
public class InstanceIDJAGProvider implements InstanceProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceIDJAGProvider.class);

    private static final String URI_INSTANCE_ID_PREFIX = "athenz://instanceid/";
    private static final String URI_SPIFFE_PREFIX      = "spiffe://";

    static final String ID_JAG_PROP_PROVIDER_DNS_SUFFIX = "athenz.zts.id_jag.provider_dns_suffix";
    static final String ID_JAG_PROP_BOOT_TIME_OFFSET    = "athenz.zts.id_jag.boot_time_offset";
    static final String ID_JAG_PROP_CERT_EXPIRY_TIME    = "athenz.zts.id_jag.cert_expiry_time";
    static final String ID_JAG_PROP_ACT_SUB_PROFILE     = "athenz.zts.id_jag.act_sub_profile";
    static final String ID_JAG_PROP_AUDIENCE            = "athenz.zts.id_jag.audience";
    static final String ID_JAG_PROP_DOMAIN              = "athenz.zts.id_jag.domain";
    static final String ID_JAG_PROP_ISSUER              = "athenz.zts.id_jag.issuer";
    static final String ID_JAG_PROP_JWKS_URI            = "athenz.zts.id_jag.jwks_uri";

    static final String CLAIM_ACT         = "act";
    static final String CLAIM_CLIENT_ID   = "client_id";
    static final String CLAIM_SUB         = "sub";
    static final String CLAIM_SUB_PROFILE = "sub_profile";

    Set<String> dnsSuffixes = null;
    String provider = null;
    String idJagIssuer = null;
    String idJagDomain = null;
    String actSubProfile = null;
    String audience = null;
    ConfigurableJWTProcessor<SecurityContext> jwtProcessor = null;
    DynamicConfigLong bootTimeOffsetSeconds;
    long certExpiryTime;

    @Override
    public Scheme getProviderScheme() {
        return Scheme.CLASS;
    }

    @Override
    public void initialize(String provider, String providerEndpoint, SSLContext sslContext, KeyStore keyStore) {

        // save our provider name

        this.provider = provider;

        // the domain that this provider is authorized to issue identities in.
        // there is no default value since accepting any domain would defeat
        // the purpose of the check

        idJagDomain = System.getProperty(ID_JAG_PROP_DOMAIN);
        if (StringUtil.isEmpty(idJagDomain)) {
            throw new IllegalArgumentException("InstanceIDJAGProvider: Domain not specified");
        }

        // the audience that the id jag token must have been issued for

        audience = System.getProperty(ID_JAG_PROP_AUDIENCE);
        if (StringUtil.isEmpty(audience)) {
            throw new IllegalArgumentException("InstanceIDJAGProvider: Audience not specified");
        }

        // the sub_profile value that the actor in the act claim must carry.
        // if this is not specified we'll just default to ai_agent. we still
        // reject an empty value in case it was configured incorrectly since
        // matching against an empty profile would defeat the check

        actSubProfile = System.getProperty(ID_JAG_PROP_ACT_SUB_PROFILE, "ai_agent");
        if (StringUtil.isEmpty(actSubProfile)) {
            throw new IllegalArgumentException("InstanceIDJAGProvider: Act sub profile not specified");
        }

        // determine the dns suffix. if this is not specified we'll just default to id-jag.athenz.io

        final String dnsSuffix = System.getProperty(ID_JAG_PROP_PROVIDER_DNS_SUFFIX, "id-jag.athenz.io");
        dnsSuffixes = Set.of(dnsSuffix.split(","));

        // how long the instance must be booted in the past before we
        // stop validating the instance requests

        long timeout = TimeUnit.SECONDS.convert(5, TimeUnit.MINUTES);
        bootTimeOffsetSeconds = new DynamicConfigLong(CONFIG_MANAGER, ID_JAG_PROP_BOOT_TIME_OFFSET, timeout);

        // get default/max expiry time for any generated certificates - 6 hours

        certExpiryTime = Long.parseLong(System.getProperty(ID_JAG_PROP_CERT_EXPIRY_TIME, "360"));

        // initialize our jwt processor. the issuer is required since it is
        // both the source of our signing keys and one of our validation checks

        idJagIssuer = System.getProperty(ID_JAG_PROP_ISSUER);
        if (StringUtil.isEmpty(idJagIssuer)) {
            throw new IllegalArgumentException("InstanceIDJAGProvider: Issuer not specified");
        }

        jwtProcessor = JwtsHelper.getJWTProcessor(new JwtsSigningKeyResolver(extractIssuerJwksUri(idJagIssuer), null),
                JwtsHelper.JWT_JAG_TYPE_VERIFIER);
    }

    String extractIssuerJwksUri(final String issuer) {

        // if we have the value configured then that's what we're going to use

        final String jwksUri = System.getProperty(ID_JAG_PROP_JWKS_URI);
        if (!StringUtil.isEmpty(jwksUri)) {
            return jwksUri;
        }

        // otherwise we'll assume the issuer follows the standard and
        // includes the jwks uri in its openid configuration

        final String openIdConfigUri = issuer + "/.well-known/openid-configuration";
        JwtsHelper helper = new JwtsHelper();
        return helper.extractJwksUri(openIdConfigUri, null);
    }

    private ProviderResourceException forbiddenError(String message) {
        LOGGER.error(message);
        return new ProviderResourceException(ProviderResourceException.FORBIDDEN, message);
    }

    @Override
    public InstanceConfirmation confirmInstance(InstanceConfirmation confirmation) throws ProviderResourceException {

        final String instanceDomain = confirmation.getDomain();
        final String instanceService = confirmation.getService();
        final Map<String, String> instanceAttributes = confirmation.getAttributes();

        // the identity must be requested in our configured domain

        if (!idJagDomain.equalsIgnoreCase(instanceDomain)) {
            throw forbiddenError("Domain: " + instanceDomain + " is not the configured domain: " + idJagDomain);
        }

        // our request must not have any sanIPs or hostnames

        if (!StringUtil.isEmpty(InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_SAN_IP))) {
            throw forbiddenError("Request must not have any sanIP addresses");
        }

        if (!StringUtil.isEmpty(InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_HOSTNAME))) {
            throw forbiddenError("Request must not have any hostname values");
        }

        // validate san URI

        if (!validateSanUri(InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_SAN_URI))) {
            throw forbiddenError("Unable to validate certificate request URI values");
        }

        // we need to validate the id jag token which is our attestation
        // data for the service requesting a certificate

        final String attestationData = confirmation.getAttestationData();
        if (StringUtil.isEmpty(attestationData)) {
            throw forbiddenError("Service credentials not provided");
        }

        StringBuilder errMsg = new StringBuilder(256);
        if (!validateIDJAGToken(attestationData, instanceService, errMsg)) {
            throw forbiddenError("Unable to validate Certificate Request: " + errMsg);
        }

        // validate the certificate san DNS names

        StringBuilder instanceId = new StringBuilder(256);
        if (!InstanceUtils.validateCertRequestSanDnsNames(instanceAttributes, instanceDomain,
                instanceService, dnsSuffixes, null, null, false, instanceId, null)) {
            throw forbiddenError("Unable to validate certificate request sanDNS entries");
        }

        // set our cert attributes in the return object. we do not allow refresh
        // of those certificates since the client must present a new id jag token,
        // and the issued certificate can only be used by clients and not servers

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_CERT_REFRESH, "false");
        attributes.put(InstanceProvider.ZTS_CERT_USAGE, ZTS_CERT_USAGE_CLIENT);
        attributes.put(InstanceProvider.ZTS_CERT_EXPIRY_TIME, Long.toString(certExpiryTime));

        confirmation.setAttributes(attributes);
        return confirmation;
    }

    @Override
    public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) throws ProviderResourceException {

        // we do not allow refresh of ID JAG based certificates

        throw forbiddenError("ID JAG X.509 Certificates cannot be refreshed");
    }

    /**
     * verifies that sanUri only contains the spiffe and instance id uris
     * @param sanUri the SAN URI value
     * @return true if it only contains spiffe and instance id uris, otherwise false
     */
    boolean validateSanUri(final String sanUri) {

        if (StringUtil.isEmpty(sanUri)) {
            LOGGER.debug("Request contains no sanURI to verify");
            return true;
        }

        for (String uri : sanUri.split(",")) {
            if (uri.startsWith(URI_SPIFFE_PREFIX) || uri.startsWith(URI_INSTANCE_ID_PREFIX)) {
                continue;
            }
            LOGGER.error("Request contains unsupported uri value: {}", uri);
            return false;
        }

        return true;
    }

    /**
     * validates the given id jag token against our configured issuer, audience
     * and act claim requirements, and verifies that the requested service name
     * matches the client id in the token
     * @param jwToken the id jag token presented as attestation data
     * @param serviceName the service name from the instance confirmation object
     * @param errMsg the buffer to append any failure details to
     * @return true if the token is valid for the requested service, false otherwise
     */
    boolean validateIDJAGToken(final String jwToken, final String serviceName, StringBuilder errMsg) {

        if (jwtProcessor == null) {
            errMsg.append("JWT Processor not initialized");
            return false;
        }

        JWTClaimsSet claimsSet;
        try {
            claimsSet = jwtProcessor.process(jwToken, null);
        } catch (Exception ex) {
            errMsg.append("Unable to parse and validate token: ").append(ex.getMessage());
            return false;
        }

        // verify the issuer matches our configured value

        if (!idJagIssuer.equals(claimsSet.getIssuer())) {
            errMsg.append("token issuer is not the configured issuer: ").append(claimsSet.getIssuer());
            return false;
        }

        // verify that the token audience matches our configured value

        if (!audience.equals(JwtsHelper.getAudience(claimsSet))) {
            errMsg.append("token audience is not the configured audience: ").append(JwtsHelper.getAudience(claimsSet));
            return false;
        }

        // need to verify that the issue time is within our configured bootstrap time

        Date issueDate = claimsSet.getIssueTime();
        if (issueDate == null || issueDate.getTime() < System.currentTimeMillis() -
                TimeUnit.SECONDS.toMillis(bootTimeOffsetSeconds.get())) {
            errMsg.append("token issue time is not recent enough, issued at: ").append(issueDate);
            return false;
        }

        // the token must include the act claim which identifies the actor
        // requesting the identity along with its delegation chain

        Object actClaim = claimsSet.getClaim(CLAIM_ACT);
        if (!(actClaim instanceof Map)) {
            errMsg.append("token does not contain required act claim");
            return false;
        }
        Map<?, ?> actMap = (Map<?, ?>) actClaim;

        // the profile of the actor must match our configured value

        final String tokenSubProfile = getActStringField(actMap, CLAIM_SUB_PROFILE);
        if (!actSubProfile.equals(tokenSubProfile)) {
            errMsg.append("token act sub_profile: ").append(tokenSubProfile)
                    .append(" does not match configured value: ").append(actSubProfile);
            return false;
        }

        // the client id must match the subject of the actor

        final String actSubject = getActStringField(actMap, CLAIM_SUB);
        if (StringUtil.isEmpty(actSubject)) {
            errMsg.append("token act claim does not contain required sub field");
            return false;
        }

        final String clientId = JwtsHelper.getStringClaim(claimsSet, CLAIM_CLIENT_ID);
        if (StringUtil.isEmpty(clientId)) {
            errMsg.append("token does not contain required client_id claim");
            return false;
        }

        if (!clientId.equals(actSubject)) {
            errMsg.append("token client_id: ").append(clientId)
                    .append(" does not match act sub: ").append(actSubject);
            return false;
        }

        // finally, the requested service name must be the client id. ZTS
        // lowercases all service names so our comparison ignores case

        if (!clientId.equalsIgnoreCase(serviceName)) {
            errMsg.append("service name: ").append(serviceName)
                    .append(" does not match token client_id: ").append(clientId);
            return false;
        }

        return true;
    }

    String getActStringField(final Map<?, ?> actMap, final String field) {
        Object value = actMap.get(field);
        return (value instanceof String) ? (String) value : null;
    }
}
