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

import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.auth.token.Token;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ResourceException;
import com.yahoo.athenz.zts.InstanceRegisterToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class InstanceZTSProvider implements InstanceProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceZTSProvider.class);
    private static final Pattern WHITESPACE_PATTERN = Pattern.compile("\\s+");
    private static final String URI_HOSTNAME_PREFIX = "athenz://hostname/";

    static final String ZTS_PROP_PROVIDER_DNS_SUFFIX  = "athenz.zts.provider_dns_suffix";
    static final String ZTS_PROP_PRINCIPAL_LIST       = "athenz.zts.provider_service_list";
    static final String ZTS_PROP_EXPIRY_TIME          = "athenz.zts.provider_token_expiry_time";

    static final String ZTS_PROVIDER_SERVICE  = "sys.auth.zts";

    public static final String HDR_KEY_ID     = "kid";
    public static final String HDR_TOKEN_TYPE = "typ";
    public static final String HDR_TOKEN_JWT  = "jwt";

    public static final String CLAIM_PROVIDER    = "provider";
    public static final String CLAIM_DOMAIN      = "domain";
    public static final String CLAIM_SERVICE     = "service";
    public static final String CLAIM_CLIENT_ID   = "client_id";
    public static final String CLAIM_INSTANCE_ID = "instance_id";

    KeyStore keyStore = null;
    Set<String> dnsSuffixes = null;
    String provider = null;
    String keyId = null;
    PrivateKey key = null;
    SignatureAlgorithm keyAlg = null;
    Set<String> principals = null;
    HostnameResolver hostnameResolver = null;
    JwtsSigningKeyResolver signingKeyResolver = null;
    int expiryTime;

    @Override
    public Scheme getProviderScheme() {
        return Scheme.CLASS;
    }

    @Override
    public void initialize(String provider, String providerEndpoint, SSLContext sslContext,
            KeyStore keyStore) {

        // save our provider name

        this.provider = provider;

        // obtain list of valid principals for this principal if
        // one is configured

        final String principalList = System.getProperty(ZTS_PROP_PRINCIPAL_LIST);
        if (principalList != null && !principalList.isEmpty()) {
            principals = new HashSet<>(Arrays.asList(principalList.split(",")));
        }

        // determine the dns suffix. if this is not specified we'll just default to zts.athenz.cloud

        dnsSuffixes = new HashSet<>();
        String dnsSuffix = System.getProperty(ZTS_PROP_PROVIDER_DNS_SUFFIX, "zts.athenz.cloud");
        if (StringUtil.isEmpty(dnsSuffix)) {
            dnsSuffix = "zts.athenz.cloud";
        }
        dnsSuffixes.addAll(Arrays.asList(dnsSuffix.split(",")));

        this.keyStore = keyStore;

        // get expiry time for any generated tokens - default 30 mins

        final String expiryTimeStr = System.getProperty(ZTS_PROP_EXPIRY_TIME, "30");
        expiryTime = Integer.parseInt(expiryTimeStr);

        // initialize our jwt key resolver

        signingKeyResolver = new JwtsSigningKeyResolver(null, null);
    }

    @Override
    public void setPrivateKey(PrivateKey key, String keyId, SignatureAlgorithm keyAlg) {
        this.key = key;
        this.keyId = keyId;
        this.keyAlg = keyAlg;
    }

    @Override
    public void setHostnameResolver(HostnameResolver hostnameResolver) {
        this.hostnameResolver = hostnameResolver;
    }

    private ResourceException forbiddenError(String message) {
        LOGGER.error(message);
        return new ResourceException(ResourceException.FORBIDDEN, message);
    }

    @Override
    public InstanceConfirmation confirmInstance(InstanceConfirmation confirmation) {
        return validateInstanceRequest(confirmation, true);
    }

    @Override
    public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) {
        return validateInstanceRequest(confirmation, false);
    }

    InstanceConfirmation validateInstanceRequest(InstanceConfirmation confirmation, boolean registerInstance) {

        // we need to validate the token which is our attestation
        // data for the service requesting a certificate

        final String instanceDomain = confirmation.getDomain();
        final String instanceService = confirmation.getService();

        final Map<String, String> instanceAttributes = confirmation.getAttributes();
        final String csrPublicKey = InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY);

        // make sure this service has been configured to be supported
        // by this zts provider

        if (principals != null && !principals.contains(instanceDomain + "." + instanceService)) {
            throw forbiddenError("Service not supported to be launched by ZTS Provider");
        }

        // we're supporting two attestation data models with our provider
        // 1) public / private key pair with service tokens - these
        //    are always starting with v=S1;... string
        // 2) provider registration tokens - using jwts

        final String attestationData = confirmation.getAttestationData();
        if (StringUtil.isEmpty(attestationData)) {
            throw forbiddenError("Service credentials not provided");
        }

        boolean tokenValidated;
        Map<String, String> attributes;
        StringBuilder errMsg = new StringBuilder(256);
        if (attestationData.startsWith("v=S1;")) {

            // set our cert attributes in the return object
            // for ZTS we do not allow refresh of those certificates

            attributes = new HashMap<>();
            attributes.put(InstanceProvider.ZTS_CERT_REFRESH, "false");

            tokenValidated = validateServiceToken(attestationData, instanceDomain,
                    instanceService, csrPublicKey, errMsg);

        } else {

            // for token based request we do support refresh operation

            attributes = Collections.emptyMap();

            final String instanceId = InstanceUtils.getInstanceProperty(instanceAttributes,
                    InstanceProvider.ZTS_INSTANCE_ID);
            tokenValidated = validateRegisterToken(attestationData, instanceDomain,
                    instanceService, instanceId, registerInstance, errMsg);
        }

        if (!tokenValidated) {
            LOGGER.error(errMsg.toString());
            throw forbiddenError("Unable to validate Certificate Request Auth Token");
        }

        final String clientIp = InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_CLIENT_IP);
        final String sanIpStr = InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_SAN_IP);
        final String hostname = InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_HOSTNAME);
        final String sanUri   = InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_SAN_URI);

        // validate the IP address if one is provided

        String[] sanIps = null;
        if (sanIpStr != null && !sanIpStr.isEmpty()) {
            sanIps = sanIpStr.split(",");
        }

        if (!validateSanIp(sanIps, clientIp)) {
            throw forbiddenError("Unable to validate request IP address");
        }

        // validate the hostname in payload
        // IP in clientIP can be NATed. For validating hostname, rely on sanIPs, which come
        // from the client, and are already matched with clientIp

        if (!validateHostname(hostname, sanIps)) {
            throw forbiddenError("Unable to validate certificate request hostname");
        }

        // validate san URI
        if (!validateSanUri(sanUri, hostname)) {
            throw forbiddenError("Unable to validate certificate request URI hostname");
        }

        // validate the certificate san DNS names

        StringBuilder instanceId = new StringBuilder(256);
        if (!InstanceUtils.validateCertRequestSanDnsNames(instanceAttributes, instanceDomain,
                instanceService, dnsSuffixes, null, null, false, instanceId, null)) {
            throw forbiddenError("Unable to validate certificate request DNS");
        }

        confirmation.setAttributes(attributes);
        return confirmation;
    }

    @Override
    public InstanceRegisterToken getInstanceRegisterToken(InstanceConfirmation details) {

        // ZTS Server has already verified that the caller has update
        // rights over the given service so we'll just generate
        // an instance register token and return to the client

        final String principal = InstanceUtils.getInstanceProperty(details.getAttributes(),
                InstanceProvider.ZTS_REQUEST_PRINCIPAL);
        final String instanceId = InstanceUtils.getInstanceProperty(details.getAttributes(),
                InstanceProvider.ZTS_INSTANCE_ID);
        final String tokenId = UUID.randomUUID().toString();

        // first we'll generate and sign our token

        final String registerToken = Jwts.builder()
                .setId(tokenId)
                .setSubject(ResourceUtils.serviceResourceName(details.getDomain(), details.getService()))
                .setIssuedAt(Date.from(Instant.now()))
                .setIssuer(provider)
                .setAudience(provider)
                .claim(CLAIM_PROVIDER, details.getProvider())
                .claim(CLAIM_DOMAIN, details.getDomain())
                .claim(CLAIM_SERVICE, details.getService())
                .claim(CLAIM_INSTANCE_ID, instanceId)
                .claim(CLAIM_CLIENT_ID, principal)
                .setHeaderParam(HDR_KEY_ID, keyId)
                .setHeaderParam(HDR_TOKEN_TYPE, HDR_TOKEN_JWT)
                .signWith(key, keyAlg)
                .compact();

        // finally return our token to the caller

        return new InstanceRegisterToken()
                .setProvider(details.getProvider())
                .setDomain(details.getDomain())
                .setService(details.getService())
                .setAttestationData(registerToken);
    }

    /**
     * verifies that at least one of the sanIps matches clientIp
     * @param sanIps an array of SAN IPs
     * @param clientIp the client IP address
     * @return true if sanIps is null or one of the sanIps matches. false otherwise
     */
    boolean validateSanIp(final String[] sanIps, final String clientIp) {

        LOGGER.debug("Validating sanIps: {}, clientIp: {}", sanIps, clientIp);

        // if we have an IP specified in the CSR, one of the sanIp must match our client IP
        if (sanIps == null || sanIps.length == 0) {
            return true;
        }

        if (clientIp == null || clientIp.isEmpty()) {
            return false;
        }

        // It's possible both ipv4, ipv6 addresses are mentioned in sanIP
        for (String sanIp: sanIps) {
            if (sanIp.equals(clientIp)) {
                return true;
            }
        }

        LOGGER.error("Unable to match sanIp: {} with clientIp:{}", sanIps, clientIp);
        return false;
    }

    /**
     * returns true if an empty hostname attribute is passed
     * returns true if a non-empty hostname attribute is passed and all IPs
     * passed in sanIp match the IPs that hostname resolves to.
     * returns false in all other cases
     * @param hostname host name to check against specified IPs
     * @param sanIps list of IPs to check against the specified hostname
     * @return true or false
     */
    boolean validateHostname(final String hostname, final String[] sanIps) {

        LOGGER.debug("Validating hostname: {}, sanIps: {}", hostname, sanIps);

        if (hostname == null || hostname.isEmpty()) {
            LOGGER.info("Request contains no hostname entry for validation");
            // if more than one sanIp is passed, all sanIPs must map to hostname, and hostname is a must
            if (sanIps != null && sanIps.length > 1) {
                LOGGER.error("SanIps:{} > 1, and hostname is empty", sanIps.length);
                return false;
            }
            return true;
        }

        // IP in clientIp can be NATed. Rely on sanIp, which comes from the
        // client, and is already matched with clientIp
        // sanIp should be non-empty

        if (sanIps == null || sanIps.length == 0) {
            LOGGER.error("Request contains no sanIp entry for hostname:{} validation", hostname);
            return false;
        }

        // All entries in sanIP must be one of the IPs that hostname resolves

        Set<String>  hostIps = hostnameResolver.getAllByName(hostname);
        for (String sanIp: sanIps) {
            if (!hostIps.contains(sanIp)) {
                LOGGER.error("One of sanIp: {} is not present in HostIps: {}", hostIps, sanIps);
                return false;
            }
        }

        return true;
    }

    /**
     * verifies if sanUri contains athenz://hostname/, the value matches the hostname
     * @param sanUri the SAN URI that includes athenz hostname
     * @param hostname name of the host to check against
     * @return true if there is no SAN URI or the hostname is included in it, otherwise false
     */
    boolean validateSanUri(final String sanUri, final String hostname) {

        LOGGER.debug("Validating sanUri: {}, hostname: {}", sanUri, hostname);

        if (sanUri == null || sanUri.isEmpty()) {
            LOGGER.info("Request contains no sanURI to verify");
            return true;
        }

        for (String uri: sanUri.split(",")) {
            int idx = uri.indexOf(URI_HOSTNAME_PREFIX);
            if (idx != -1) {
                if (!uri.substring(idx + URI_HOSTNAME_PREFIX.length()).equals(hostname)) {
                    LOGGER.error("SanURI: {} does not contain hostname: {}", sanUri, hostname);
                    return false;
                }
            }
        }

        return true;
    }

    boolean validateServiceToken(final String signedToken, final String domainName,
            final String serviceName, final String csrPublicKey, StringBuilder errMsg) {
        
        final PrincipalToken serviceToken = authenticate(signedToken, keyStore, csrPublicKey, errMsg);
        if (serviceToken == null) {
            return false;
        }
        
        // verify that domain and service name match
        
        if (!serviceToken.getDomain().equalsIgnoreCase(domainName)) {
            errMsg.append("validate failed: domain mismatch: ").
                append(serviceToken.getDomain()).append(" vs. ").append(domainName);
            return false;
        }
        
        if (!serviceToken.getName().equalsIgnoreCase(serviceName)) {
            errMsg.append("validate failed: service mismatch: ").
                append(serviceToken.getName()).append(" vs. ").append(serviceName);
            return false;
        }

        return true;
    }

    boolean validateRegisterToken(final String jwToken, final String domainName, final String serviceName,
                                  final String instanceId, boolean registerInstance, StringBuilder errMsg) {

        Jws<Claims> claims = Jwts.parserBuilder()
                .setSigningKeyResolver(signingKeyResolver)
                .setAllowedClockSkewSeconds(60)
                .build()
                .parseClaimsJws(jwToken);

        // verify that token audience is set for our service

        Claims claimsBody = claims.getBody();
        if (!ZTS_PROVIDER_SERVICE.equals(claimsBody.getAudience())) {
            errMsg.append("token audience is not ZTS provider: ").append(claimsBody.getAudience());
            return false;
        }

        // need to verify that the issue time is not before our expiry
        // only for register requests.

        if (registerInstance) {
            Date issueDate = claimsBody.getIssuedAt();
            if (issueDate == null || issueDate.getTime() < System.currentTimeMillis() -
                    TimeUnit.MINUTES.toMillis(expiryTime)) {
                errMsg.append("token is already expired, issued at: ").append(issueDate);
                return false;
            }
        }

        // verify provider, domain, service, and instance id values

        if (!domainName.equals(claimsBody.get(CLAIM_DOMAIN, String.class))) {
            errMsg.append("invalid domain name in token: ").append(claimsBody.get(CLAIM_DOMAIN, String.class));
            return false;
        }
        if (!serviceName.equals(claimsBody.get(CLAIM_SERVICE, String.class))) {
            errMsg.append("invalid service name in token: ").append(claimsBody.get(CLAIM_SERVICE, String.class));
            return false;
        }
        if (!instanceId.equals(claimsBody.get(CLAIM_INSTANCE_ID, String.class))) {
            errMsg.append("invalid instance id in token: ").append(claimsBody.get(CLAIM_INSTANCE_ID, String.class));
            return false;
        }
        if (!ZTS_PROVIDER_SERVICE.equals(claimsBody.get(CLAIM_PROVIDER, String.class))) {
            errMsg.append("invalid provider name in token: ").append(claimsBody.get(CLAIM_PROVIDER, String.class));
            return false;
        }

        return true;
    }

    PrincipalToken authenticate(final String signedToken, KeyStore keyStore,
            final String csrPublicKey, StringBuilder errMsg) {

        PrincipalToken serviceToken;
        try {
            serviceToken = new PrincipalToken(signedToken);
        } catch (IllegalArgumentException ex) {
            errMsg.append("authenticate failed: Invalid token: exc=").
                    append(ex.getMessage()).append(" : credential=").
                    append(Token.getUnsignedToken(signedToken));
            LOGGER.error(errMsg.toString());
            return null;
        }

        // before authenticating verify that this is not an authorized
        // service token

        if (serviceToken.getAuthorizedServices() != null) {
            errMsg.append("authenticate failed: authorized service token")
                    .append(" : credential=").append(Token.getUnsignedToken(signedToken));
            LOGGER.error(errMsg.toString());
            return null;
        }

        final String tokenDomain = serviceToken.getDomain().toLowerCase();
        final String tokenName = serviceToken.getName().toLowerCase();

        // get the public key for this token to validate signature

        final String publicKey = keyStore.getPublicKey(tokenDomain, tokenName,
                serviceToken.getKeyId());

        if (!serviceToken.validate(publicKey, 300, false, errMsg)) {
            return null;
        }

        // finally we want to make sure the public key in the csr
        // matches the public key registered in Athenz

        if (!validatePublicKeys(publicKey, csrPublicKey)) {
            errMsg.append("CSR and Athenz public key mismatch");
            LOGGER.error(errMsg.toString());
            return null;
        }

        return serviceToken;
    }

    public boolean validatePublicKeys(final String athenzPublicKey, final String csrPublicKey) {

        // we are going to remove all whitespace, new lines
        // in order to compare the pem encoded keys

        Matcher matcher = WHITESPACE_PATTERN.matcher(athenzPublicKey);
        final String normAthenzPublicKey = matcher.replaceAll("");

        matcher = WHITESPACE_PATTERN.matcher(csrPublicKey);
        final String normCsrPublicKey = matcher.replaceAll("");

        return normAthenzPublicKey.equals(normCsrPublicKey);
    }
}
