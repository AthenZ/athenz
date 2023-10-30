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
package com.yahoo.athenz.zts;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.*;

import com.yahoo.rdl.Timestamp;

public class ZTSRDLClientMock extends ZTSRDLGeneratedClient implements java.io.Closeable {

    public ZTSRDLClientMock() {
        super("http://localhost:4080/");
    }
    
    public ZTSRDLClientMock(String url) {
        super(url);
    }

    private long sleepInterval = 60;
    private int expiryTime    = 2400;
    private String roleName   = null;
    private String policyName = null;
    private List<String> tenantDomains = null;
    private int jwkExcCode = 0;
    private int requestCount = 0;
    private int openIDConfigExcCode = 0;

    Map<String, AWSTemporaryCredentials> credsMap = new HashMap<>();

    private final Map<String, Long> lastRoleTokenFetchedTime = new HashMap<>();
    private final Map<String, Long> lastAccessTokenFetchedTime = new HashMap<>();
    private final Map<String, Long> lastRoleTokenFailTime = new HashMap<>();
    private final Map<String, Long> lastIdTokenFetchedTime = new HashMap<>();

    static String getKey(String domain, String roleName, String proxyForPrincipal) {
        return domain + "-" + roleName + "-" + proxyForPrincipal;
    }
    
    long getLastRoleTokenFetchedTime(String domain, String roleName) {
        return getLastRoleTokenFetchedTime(domain, roleName, null);
    }

    long getLastAccessTokenFetchedTime(String domain, String roleName) {
        return getLastAccessTokenFetchedTime(domain, roleName, null);
    }

    long getLastRoleTokenFetchedTime(String domain, String roleName, String proxyForPrincipal) {
        String key = getKey(domain, roleName, proxyForPrincipal);
        if (lastRoleTokenFetchedTime.containsKey(key)) {
            return lastRoleTokenFetchedTime.get(key);
        }
        return -1;
    }

    long getLastTokenFailTime(String domain, String roleName) {
        String key = domain + ":" + roleName;
        if (lastRoleTokenFailTime.containsKey(key)) {
            return lastRoleTokenFailTime.get(key);
        }
        return -1L;
    }

    long getLastAccessTokenFetchedTime(String domain, String roleName, String proxyForPrincipal) {
        String key = getKey(domain, roleName, proxyForPrincipal);
        if (lastAccessTokenFetchedTime.containsKey(key)) {
            return lastAccessTokenFetchedTime.get(key);
        }
        return -1;
    }

    long getLastIdTokenFetchedTime(final String scope) {
        if (lastIdTokenFetchedTime.containsKey(scope)) {
            return lastIdTokenFetchedTime.get(scope);
        }
        return -1;
    }

    public void setTestSleepInterval(long intervalSecs) {
        sleepInterval = intervalSecs;
    }
    
    @Override
    public HostServices getHostServices(String hostName) {
        if (hostName.equals("not.exist.host")) {
            throw new ResourceException(404, "hostname not found");
        }

        return new HostServices().setHost(hostName)
                .setNames(Arrays.asList("service1", "service2"));
    }

    public void setJwkFailure(int jwkExcCode) {
        this.jwkExcCode = jwkExcCode;
    }

    @Override
    public JWKList getJWKList(Boolean rfc) {

        if (jwkExcCode != 0) {
            if (jwkExcCode < 500) {
                throw new ResourceException(jwkExcCode, "unable to retrieve jwk list");
            } else {
                throw new IllegalArgumentException();
            }
        }

        JWKList jwkList = new JWKList();
        List<JWK> list = new ArrayList<>();
        if (rfc) {
            list.add(new JWK().setKid("id1").setKty("EC").setX("x").setY("y").setCrv("P-256"));
        } else {
            list.add(new JWK().setKid("id1").setKty("RSA").setN("n").setE("e"));
        }
        jwkList.setKeys(list);

        return jwkList;
    }

    @Override
    public PublicKeyEntry getPublicKeyEntry(String domainName, String serviceName,
            String keyId) {
        if (domainName.equals("invalid.domain")) {
            throw new ResourceException(404, "invalid domain");
        }

        return new PublicKeyEntry().setId(keyId).setKey("test-key");
    }
    
    @Override
    public RoleAccess getRoleAccess(String domainName, String principal) {
        if (domainName.equals("exc")) {
            throw new ResourceException(400, "Invalid request");
        } else if (domainName.equals("unknown")) {
            throw new ResourceException(404, "Unknown domain");
        }
        RoleAccess roleAccess = new RoleAccess();
        ArrayList<String> roles = new ArrayList<>();
        roles.add("role1");
        roles.add("role2");
        roleAccess.setRoles(roles);
        return roleAccess;
    }
    
    @Override
    public RoleToken getRoleToken(String domainName, String rName,
            Integer minExpiryTime, Integer maxExpiryTime, String proxyForPrincipal) {
        
        if (rName != null && !roleName.endsWith(rName)) {
            throw new ResourceException(403, "No access to any roles");
        }

        // calculate expiry time based on test domain name
        long expireWindow = expiryTime;
        if (domainName.equals("providerdomain")) {
            expireWindow = sleepInterval + 10;
        }
        
        List<String> roles = new ArrayList<>();
        roles.add(roleName);
        com.yahoo.athenz.auth.token.RoleToken token =
                new com.yahoo.athenz.auth.token.RoleToken.Builder("Z1", domainName, roles)
                    .expirationWindow(expireWindow).keyId("0").proxyUser(proxyForPrincipal).build();
        RoleToken roleToken = new RoleToken();
        roleToken.setToken(token.getUnsignedToken());
        roleToken.setExpiryTime(token.getExpiryTime());
        String key = getKey(domainName, rName, proxyForPrincipal);
        long lastUpdatedTime = System.currentTimeMillis();
        lastRoleTokenFetchedTime.put(key, lastUpdatedTime);
        return roleToken;
    }

    @Override
    public AccessTokenResponse postAccessTokenRequest(String request) {

        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setExpires_in(3600);
        tokenResponse.setAccess_token("accesstoken");
        tokenResponse.setToken_type("Bearer");

        switch (request) {
            case "grant_type=client_credentials&expires_in=3600&scope=coretech%3Adomain":
            case "grant_type=client_credentials&expires_in=3600&scope=coretech%3Arole.role1":
                tokenResponse.setScope("coretech:role.role1");
                break;
            case "grant_type=client_credentials&expires_in=8&scope=coretech%3Adomain":
                tokenResponse.setScope("coretech:role.role1");
                tokenResponse.setExpires_in(8);
                break;
            case "grant_type=client_credentials&expires_in=3600&scope=coretech2%3Adomain":
                tokenResponse.setScope("coretech2:role.role1");
                break;
            case "grant_type=client_credentials&expires_in=8&scope=coretech2%3Adomain":
                tokenResponse.setScope("coretech2:role.role1");
                tokenResponse.setExpires_in(8);
                break;
            case "grant_type=client_credentials&expires_in=3600&scope=coretech%3Adomain+openid+coretech%3Aservice.backend":
                tokenResponse.setScope("coretech:role.role1");
                tokenResponse.setId_token("idtoken");
                break;
            case "grant_type=client_credentials&expires_in=3600&scope=coretech%3Arole.role1&authorization_details=%5B%7B%22type%22%3A%22message_access%22%2C%22location%22%3A%5B%22https%3A%2F%2Flocation1%22%2C%22https%3A%2F%2Flocation2%22%5D%2C%22identifier%22%3A%22id1%22%7D%5D":
                tokenResponse.setAccess_token("accesstoken-authz-details");
                tokenResponse.setExpires_in(3600 + requestCount);
                break;
            case "grant_type=client_credentials&expires_in=500&scope=resourceexception%3Adomain":
                throw new ResourceException(400, "Unable to get access token");
            case "grant_type=client_credentials&expires_in=500&scope=exception%3Adomain":
                throw new IllegalArgumentException("Unable to get access token");
            default:
                throw new ResourceException(404, "domain not found");
        }

        int idxScope = request.indexOf("scope=");
        if (idxScope != -1) {
            int domainScope = request.indexOf("%3Adomain", idxScope);
            if (domainScope != -1) {
                final String domainName = request.substring(idxScope + 6, domainScope);
                String key = getKey(domainName, null, null);
                lastAccessTokenFetchedTime.put(key, System.currentTimeMillis());
            }
        }

        requestCount += 1;
        return tokenResponse;
    }

    @Override
    public OIDCResponse getOIDCResponse(String responseType, String clientId, String redirectUri, String scope,
            String state, String nonce, String keyType, Boolean fullArn, Integer expiryTime,
            String output, Boolean roleInAudClaim, Map<String, List<String>> headers)
            throws URISyntaxException, IOException {

        // some exception test cases based on the state value
        if (state != null) {
            switch (state) {
                case "zts-403":
                    throw new ResourceException(403, "forbidden request");
                case "zts-500":
                    throw new IllegalArgumentException("invalid arguments", null);
            }
        }

        // process our request, generate a token and return

        if (expiryTime == null) {
            expiryTime = 3600;
        }
        String token = AccessTokenTestFileHelper.getSignedAccessToken(expiryTime);
        OIDCResponse oidcResponse = new OIDCResponse()
                .setExpiration_time(System.currentTimeMillis() / 1000 + expiryTime)
                .setVersion(1)
                .setSuccess(true)
                .setToken_type("urn:ietf:params:oauth:token-type:id_token")
                .setId_token(token);
        lastIdTokenFetchedTime.put(scope, System.currentTimeMillis());

        return oidcResponse;
    }

    @Override
    public ServiceIdentity getServiceIdentity(String domainName, String serviceName) {
        if (domainName.equals("unknown.domain")) {
            throw new ResourceException(404, "Domain not found");
        }

        return new ServiceIdentity().setName(serviceName);
    }

    @Override
    public ServiceIdentityList getServiceIdentityList(String domainName) {
        if (domainName.equals("unknown.domain")) {
            throw new ResourceException(404, "Domain not found");
        }

        return new ServiceIdentityList().setNames(Collections.singletonList("storage"));
    }

    @Override
    public RoleAccess getRolesRequireRoleCert(String principal) {
        if (principal.equals("unknown.service")) {
            throw new ResourceException(404, "Service not found");
        } else if (principal.equals("error.service")) {
            throw new RuntimeException("Unknown exception");
        }
        List<String> roles = new ArrayList<>();
        roles.add("role1");
        RoleAccess roleList = new RoleAccess();
        roleList.setRoles(roles);
        return roleList;
    }
    
    public void setAwsCreds(Timestamp expiration, String domainName, String roleName) {
        String key = domainName + ":" + roleName;
        setAwsCreds(expiration, domainName, roleName, key + "session", key + "secret", key + "keyid");
    }
    
    public void setAwsCreds(Timestamp expiration, String domainName, String roleName,
            String sessToken, String secretKey, String accessKeyId) {

        AWSTemporaryCredentials awsCreds = new AWSTemporaryCredentials();
        String key = domainName + ":" + roleName;
        awsCreds.setExpiration(expiration).setSessionToken(sessToken).
            setSecretAccessKey(secretKey).setAccessKeyId(accessKeyId);

        credsMap.put(key, awsCreds);
    }
    
    @Override
    public AWSTemporaryCredentials getAWSTemporaryCredentials(String domainName, String roleName,
            Integer durationSeconds, String externalId) {

        String key = domainName + ":" + roleName;
        if (credsMap.isEmpty()) {
            lastRoleTokenFailTime.put(key, System.currentTimeMillis());
            throw new ZTSClientException(ResourceException.NOT_FOUND, "role is not assumed");
        } else {
            lastRoleTokenFailTime.put(key, -1L);
        }
        AWSTemporaryCredentials creds = credsMap.get(key);
        if (creds == null) {
            return null;
        }
        
        // calculate expiry time based on test domain name
        long expireWindow = expiryTime;
        if (domainName.equals("providerdomain")) {
            expireWindow = sleepInterval + 10;
        }
        long expiration = System.currentTimeMillis() + (expireWindow * 1000);
        String sessToken = Long.toString(expiration);
        String oldSessToken = creds.getSessionToken();
        String keyid        = creds.getAccessKeyId();
        String secret       = creds.getSecretAccessKey();
        
        creds = new AWSTemporaryCredentials();
        creds.setExpiration(Timestamp.fromMillis(expiration));
        creds.setAccessKeyId(keyid);
        creds.setSecretAccessKey(secret);
        
        String []split = oldSessToken.split(":");
        creds.setSessionToken(split[0] + ":" + sessToken);
        
        key = getKey(domainName, roleName, null);
        credsMap.put(key, creds);
        long lastUpdatedTime = System.currentTimeMillis();
        lastRoleTokenFetchedTime.put(key, lastUpdatedTime);
              
        return creds;
    }
    
    @Override
    public DomainSignedPolicyData getDomainSignedPolicyData(String domainName, String matchingTag,
            Map<String, List<String>> responseHeaders) {
        if (policyName == null) {
            return null;
        } else if (domainName == null) {
            throw new ResourceException(400, "Invalid request");
        }
        
        Policy policy = new Policy();
        policy.setName(policyName);
        
        List<Policy> policyList = new ArrayList<>();
        policyList.add(policy);
        
        PolicyData policyData = new PolicyData();
        policyData.setDomain(domainName);
        policyData.setPolicies(policyList);
        
        SignedPolicyData signedPolicyData = new SignedPolicyData();
        signedPolicyData.setZmsSignature("zmsSignature");
        signedPolicyData.setZmsKeyId("0");
        signedPolicyData.setPolicyData(policyData);
        signedPolicyData.setExpires(Timestamp.fromMillis(System.currentTimeMillis()));
        signedPolicyData.setModified(Timestamp.fromMillis(System.currentTimeMillis()));
        
        DomainSignedPolicyData domSignedPolicyData = new DomainSignedPolicyData();
        domSignedPolicyData.setKeyId("0");
        domSignedPolicyData.setSignature("signature");
        domSignedPolicyData.setSignedPolicyData(signedPolicyData);
        
        return domSignedPolicyData;
    }

    @Override
    public JWSPolicyData postSignedPolicyRequest(String domainName, SignedPolicyRequest request, String matchingTag, Map<String, List<String>> responseHeaders) {

        if ("invalid-domain".equals(domainName)) {
            throw new ResourceException(404, "not found domain");
        } else if (domainName == null) {
            throw new IllegalArgumentException("Invalid request");
        }

        JWSPolicyData jwsPolicyData = new JWSPolicyData();
        jwsPolicyData.setSignature("signature");
        jwsPolicyData.setPayload("payload");
        jwsPolicyData.setPayload("protected-header");
        Map<String, String> headers = new HashMap<>();
        headers.put("kid", "0");
        jwsPolicyData.setHeader(headers);

        return jwsPolicyData;
    }

    @Override
    public TenantDomains getTenantDomains(String providerDomainName, String userName,
            String roleName, String serviceName) {
        if (providerDomainName.equals("exc")) {
            throw new ResourceException(400, "Invalid request");
        } else if (providerDomainName.equals("unknown")) {
            throw new ResourceException(404, "Unknown domain");
        }
        
        TenantDomains doms = new TenantDomains();
        doms.setTenantDomainNames(tenantDomains);
        return doms;
    }

    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }

    public String getPolicyName() {
        return policyName;
    }

    public void setPolicyName(String policyName) {
        this.policyName = policyName;
    }
    
    public int getExpiryTime() {
        return expiryTime;
    }

    public void setExpiryTime(int expiryTime) {
        this.expiryTime = expiryTime;
    }
    
    public void setTenantDomains(List<String> tenantDomains) {
        this.tenantDomains = tenantDomains;
    }

    @Override
    public InstanceIdentity postInstanceRegisterInformation(InstanceRegisterInformation info,
            Map<String, List<String>> headers) {

        if (!info.getAttestationData().equals("good-instance-document")) {
            throw new ResourceException(400, "Invalid request");
        }
        return new InstanceIdentity().setProvider("provider")
                .setName(info.getDomain() + "." + info.getService())
                .setX509Certificate("x509");
    }
    
    @Override
    public InstanceIdentity postInstanceRefreshInformation(String provider, String domain,
            String service, String instanceId, InstanceRefreshInformation info) {
        
        if (!info.getCsr().equals("good-x509-csr")) {
            throw new ResourceException(400, "Invalid request");
        }
        return new InstanceIdentity().setProvider(provider)
                .setName(domain + "." + service).setX509Certificate("x509");
    }
    
    @Override
    public InstanceIdentity deleteInstanceIdentity(String provider, String domain, String service,
            String instanceId) {
        
        if (instanceId.startsWith("bad")) {
            throw new ResourceException(400, "Invalid delete request");
        }
        return new InstanceIdentity();
    }
    
    @Override
    public Identity postInstanceRefreshRequest(String domain, String service, InstanceRefreshRequest req) {
        if (domain.equals("exc")) {
            throw new ResourceException(400, "Invalid request");
        }
        return new Identity().setName(domain + "." + service)
            .setServiceToken("v=S1;d=" + domain + ";n=" + service + ";k=zts.dev;z=zts;o=athenz.svc;t=1234;e=1235;s=sig");
    }

    @Override
    public RoleToken postRoleCertificateRequest(String domainName, String roleName, RoleCertificateRequest req) {
        if (domainName.equals("exc")) {
            throw new IllegalArgumentException();
        } if (roleName.equals("no-role")) {
            throw new ResourceException(403, "Forbidden");
        }
        return new RoleToken().setToken("x509cert");
    }

    @Override
    public RoleCertificate postRoleCertificateRequestExt(RoleCertificateRequest req) {
        if (req.getCsr().contains("exc")) {
            throw new IllegalArgumentException();
        } if (req.getCsr().contains("no-role")) {
            throw new ResourceException(403, "Forbidden");
        }
        return new RoleCertificate().setX509Certificate("x509cert");
    }

    @Override
    public Access getAccess(String domainName, String roleName, String principal) {
        if (domainName.equals("exc")) {
            throw new ResourceException(400, "Invalid request");
        }
        Access access = new Access();
        access.setGranted(roleName.equals("match"));
        return access;
    }

    @Override
    public ResourceAccess getResourceAccess(String action, String resource,
            String trustDomain, String principal) {
        if (action.equals("exc")) {
            throw new ResourceException(400, "Invalid request");
        }
        ResourceAccess access = new ResourceAccess();
        access.setGranted(action.equals("access") && resource.equals("resource"));
        return access;
    }

    @Override
    public ResourceAccess getResourceAccessExt(String action, String resource,
                                            String trustDomain, String principal) {
        if (action.equals("exc")) {
            throw new ResourceException(400, "Invalid request");
        }
        ResourceAccess access = new ResourceAccess();
        access.setGranted(action.equals("access") && resource.equals("resource") && principal.equals("principal"));
        return access;
    }

    @Override
    public CertificateAuthorityBundle getCertificateAuthorityBundle(String bundleName) {
        if (bundleName.equals("exc")) {
            throw new NullPointerException("Invalid request");
        }
        if (bundleName.equals("system")) {
            throw new ResourceException(404, "Unknown bundle name");
        }
        CertificateAuthorityBundle bundle = new CertificateAuthorityBundle();
        bundle.setName(bundleName);
        bundle.setCerts("certs");
        return bundle;
    }

    @Override
    public Workloads getWorkloadsByService(String domainName, String serviceName) {
        if ("bad-domain".equals(domainName)) {
            throw new ResourceException(404, "unknown domain");
        }
        Workload wl = new Workload().setProvider("openstack").setIpAddresses(Collections.singletonList("10.0.0.1"))
                .setUuid("avve-resw").setUpdateTime(Timestamp.fromMillis(System.currentTimeMillis()));
        return new Workloads().setWorkloadList(Collections.singletonList(wl));
    }

    @Override
    public Workloads getWorkloadsByIP(String ip) {
        if ("127.0.0.1".equals(ip)) {
            throw new ResourceException(404, "unknown ip");
        }
        Workload wl = new Workload().setProvider("openstack").setDomainName("athenz").setServiceName("api")
                .setUuid("avve-resw").setUpdateTime(Timestamp.fromMillis(System.currentTimeMillis()));
        return new Workloads().setWorkloadList(Collections.singletonList(wl));
    }

    @Override
    public TransportRules getTransportRules(String domainName, String serviceName) {
        TransportRule tr;
        TransportRules transportRules = null;
        switch (domainName) {
            case "bad-domain":
                throw new ResourceException(404, "unknown domain");
            case "ingress-domain":
                tr = new TransportRule().setEndPoint("10.0.0.1/26").setPort(4443).setProtocol("TCP")
                        .setSourcePortRange("1024-65535");
                transportRules = new TransportRules();
                transportRules.setIngressRules(Collections.singletonList(tr));
                break;
            case "egress-domain":
                tr = new TransportRule().setEndPoint("10.0.0.1/23").setPort(8443).setProtocol("TCP")
                        .setSourcePortRange("1024-65535");
                transportRules = new TransportRules();
                transportRules.setEgressRules(Collections.singletonList(tr));
                break;
        }

        return transportRules;
    }

    @Override
    public InstanceRegisterToken getInstanceRegisterToken(String provider, String domain, String service, String instanceId) {

        if ("coretech".equals(domain)) {
            return new InstanceRegisterToken().setProvider(provider).setDomain(domain)
                    .setService(service).setAttestationData("token");
        } else if ("bad-domain".equals(domain)) {
            throw new ResourceException(ResourceException.NOT_FOUND, "unknown domain");
        } else {
            throw new IllegalArgumentException();
        }
    }

    public void setOpenIDConfigFailure(int excCode) {
        this.openIDConfigExcCode = excCode;
    }

    @Override
    public OpenIDConfig getOpenIDConfig() {

        if (openIDConfigExcCode != 0) {
            if (openIDConfigExcCode < 500) {
                throw new ResourceException(openIDConfigExcCode, "unable to retrieve openid config");
            } else {
                throw new IllegalArgumentException();
            }
        }

        OpenIDConfig openIDConfig = new OpenIDConfig();
        openIDConfig.setIssuer("https://athenz.cloud");
        openIDConfig.setJwks_uri("https://athenz.cloud/oauth2/keys");
        openIDConfig.setAuthorization_endpoint("https://athenz.cloud/access");
        openIDConfig.setSubject_types_supported(Collections.singletonList("public"));
        openIDConfig.setResponse_types_supported(Collections.singletonList("id_token"));
        openIDConfig.setId_token_signing_alg_values_supported(Collections.singletonList("RS256"));
        return openIDConfig;
    }
}
