/*
 * Copyright 2016 Yahoo Inc.
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
    private boolean jwkFailure = false;

    Map<String, AWSTemporaryCredentials> credsMap = new HashMap<>();
    
    private Map<String, Long> lastRoleTokenFetchedTime = new HashMap<>();
    
    static String getKey(String domain, String roleName, String proxyForPrincipal) {
        return domain + "-" + roleName + "-" + proxyForPrincipal;
    }
    
    long getLastRoleTokenFetchedTime(String domain, String roleName) {
        return getLastRoleTokenFetchedTime(domain, roleName, null);
    }
    
    long getLastRoleTokenFetchedTime(String domain, String roleName, String proxyForPrincipal) {
        String key = getKey(domain, roleName, proxyForPrincipal);
        if (lastRoleTokenFetchedTime.containsKey(key)) {
            return lastRoleTokenFetchedTime.get(key);
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

    public void setJwkFailure(boolean jwkFailure) {
        this.jwkFailure = jwkFailure;
    }

    @Override
    public JWKList getJWKList() {

        if (jwkFailure) {
            throw new ResourceException(500, "unable to retrieve jwk list");
        }

        JWKList jwkList = new JWKList();
        List<JWK> list = new ArrayList<>();
        list.add(new JWK().setKid("id1").setKty("RSA").setN("n").setE("e"));
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

        if (request.equals("grant_type=client_credentials&expires_in=3600&scope=coretech%3Adomain")) {
            tokenResponse.setScope("coretech:role.role1");
        } else if (request.equals("grant_type=client_credentials&expires_in=3600&scope=coretech%3Arole.role1")) {
            tokenResponse.setScope("coretech:role.role1");
        } else if (request.equals("grant_type=client_credentials&expires_in=3600&scope=coretech%3Adomain+openid+coretech%3Aservice.backend")) {
            tokenResponse.setScope("coretech:role.role1");
            tokenResponse.setId_token("idtoken");
        } else if (request.equals("grant_type=client_credentials&expires_in=500&scope=resourceexception%3Adomain")) {
            throw new ResourceException(400, "Unable to get access token");
        } else if (request.equals("grant_type=client_credentials&expires_in=500&scope=exception%3Adomain")) {
            throw new IllegalArgumentException("Unable to get access token");
        } else {
            throw new ResourceException(404, "domain not found");
        }
        return tokenResponse;
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
        
        if (credsMap.isEmpty()) {
            throw new ZTSClientException(ZTSClientException.NOT_FOUND, "role is not assumed");
        }
        String key = domainName + ":" + roleName;
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
            throw new ResourceException(400, "Invalid request");
        } if (roleName.equals("no-role")) {
            throw new ResourceException(403, "Forbidden");
        }
        return new RoleToken().setToken("x509cert");
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
    public DomainMetrics postDomainMetrics(String domainName, DomainMetrics req) {
        if (domainName.equals("exc")) {
            throw new ResourceException(400, "Invalid request");
        }
        return null;
    }
}
