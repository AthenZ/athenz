/**
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.yahoo.rdl.Timestamp;

public class ZTSClientMock extends ZTSRDLGeneratedClient implements java.io.Closeable {

    public ZTSClientMock() {
        super("http://localhost:4080/");
    }
    
    public ZTSClientMock(String url) {
        super(url);
    }

    private long sleepInterval = 60;
    private int expiryTime    = 2400;
    private String roleName   = null;
    private String policyName = null;
    private List<String> tenantDomains = null;

    Map<String, AWSTemporaryCredentials> credsMap = new HashMap<>();
    
    private Map<String, Long> lastRoleTokenFetchedTime = new HashMap<String, Long>();
    
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
        if (hostName == "not.exist.host") {
            throw new ResourceException(404, "hostname not found");
        }
        
        HostServices hostServices = new HostServices().setHost(hostName)
                .setNames(Arrays.asList("service1", "service2"));
        return hostServices;
    }

    @Override
    public PublicKeyEntry getPublicKeyEntry(String domainName, String serviceName,
            String keyId) {
        if (domainName == "invalid.domain") {
            throw new ResourceException(404, "invalid domain");
        }
        
        PublicKeyEntry publicKeyEntry = new PublicKeyEntry().setId(keyId).setKey("test-key");
        return publicKeyEntry;
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
    public ServiceIdentity getServiceIdentity(String domainName, String serviceName) {
        if (domainName == "unknown.domain") {
            throw new ResourceException(404, "Domain not found");
        }
        
        ServiceIdentity serviceIdentity = new ServiceIdentity().setName(serviceName);
        
        return serviceIdentity;
    }

    @Override
    public ServiceIdentityList getServiceIdentityList(String domainName) {
        if (domainName == "unknown.domain") {
            throw new ResourceException(404, "Domain not found");
        }
        
        ServiceIdentityList serviceIdentityList = new ServiceIdentityList().setNames(Arrays.asList("storage"));
        
        return serviceIdentityList;
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
    public AWSTemporaryCredentials getAWSTemporaryCredentials(String domainName, String roleName) {
        
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
    public Identity postAWSCertificateRequest(String domain, String service, AWSCertificateRequest req) {
        return null;
    }

    @Override
    public Identity postInstanceInformation(InstanceInformation info) {
        return null;
    }

    @Override
    public Identity postAWSInstanceInformation(AWSInstanceInformation info) {
        return null;
    }

    @Override
    public Identity postInstanceRefreshRequest(String domain, String service, InstanceRefreshRequest req) {
        if (domain.equals("exc")) {
            throw new ResourceException(400, "Invalid request");
        }
        Identity identity = new Identity().setName(domain + "." + service)
            .setServiceToken("v=S1;d=" + domain + ";n=" + service + ";k=zts.dev;z=zts;o=athenz.svc;t=1234;e=1235;s=sig");
        return identity;
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
    public DomainMetrics postDomainMetrics(String domainName, DomainMetrics req) {
        if (domainName.equals("exc")) {
            throw new ResourceException(400, "Invalid request");
        }
        return null;
    }
}
