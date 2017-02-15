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
package com.yahoo.athenz.zms;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.Closeable;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Map;
import java.util.List;
import java.util.Date;

import org.glassfish.jersey.client.ClientProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.common.config.AthenzConfig;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Timestamp;

public class ZMSClient implements Closeable {

    private String zmsUrl = null;
    private Principal principal = null;
    private boolean principalCheckDone = false;
    protected ZMSRDLGeneratedClient client = null;
    
    private static final String STR_ENV_ROOT = "ROOT";
    private static final String STR_DEF_ROOT = "/home/athenz";
    private static final String HTTP_RFC1123_DATE_FORMAT = "EEE, d MMM yyyy HH:mm:ss zzz";
    
    public static final String ZMS_CLIENT_PROP_ATHENZ_CONF     = "athenz.athenz_conf";
    public static final String ZMS_CLIENT_PROP_READ_TIMEOUT    = "athenz.zms.client.read_timeout";
    public static final String ZMS_CLIENT_PROP_CONNECT_TIMEOUT = "athenz.zms.client.connect_timeout";

    private static final Logger LOGGER = LoggerFactory.getLogger(ZMSClient.class);
    private static final Authority PRINCIPAL_AUTHORITY = new com.yahoo.athenz.auth.impl.PrincipalAuthority();
    
    /**
     * Constructs a new ZMSClient object with media type set to application/json.
     * The url for ZMS Server is automatically retrieved from the athenz_config
     * package's configuration file (zms_url field). The client can only be used
     * to retrieve objects from ZMS that do not require any authentication
     * otherwise addCredentials method must be used to set the principal identity.
     * Default read and connect timeout values are 30000ms (30sec). The application can
     * change these values by using the yahoo.zms_java_client.read_timeout and
     * yahoo.zms_java_client.connect_timeout system properties. The values specified
     * for timeouts must be in milliseconds.
     */
    public ZMSClient() {
        initClient(null);
    }
    
    /**
     * Constructs a new ZMSClient object with the given ZMS Server url and
     * media type set to application/json. The client can only be used
     * to retrieve objects from ZMS that do not require any authentication
     * otherwise addCredentials method must be used to set the principal identity.
     * Default read and connect timeout values are 30000ms (30sec). The application can
     * change these values by using the yahoo.zms_java_client.read_timeout and
     * yahoo.zms_java_client.connect_timeout system properties. The values specified
     * for timeouts must be in milliseconds.
     * @param url ZMS Server url (e.g. https://server1.athenzcompany.com:4443/zms/v1)
     */
    public ZMSClient(String url) {
        initClient(url);
    }
    
    /**
     * Close the ZMSClient object and release any allocated resources.
     */
    public void close() {
        client.close();
    }

    public void setZMSRDLGeneratedClient(ZMSRDLGeneratedClient client) {
        this.client = client;
    }
    
    /**
     * Sets or overrides the current principal identity set in the client.
     * @param identity Principal identity for authenticating requests
     * @return self ZMSClient object
     */
    public ZMSClient addCredentials(Principal identity) {
        
        // make sure the principal has proper authority assigned
        
        if (identity == null || identity.getAuthority() == null) {
            throw new IllegalArgumentException("Principal must be valid object with authority field");
        }
        
        // if we already have a principal set, we're going to
        // clear our credentials first
        
        if (principal != null) {
            client.addCredentials(principal.getAuthority().getHeader(), null);
        }
        
        // now we're going to update our principal and set credentials
        
        principal = identity;
        principalCheckDone = false;
        
        final Authority authority = principal.getAuthority();
        if (authority != null) {
            client.addCredentials(authority.getHeader(), principal.getCredentials());
        
            // finally check if we this is a principal token required by ZMS

            principalCheckDone = (authority instanceof PrincipalAuthority);
        }
        
        return this;
    }
    
    /**
     * Clear the principal identity set for the client. Unless a new principal is set
     * using the addCredentials method, the client can only be used to requests data
     * from the ZMS Server that doesn't require any authentication.
     * @return self ZMSClient object
     */
    public ZMSClient clearCredentials() {
        if (principal != null) {
            client.addCredentials(principal.getAuthority().getHeader(), null);
            principal = null;
            principalCheckDone = true;
        }
        return this;
    }
    
    /**
     * If the current principal is the user principal then request
     * a UserToken from ZMS and set the UserToken as the principal
     * identity for authentication.
     */
    private void updatePrincipal() {

        /* if the check has already been done then we have nothing to do */
        
        if (principalCheckDone) {
            return;
        }
        
        /* make sure we have a principal specified */
        
        if (principal == null) {
            principalCheckDone = true;
            return;
        }
        
        /* so at this point we have some credentials specified
         * but it's not the principal authority so we're going
         * to ask ZMS to return a UserToken for us.
         */

        String userName = principal.getName();
        long issueTime = principal.getIssueTime();
        UserToken userToken = getUserToken(userName);

        PrincipalToken principalToken = new PrincipalToken(userToken.getToken());
        Principal identity = SimplePrincipal.create(principalToken.getDomain(),
                principalToken.getName(), userToken.getToken(), issueTime,
                PRINCIPAL_AUTHORITY);
        clearCredentials();
        addCredentials(identity);
    }

    String lookupZMSUrl() {
        
        String rootDir = System.getenv(STR_ENV_ROOT);
        if (rootDir == null) {
            rootDir = STR_DEF_ROOT;
        }
        
        String confFileName = System.getProperty(ZMS_CLIENT_PROP_ATHENZ_CONF,
                rootDir + "/conf/athenz/athenz.conf");
        String url = null;
        try {
            Path path = Paths.get(confFileName);
            AthenzConfig conf = JSON.fromBytes(Files.readAllBytes(path), AthenzConfig.class);
            url = conf.getZmsUrl();
        } catch (Exception ex) {
            LOGGER.error("Unable to extract ZMS Url from {} exc: {}",
                    confFileName, ex.getMessage());
        }
        
        return url;
    }
    /**
     * Initialize the client for class constructors
     * @param url ZMS Server url
     * @param identity Principal identity for authentication
     * @param mediaType media type for http content type
     */
    private void initClient(String url) {

        /* if we have no url specified then we're going to retrieve
         * the value from our configuration package */
        
        if (url == null) {
            zmsUrl = lookupZMSUrl();
        } else {
            zmsUrl = url;
        }
        
        /* verify if the url is ending with /zms/v1 and if it's
         * not we'll automatically append it */
        
        if (zmsUrl != null && !zmsUrl.isEmpty()) {
            if (!zmsUrl.endsWith("/zms/v1")) {
                if (zmsUrl.charAt(zmsUrl.length() - 1) != '/') {
                    zmsUrl += '/';
                }
                zmsUrl += "zms/v1";
            }
        }
        
        /* determine our read and connect timeouts */
        
        int readTimeout = Integer.parseInt(System.getProperty(ZMS_CLIENT_PROP_READ_TIMEOUT, "30000"));
        int connectTimeout = Integer.parseInt(System.getProperty(ZMS_CLIENT_PROP_CONNECT_TIMEOUT, "30000"));

        /* if we are not given a url then use the default value */
 
        client = new ZMSRDLGeneratedClient(zmsUrl)
            .setProperty(ClientProperties.CONNECT_TIMEOUT, connectTimeout)
            .setProperty(ClientProperties.READ_TIMEOUT, readTimeout);
    }
    
    public String getZmsUrl() {
        return zmsUrl;
    }
    
    /**
     * Generate a role name as expected by ZMS Server can be used to
     * set the role object's name field (e.g. role.setName(name))
     * @param domain name of the domain
     * @param role name of the role
     * @return full role name
     */
    public String generateRoleName(String domain, String role) {
        StringBuilder str = new StringBuilder(256);
        str.append(domain);
        str.append(":role.");
        str.append(role);
        return str.toString();
    }

    /**
     * Generate a policy name as expected by ZMS Server can be used to
     * set the policy object's name field (e.g. policy.setName(name))
     * @param domain name of the domain
     * @param policy name of the policy
     * @return full policy name
     */
    public String generatePolicyName(String domain, String policy) {
        StringBuilder str = new StringBuilder(256);
        str.append(domain);
        str.append(":policy.");
        str.append(policy);
        return str.toString();
    }

    /**
     * Generate a service name as expected by ZMS Server can be used to
     * set the service identity object's name field 
     * (e.g. serviceIdentity.setName(name))
     * @param domain name of the domain
     * @param service name of the service
     * @return full service identity name
     */
    public String generateServiceIdentityName(String domain, String service) {
        StringBuilder str = new StringBuilder(256);
        str.append(domain);
        str.append(".");
        str.append(service);
        return str.toString();
    }

    /**
     * Retrieve the specified domain object
     * @param domain name of the domain to be retrieved
     * @return Domain object or ZMSClientException will be thrown in case of failure
     */
    public Domain getDomain(String domain) {
        updatePrincipal();
        try {
            return client.getDomain(domain);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of domains provisioned on the ZMS Server
     * @return list of Domains or ZMSClientException will be thrown in case of failure
     */
    public DomainList getDomainList() {
        return getDomainList(null, null, null, null, null, null, null);
    }
    
    /**
     * Retrieve the list of domains provisioned on the ZMS Server
     * filters based on the specified arguments
     * @param limit number of domain objects to return
     * @param skip exclude all the domains including the specified one from the return set
     * @param prefix return domains starting with this value
     * @param depth maximum depth of the domain (0 - top level domains only)
     * @param account return domain that has the specified account name. If account name
     *        is specified all other optional attributes are ignored since there must be
     *        only one domain matching the specified account name.
     * @param productId return domain that has the specified product id. If product id
     *        is specified all other optional attributes are ignored since there must be
     *        only one domain matching the specified product id.
     * @param modifiedSince return domains only modified since this date
     * @return list of domain names or ZMSClientException will be thrown in case of failure
     */
    public DomainList getDomainList(Integer limit, String skip, String prefix, Integer depth,
            String account, Integer productId, Date modifiedSince) {
        updatePrincipal();
        String modSinceStr = null;
        if (modifiedSince != null) {
            DateFormat df = new SimpleDateFormat(HTTP_RFC1123_DATE_FORMAT);
            modSinceStr = df.format(modifiedSince);
        }
        try {
            return client.getDomainList(limit, skip, prefix, depth, account, productId, null, null, modSinceStr);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Retrieve the list of domains provisioned on the ZMS Server
     * filters based on the specified arguments
     * @param roleMember name of the principal
     * @param roleName name of the role where the principal is a member of
     * @return list of domain names or ZMSClientException will be thrown in case of failure
     */
    public DomainList getDomainList(String roleMember, String roleName) {
        updatePrincipal();
        try {
            return client.getDomainList(null, null, null, null, null, null, roleMember, roleName, null);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Create/Update Top level domain. If updating a domain the provided
     * object must contain all attributes as it will replace the full domain
     * object configured on the server (not just some of the attributes).
     * @param auditRef string containing audit specification or ticket number
     * @param detail TopLevelDomain object to be created in ZMS
     * @return created Domain object or ZMSClientException will be thrown in case of failure
     */
    public Domain postTopLevelDomain(String auditRef, TopLevelDomain detail) {
        updatePrincipal();
        try {
            return client.postTopLevelDomain(auditRef, detail);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create/Update a sub-domain in the specified domain. If updating a
     * subdomain the provided object must contain all attributes as it will
     * replace the full domain object configured on the server (not just some
     * of the attributes).
     * @param parent name of the parent domain
     * @param auditRef string containing audit specification or ticket number
     * @param detail SubDomain object to be created in ZMS
     * @return created Domain object or ZMSClientException will be thrown in case of failure
     */
    public Domain postSubDomain(String parent, String auditRef, SubDomain detail) {
        updatePrincipal();
        try {
            return client.postSubDomain(parent, auditRef, detail);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create a top-level user-domain - this is user.&lt;userid&gt; domain.
     * @param name domain to be created, this is the &lt;userid&gt;
     * @param auditRef string containing audit specification or ticket number
     * @param detail UserDomain object to be created in ZMS
     * @return created Domain object or ZMSClientException will be thrown in case of failure
     */
    public Domain postUserDomain(String name, String auditRef, UserDomain detail) {
        updatePrincipal();
        try {
            return client.postUserDomain(name, auditRef, detail);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Delete a top level domain
     * @param name domain name to be deleted from ZMS
     * @param auditRef string containing audit specification or ticket number
     */
    public void deleteTopLevelDomain(String name, String auditRef) {
        updatePrincipal();
        try {
            client.deleteTopLevelDomain(name, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete a sub-domain
     * @param parent name of the parent domain
     * @param name sub-domain to be deleted
     * @param auditRef string containing audit specification or ticket number
     */
    public void deleteSubDomain(String parent, String name, String auditRef) {
        updatePrincipal();
        try {
            client.deleteSubDomain(parent, name, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete a top-level user-domain (user.&lt;userid&gt;)
     * @param name domain to be deleted, this is the &lt;userid&gt;
     * @param auditRef string containing audit specification or ticket number
     */
    public void deleteUserDomain(String name, String auditRef) {
        updatePrincipal();
        try {
            client.deleteUserDomain(name, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Set the domain meta parameters
     * @param name domain name to be modified
     * @param auditRef string containing audit specification or ticket number
     * @param detail meta parameters to be set on the domain
     */
    public void putDomainMeta(String name, String auditRef, DomainMeta detail) {
        updatePrincipal();
        try {
            client.putDomainMeta(name, auditRef, detail);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of roles defined for the specified domain
     * @param domainName name of the domain
     * @return list of role names or ZMSClientException will be thrown in case of failure
     */
    public RoleList getRoleList(String domainName) {
        updatePrincipal();
        try {
            return client.getRoleList(domainName, null, null);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of roles defined for the specified domain
     * filtered based on the parameters specified
     * @param domainName name of the domain
     * @param limit number of roles to return
     * @param skip exclude all the roles including the specified one from the return set
     * @return list of role names or ZMSClientException will be thrown in case of failure
     */
    public RoleList getRoleList(String domainName, Integer limit, String skip) {
        updatePrincipal();
        try {
            return client.getRoleList(domainName, limit, skip);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of roles defined for the specified domain. The roles
     * will contain their attributes and, if specified, the list of members.
     * @param domainName name of the domain
     * @param members include all members for group roles as well
     * @return list of roles or ZMSClientException will be thrown in case of failure
     */
    public Roles getRoles(String domainName, Boolean members) {
        updatePrincipal();
        try {
            return client.getRoles(domainName, members);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Retrieve the specified role
     * @param domainName name of the domain
     * @param roleName name of the role
     * @return role object or ZMSClientException will be thrown in case of failure
     */
    public Role getRole(String domainName, String roleName) {
        return getRole(domainName, roleName, false, false);
    }

    /**
     * Retrieve the specified role
     * @param domainName name of the domain
     * @param roleName name of the role
     * @param auditLog include audit log for the role changes in the response
     * @return role object or ZMSClientException will be thrown in case of failure
     */
    public Role getRole(String domainName, String roleName, boolean auditLog) {
        return getRole(domainName, roleName, auditLog, false);
    }
    

    /**
     * Retrieve the specified role
     * @param domainName name of the domain
     * @param roleName name of the role
     * @param auditLog include audit log for the role changes in the response
     * @param expand if the requested role is a delegated/trust role, this flag
     * will instruct the ZMS server to automatically retrieve the members of the
     * role from the delegated domain and return as part of the role object
     * @return role object or ZMSClientException will be thrown in case of failure
     */
    public Role getRole(String domainName, String roleName, boolean auditLog, boolean expand) {
        updatePrincipal();
        try {
            return client.getRole(domainName, roleName, auditLog, expand);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Create/Update a new role in the specified domain. If updating a role
     * the provided object must contain all attributes as it will replace
     * the full role object configured on the server (not just some of the attributes).
     * @param domainName name of the domain
     * @param roleName name of the role
     * @param auditRef string containing audit specification or ticket number
     * @param role role object to be added to the domain
     */
    public void putRole(String domainName, String roleName, String auditRef, Role role) {
        updatePrincipal();
        try {
            client.putRole(domainName, roleName, auditRef, role);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete the specified role from domain
     * @param domainName name of the domain
     * @param roleName name of the role
     * @param auditRef string containing audit specification or ticket number
     */
    public void deleteRole(String domainName, String roleName, String auditRef) {
        updatePrincipal();
        try {
            client.deleteRole(domainName, roleName, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Get membership details for the specified member in the given role
     * in a specified domain
     * @param domainName name of the domain
     * @param roleName name of the role
     * @param memberName name of the member
     * @return Membership object or ZMSClientException will be thrown in case of failure
     */
    public Membership getMembership(String domainName, String roleName, String memberName) {
        updatePrincipal();
        try {
            return client.getMembership(domainName, roleName, memberName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Add a new member in the specified role.
     * @param domainName name of the domain
     * @param roleName name of the role
     * @param memberName name of the member to be added
     * @param auditRef string containing audit specification or ticket number
     */
    public void putMembership(String domainName, String roleName, String memberName, String auditRef) {
        putMembership(domainName, roleName, memberName, null, auditRef);
    }
    
    /**
     * Add a temporary member in the specified role with expiration
     * @param domainName name of the domain
     * @param roleName name of the role
     * @param memberName name of the member to be added
     * @param expiration timestamp when this membership will expire (optional)
     * @param auditRef string containing audit specification or ticket number
     */
    public void putMembership(String domainName, String roleName, String memberName,
            Timestamp expiration, String auditRef) {
        Membership mbr = new Membership();
        mbr.setRoleName(roleName);
        mbr.setMemberName(memberName);
        mbr.setExpiration(expiration);
        mbr.setIsMember(true);
        updatePrincipal();
        try {
            client.putMembership(domainName, roleName, memberName, auditRef, mbr);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Remove the specified member from the role
     * @param domainName name of the domain
     * @param roleName name of the role
     * @param memberName name of the member to be removed
     * @param auditRef string containing audit specification or ticket number
     */
    public void deleteMembership(String domainName, String roleName, String memberName, String auditRef) {
        updatePrincipal();
        try {
            client.deleteMembership(domainName, roleName, memberName, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of policies defined for the specified domain. The policies
     * will contain their attributes and, if specified, the list of assertions.
     * @param domainName name of the domain
     * @param assertions include all assertion for policies as well
     * @return list of policies or ZMSClientException will be thrown in case of failure
     */
    public Policies getPolicies(String domainName, Boolean assertions) {
        updatePrincipal();
        try {
            return client.getPolicies(domainName, assertions);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Get list of policies defined in the specified domain
     * @param domainName name of the domain
     * @return list of policy names or ZMSClientException will be thrown in case of failure
     */
    public PolicyList getPolicyList(String domainName) {
        updatePrincipal();
        try {
            return client.getPolicyList(domainName, null, null);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Get list of policies defined in the specified domain filtered
     * based on the specified arguments
     * @param domainName name of the domain
     * @param limit number of policies to return
     * @param skip exclude all the policies including the specified one from the return set
     * @return list of policy names or ZMSClientException will be thrown in case of failure
     */
    public PolicyList getPolicyList(String domainName, Integer limit, String skip) {
        updatePrincipal();
        try {
            return client.getPolicyList(domainName, limit, skip);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Return the specified policy object assertion
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param assertionId the id of the assertion to be retrieved
     * @return Assertion object or ZMSClientException will be thrown in case of failure
     */
    public Assertion getAssertion(String domainName, String policyName, Long assertionId) {
        updatePrincipal();
        try {
            return client.getAssertion(domainName, policyName, assertionId);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Add the specified assertion to the specified policy
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param auditRef string containing audit specification or ticket number
     * @param assertion Assertion object to be added to the policy
     * @return updated assertion object that includes the server assigned id
     */
    public Assertion putAssertion(String domainName, String policyName, String auditRef, Assertion assertion) {
        updatePrincipal();
        try {
            return client.putAssertion(domainName, policyName, auditRef, assertion);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete specified assertion from the given policy
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param assertionId the id of the assertion to be deleted
     * @param auditRef string containing audit specification or ticket number
     */
    public void deleteAssertion(String domainName, String policyName, Long assertionId, String auditRef) {
        updatePrincipal();
        try {
            client.deleteAssertion(domainName, policyName, assertionId, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Return the specified policy object
     * @param domainName name of the domain
     * @param policyName name of the policy to be retrieved
     * @return Policy object or ZMSClientException will be thrown in case of failure
     */
    public Policy getPolicy(String domainName, String policyName) {
        updatePrincipal();
        try {
            return client.getPolicy(domainName, policyName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create/Update a new policy in the specified domain. If updating a policy
     * the provided object must contain all attributes as it will replace the
     * full policy object configured on the server (not just some of the attributes).
     * @param domainName name of the domain
     * @param policyName name of the policy
     * @param auditRef string containing audit specification or ticket number
     * @param policy Policy object with details
     */
    public void putPolicy(String domainName, String policyName, String auditRef, Policy policy) {
        updatePrincipal();
        try {
            client.putPolicy(domainName, policyName, auditRef, policy);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /** 
     * Delete specified policy from a domain
     * @param domainName name of the domain
     * @param policyName name of the policy to be deleted
     * @param auditRef string containing audit specification or ticket number
     */
    public void deletePolicy(String domainName, String policyName, String auditRef) {
        updatePrincipal();
        try {
            client.deletePolicy(domainName, policyName, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create/Update a new service in the specified domain.  If updating a service
     * the provided object must contain all attributes as it will replace the
     * full service object configured on the server (not just some of the attributes).
     * @param domainName name of the domain
     * @param serviceName name of the service
     * @param auditRef string containing audit specification or ticket number
     * @param service ServiceIdentity object with all service details
     */
    public void putServiceIdentity(String domainName, String serviceName, 
            String auditRef, ServiceIdentity service) {
        updatePrincipal();
        try {
            client.putServiceIdentity(domainName, serviceName, auditRef, service);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the specified service object from a domain
     * @param domainName name of the domain
     * @param serviceName name of the service to be retrieved
     * @return ServiceIdentity object or ZMSClientException will be thrown in case of failure
     */
    public ServiceIdentity getServiceIdentity(String domainName, String serviceName) {
        updatePrincipal();
        try {
            return client.getServiceIdentity(domainName, serviceName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete the specified service from a domain
     * @param domainName name of the domain
     * @param serviceName name of the service to be deleted
     * @param auditRef string containing audit specification or ticket number
     */
    public void deleteServiceIdentity(String domainName, String serviceName, String auditRef) {
        updatePrincipal();
        try {
            client.deleteServiceIdentity(domainName, serviceName, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of services defined for the specified domain. The services
     * will contain their attributes and, if specified, the list of publickeys and hosts.
     * @param domainName name of the domain
     * @param publicKeys include all public keys for services as well
     * @param hosts include all configured hosts for services as well
     * @return list of services or ZMSClientException will be thrown in case of failure
     */
    public ServiceIdentities getServiceIdentities(String domainName, Boolean publicKeys, Boolean hosts) {
        updatePrincipal();
        try {
            return client.getServiceIdentities(domainName, publicKeys, hosts);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Retrieve the full list of services defined in a domain
     * @param domainName name of the domain
     * @return list of all service names or ZMSClientException will be thrown in case of failure
     */
    public ServiceIdentityList getServiceIdentityList(String domainName) {
        updatePrincipal();
        try {
            return client.getServiceIdentityList(domainName, null, null);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of services defined in a domain filtered
     * based on the specified arguments
     * @param domainName name of the domain
     * @param limit number of services to return
     * @param skip exclude all the services including the specified one from the return set
     * @return list of service names or ZMSClientException will be thrown in case of failure
     */
    public ServiceIdentityList getServiceIdentityList(String domainName, Integer limit, String skip) {
        updatePrincipal();
        try {
            return client.getServiceIdentityList(domainName, limit, skip);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the specified public key from the given service object
     * @param domainName name of the domain
     * @param serviceName name of the service
     * @param keyId the identifier of the public key to be retrieved
     * @return PublicKeyEntry object or ZMSClientException will be thrown in case of failure
     */
    public PublicKeyEntry getPublicKeyEntry(String domainName, String serviceName, String keyId) {
        updatePrincipal();
        try {
            return client.getPublicKeyEntry(domainName, serviceName, keyId);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Update or add (if doesn't already exist) the specified public key in the service object
     * @param domainName name of the domain
     * @param serviceName name of the service
     * @param keyId the identifier of the public key to be updated
     * @param auditRef string containing audit specification or ticket number
     * @param publicKeyEntry that contains the public key details
     */
    public void putPublicKeyEntry(String domainName, String serviceName, String keyId, String auditRef,
            PublicKeyEntry publicKeyEntry) {
        updatePrincipal();
        try {
            client.putPublicKeyEntry(domainName, serviceName, keyId, auditRef, publicKeyEntry);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete the specified public key from the service object. If the key doesn't exist then
     * it is treated as a successful operation and no exception will be thrown.
     * @param domainName name of the domain
     * @param serviceName name of the service
     * @param keyId the identifier of the public key to be deleted
     * @param auditRef string containing audit specification or ticket number
     */
    public void deletePublicKeyEntry(String domainName, String serviceName, String keyId, String auditRef) {
        updatePrincipal();
        try {
            client.deletePublicKeyEntry(domainName, serviceName, keyId, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create/update an entity object in ZMS
     * @param domainName name of the domain
     * @param entityName name of the entity
     * @param auditRef string containing audit specification or ticket number
     * @param entity entity object with details
     */
    public void putEntity(String domainName, String entityName, String auditRef, Entity entity) {
        updatePrincipal();
        try {
            client.putEntity(domainName, entityName, auditRef, entity);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the specified entity from the ZMS Server
     * @param domainName name of the domain
     * @param entityName name of the entity
     * @return Entity object with details or ZMSClientException will be thrown in case of failure
     */
    public Entity getEntity(String domainName, String entityName) {
        updatePrincipal();
        try {
            return client.getEntity(domainName, entityName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete the specified entity from the ZMS Server
     * @param domainName name of the domain
     * @param entityName name of the entity
     * @param auditRef string containing audit specification or ticket number
     */
    public void deleteEntity(String domainName, String entityName, String auditRef) {
        updatePrincipal();
        try {
            client.deleteEntity(domainName, entityName, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of entities defined for the specified domain
     * @param domainName name of the domain
     * @return list of entity names or ZMSClientException will be thrown in case of failure
     */
    public EntityList getEntityList(String domainName) {
        updatePrincipal();
        try {
            return client.getEntityList(domainName);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Create a new tenant for the specified domain. The service specifies the 
     * provider.
     * @param tenantDomain name of the tenant domain
     * @param providerService name of the provider service
     *        format: provider-domain-name.provider-service-name, ex: "sports.storage"
     * @param auditRef string containing audit specification or ticket number
     * @param tenant Tenancy object with tenant details
     */
    public void putTenancy(String tenantDomain, String providerService, String auditRef, Tenancy tenant) {
        updatePrincipal();
        try {
            client.putTenancy(tenantDomain, providerService, auditRef, tenant);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the specified tenant from a domain
     * @param tenantDomain name of the tenant domain
     * @param providerService name of the provider service,
     *        format: provider-domain-name.provider-service-name, ex: "sports.storage"
     * @return Tenancy object or ZMSClientException will be thrown in case of failure
     */
    public Tenancy getTenancy(String tenantDomain, String providerService) {
        updatePrincipal();
        try {
            return client.getTenancy(tenantDomain, providerService);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete the specified tenant from a domain
     * @param tenantDomain name of the tenant domain
     * @param providerService name of the provider service,
     *        format: provider-domain-name.provider-service-name, ex: "sports.storage"
     * @param auditRef string containing audit specification or ticket number
     */
    public void deleteTenancy(String tenantDomain, String providerService, String auditRef) {
        updatePrincipal();
        try {
            client.deleteTenancy(tenantDomain, providerService, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create a new resource group for the specified tenant. The service specifies the
     * provider. The tenant must have on-boarded already using the putTenancy call.
     * @param tenantDomain name of the tenant domain
     * @param providerService name of the provider service,
     *        format: provider-domain-name.provider-service-name, ex: "sports.storage"
     * @param resourceGroup name of the resource group
     * @param auditRef string containing audit specification or ticket number
     * @param resourceGroupData TenancyResourceGroup object with tenant's resource group details
     */
    public void putTenancyResourceGroup(String tenantDomain, String providerService,
            String resourceGroup, String auditRef, TenancyResourceGroup resourceGroupData) {
        updatePrincipal();
        try {
            client.putTenancyResourceGroup(tenantDomain, providerService, resourceGroup, auditRef, resourceGroupData);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete the specified resource group for the tenant.
     * @param tenantDomain name of the tenant domain
     * @param providerService name of the provider service, format:
     *        provider-domain-name.provider-service-name, ex: "sports.storage"
     * @param resourceGroup name of the resource group
     * @param auditRef string containing audit specification or ticket number
     */
    public void deleteTenancyResourceGroup(String tenantDomain, String providerService,
            String resourceGroup, String auditRef) {
        updatePrincipal();
        try {
            client.deleteTenancyResourceGroup(tenantDomain, providerService, resourceGroup, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create tenant roles for the specified tenant
     * @param providerDomain name of the provider domain
     * @param providerServiceName name of the provider service
     * @param tenantDomain name of the tenant's domain
     * @param auditRef string containing audit specification or ticket number
     * @param tenantRoles Tenant roles
     */
    public void putTenantRoles(String providerDomain, String providerServiceName,
            String tenantDomain, String auditRef, TenantRoles tenantRoles) {
        updatePrincipal();
        try {
            client.putTenantRoles(providerDomain, providerServiceName, tenantDomain, auditRef, tenantRoles);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Create tenant roles for the specified tenant resource group.
     * @param providerDomain name of the provider domain
     * @param providerServiceName name of the provider service
     * @param tenantDomain name of the tenant's domain
     * @param resourceGroup name of the resource group
     * @param auditRef string containing audit specification or ticket number
     * @param tenantRoles Tenant roles
     */
    public void putTenantResourceGroupRoles(String providerDomain, String providerServiceName, String tenantDomain,
            String resourceGroup, String auditRef, TenantResourceGroupRoles tenantRoles) {
        updatePrincipal();
        try {
            client.putTenantResourceGroupRoles(providerDomain, providerServiceName, tenantDomain,
                    resourceGroup, auditRef, tenantRoles);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of tenant roles defined for a tenant in a domain
     * @param providerDomain name of the provider domain
     * @param providerServiceName name of the provider service
     * @param tenantDomain name of the tenant's domain
     * @return list of tenant roles or ZMSClientException will be thrown in case of failure
     */
    public TenantRoles getTenantRoles(String providerDomain, String providerServiceName, String tenantDomain) {
        updatePrincipal();
        try {
            return client.getTenantRoles(providerDomain, providerServiceName, tenantDomain);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of tenant roles defined for a tenant resource group in a domain
     * @param providerDomain name of the provider domain
     * @param providerServiceName name of the provider service
     * @param tenantDomain name of the tenant's domain
     * @param resourceGroup name of the resource group
     * @return list of tenant roles or ZMSClientException will be thrown in case of failure
     */
    public TenantResourceGroupRoles getTenantResourceGroupRoles(String providerDomain, String providerServiceName,
            String tenantDomain, String resourceGroup) {
        updatePrincipal();
        try {
            return client.getTenantResourceGroupRoles(providerDomain, providerServiceName,
                    tenantDomain, resourceGroup);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete tenant roles for the specified tenant in a domain
     * @param providerDomain name of the provider domain
     * @param providerServiceName name of the provider service
     * @param tenantDomain name of tenant's domain
     * @param auditRef string containing audit specification or ticket number
     */
    public void deleteTenantRoles(String providerDomain, String providerServiceName, String tenantDomain,
            String auditRef) {
        updatePrincipal();
        try {
            client.deleteTenantRoles(providerDomain, providerServiceName, tenantDomain, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete tenant roles for the specified tenant resource group in a domain
     * @param providerDomain name of the provider domain
     * @param providerServiceName name of the provider service
     * @param tenantDomain name of tenant's domain
     * @param resourceGroup name of the resource group
     * @param auditRef string containing audit specification or ticket number
     */
    public void deleteTenantResourceGroupRoles(String providerDomain, String providerServiceName, String tenantDomain,
            String resourceGroup, String auditRef) {
        updatePrincipal();
        try {
            client.deleteTenantResourceGroupRoles(providerDomain, providerServiceName, tenantDomain,
                    resourceGroup, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Requests the ZMS to indicate whether or not the specific request for the 
     * specified resource with authentication details will be granted or not.
     * @param action value of the action to be carried out (e.g. "UPDATE", "DELETE")
     * @param resource resource name. Resource is defined as {DomainName}:{Entity}"
     * @param trustDomain (optional) if the access checks involves cross domain check only
     *        check the specified trusted domain and ignore all others
     * @return Access object indicating whether or not the request will be granted or not
     */
    public Access getAccess(String action, String resource, String trustDomain) {
        return getAccess(action, resource, trustDomain, null);
    }

    /**
     * Requests the ZMS to indicate whether or not the specific request for the 
     * specified resource with authentication details will be granted or not.
     * @param action value of the action to be carried out (e.g. "UPDATE", "DELETE")
     * @param resource resource name. Resource is defined as {DomainName}:{Entity}"
     * @param trustDomain (optional) if the access checks involves cross domain check only
     *        check the specified trusted domain and ignore all others
     * @param principal (optional) carry out the access check for specified principal
     * @return Access object indicating whether or not the request will be granted or not
     */
    public Access getAccess(String action, String resource, String trustDomain, String principal) {
        try {
            return client.getAccess(action, resource, trustDomain, principal);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }


    /**
     * Requests the ZMS to indicate whether or not the specific request for the 
     * specified resource with authentication details will be granted or not.
     * @param action value of the action to be carried out (e.g. "UPDATE", "DELETE")
     * @param resource resource string.
     * @param trustDomain (optional) if the access checks involves cross domain check only
     *        check the specified trusted domain and ignore all others
     * @param principal (optional) carry out the access check for specified principal
     * @return Access object indicating whether or not the request will be granted or not
     */
    public Access getAccessExt(String action, String resource, String trustDomain, String principal) {
        try {
            return client.getAccessExt(action, resource, trustDomain, principal);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Retrieve the list of all domain data from the ZMS Server that
     * is signed with ZMS's private key. It will pass an optional matchingTag
     * so that ZMS can skip returning domains if no changes have taken
     * place since that tag was issued.
     * @param domainName name of the domain. if specified, the server will
     *        only return this domain in the result set
     * @param metaOnly (can be null) must have value of true or false (default).
     *        if set to true, zms server will only return meta information
     *        about each domain (description, last modified timestamp, etc) and
     *        no role/policy/service details will be returned.
     * @param matchingTag (can be null) contains modified timestamp received
     *        with last request. If null, then return all domains.
     * @param responseHeaders contains the "tag" returned for modification
     *        time of the domains, map key = "tag", List should
     *        contain a single value timestamp String to be used
     *        with subsequent call as matchingTag to this API
     * @return list of domains signed by ZMS Server
     */
    public SignedDomains getSignedDomains(String domainName, String metaOnly, String matchingTag,
            Map<String, List<String>> responseHeaders) {
        updatePrincipal();
        try {
            SignedDomains sd = client.getSignedDomains(domainName, metaOnly, matchingTag, responseHeaders);
            return sd;
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * For the specified user credentials return the corresponding User Token that
     * can be used for authenticating other ZMS operations. The client internally
     * automatically calls this method and uses the UserToken if the ZMSClient
     * object was initialized with a user principal.
     * @param userName name of the user. This is only used to verify that it matches
     * the user name from the credentials and is optional. The caller can just pass
     * the string "_self_" as the userName to bypass this optional check.
     * @return ZMS generated User Token
     */
    public UserToken getUserToken(String userName) {
        return getUserToken(userName, null);
    }
    
    /**
     * For the specified user credentials return the corresponding User Token that
     * can be used for authenticating other ZMS operations by any of the specified
     * authorized services.
     * @param userName name of the user
     * @param serviceNames comma separated list of authorized service names
     * @return ZMS generated User Token
     */
    public UserToken getUserToken(String userName, String serviceNames) {
        try {
            return client.getUserToken(userName, serviceNames);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * For the specified domain in domainName, a list of default administrators
     * can be passed to this method and will be added to the domain's admin role
     * In addition this method will ensure that the admin role and policy exist and
     * are properly set up
     * @param domainName - name of the domain to add default administrators to
     * @param auditRef - string containing audit specification or ticket number
     * @param defaultAdmins - list of names to be added as default administrators
     */
    public void putDefaultAdmins(String domainName, String auditRef, DefaultAdmins defaultAdmins) {
        updatePrincipal();
        try {
            client.putDefaultAdmins(domainName, auditRef, defaultAdmins);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * The client will validate the given serviceToken against the ZMS Server
     * and if the token is valid, it will return a Principal object.
     * @param serviceToken token to be validated.
     * @return Principal object if the token is successfully validated or 
     * ZMSClientException will be thrown in case of failure
     */
    public Principal getPrincipal(String serviceToken) {
        
        if (serviceToken == null) {
            throw new ZMSClientException(401, "Null service token provided");
        }
        
        PrincipalToken token = null;
        try {
            token = new PrincipalToken(serviceToken);
        } catch (IllegalArgumentException ex) {
            throw new ZMSClientException(ZMSClientException.UNAUTHORIZED, "Invalid service token provided: " + ex.getMessage());
        }
        
        Principal servicePrincipal = null;
        try {
            servicePrincipal = SimplePrincipal.create(token.getDomain(), token.getName(), 
                serviceToken, 0, PRINCIPAL_AUTHORITY);
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.UNAUTHORIZED, "Invalid service token provided");
        }
        
        addCredentials(servicePrincipal);
        
        ServicePrincipal validatedPrincipal = null;
        try {
            validatedPrincipal = client.getServicePrincipal();
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
        
        if (validatedPrincipal == null) {
            throw new ZMSClientException(ZMSClientException.UNAUTHORIZED, "Invalid service token provided");
        }
        
        // before returning let's validate that domain, name and
        // credentials match to what was passed to 
        
        if (!servicePrincipal.getDomain().equalsIgnoreCase(validatedPrincipal.getDomain())) {
            throw new ZMSClientException(ZMSClientException.UNAUTHORIZED, "Validated principal domain name mismatch");
        }
        
        if (!servicePrincipal.getName().equalsIgnoreCase(validatedPrincipal.getService())) {
            throw new ZMSClientException(ZMSClientException.UNAUTHORIZED, "Validated principal service name mismatch");
        }
        
        return servicePrincipal;
    }
    
    /**
     * Create provider roles for the specified tenant resource group in the tenant domain.
     * If the principal requesting this operation has been authorized by the provider
     * service itself, then the corresponding tenant roles will be created in the provider
     * domain as well thus completing the tenancy on-boarding process in one call.
     * @param tenantDomain name of the tenant's domain
     * @param providerDomain name of the provider domain
     * @param providerServiceName name of the provider service
     * @param resourceGroup name of the resource group
     * @param auditRef string containing audit specification or ticket number
     * @param providerRoles Provider roles
     */
    public void putProviderResourceGroupRoles(String tenantDomain, String providerDomain,
            String providerServiceName, String resourceGroup, String auditRef,
            ProviderResourceGroupRoles providerRoles) {
        updatePrincipal();
        try {
            client.putProviderResourceGroupRoles(tenantDomain, providerDomain, providerServiceName,
                    resourceGroup, auditRef, providerRoles);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Delete the provider roles for the specified tenant resource group from the tenant domain.
     * If the principal requesting this operation has been authorized by the provider
     * service itself, then the corresponding tenant roles will be deleted from the provider
     * domain as well thus completing the process in one call.
     * @param tenantDomain name of tenant's domain
     * @param providerDomain name of the provider domain
     * @param providerServiceName name of the provider service
     * @param resourceGroup name of the resource group
     * @param auditRef string containing audit specification or ticket number
     */
    public void deleteProviderResourceGroupRoles(String tenantDomain, String providerDomain,
            String providerServiceName, String resourceGroup, String auditRef) {
        updatePrincipal();
        try {
            client.deleteProviderResourceGroupRoles(tenantDomain, providerDomain, providerServiceName,
                    resourceGroup, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Retrieve the list of provider roles defined for a tenant resource group in a domain
     * @param tenantDomain name of the tenant's domain
     * @param providerDomain name of the provider domain
     * @param providerServiceName name of the provider service
     * @param resourceGroup name of the resource group
     * @return list of provider roles or ZMSClientException will be thrown in case of failure
     */
    public ProviderResourceGroupRoles getProviderResourceGroupRoles(String tenantDomain,
            String providerDomain, String providerServiceName, String resourceGroup) {
        updatePrincipal();
        try {
            return client.getProviderResourceGroupRoles(tenantDomain, providerDomain, providerServiceName,
                    resourceGroup);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Check the data for the specified domain object
     * @param domain name of the domain to be checked
     * @return DomainDataCheck object or ZMSClientException will be thrown in case of failure
     */
    public DomainDataCheck getDomainDataCheck(String domain) {
        updatePrincipal();
        try {
            return client.getDomainDataCheck(domain);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Retrieve the the specified solution template provisioned on the ZMS Server.
     * The template object will include the list of roles and policies that will
     * be provisioned in the domain when the template is applied.
     * @param template name of the solution template to be retrieved
     * @return template object or ZMSClientException will be thrown in case of failure
     */
    public Template getTemplate(String template) {
        updatePrincipal();
        try {
            return client.getTemplate(template);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve the list of solution templates provisioned on the ZMS Server
     * @return list of template names or ZMSClientException will be thrown in case of failure
     */
    public ServerTemplateList getServerTemplateList() {
        updatePrincipal();
        try {
            return client.getServerTemplateList();
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Provision the specified solution template roles and policies in the domain
     * @param domain name of the domain to be updated
     * @param auditRef string containing audit specification or ticket number
     * @param templates contains list of template names to be provisioned in the domain
     */
    public void putDomainTemplate(String domain, String auditRef, DomainTemplate templates) {
        updatePrincipal();
        try {
            client.putDomainTemplate(domain, auditRef, templates);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Delete the specified solution template roles and policies from the domain
     * @param domain name of the domain to be updated
     * @param template is the name of the provisioned template to be deleted
     * @param auditRef string containing audit specification or ticket number
     */
    public void deleteDomainTemplate(String domain, String template, String auditRef) {
        updatePrincipal();
        try {
            client.deleteDomainTemplate(domain, template, auditRef);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Retrieve the list of solution template provisioned for a domain
     * @param domain name of the domain
     * @return TemplateList object that includes the list of provisioned solution template names
     */
    public DomainTemplateList getDomainTemplateList(String domain) {
        updatePrincipal();
        try {
            return client.getDomainTemplateList(domain);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
    
    /**
     * Retrieve the list of resources as defined in their respective assertions
     * that the given principal has access to through their role membership
     * @param principal the principal name (e.g. user.joe). Must have special
     * privileges to execute this query without specifying the principal.
     * Check with Athenz Service Administrators if you have a use case to
     * request all principals from Athenz Service
     * @param action optional field specifying what action to filter assertions on
     * @return ResourceAccessList object that lists the set of assertions per principal
     */
    public ResourceAccessList getResourceAccessList(String principal, String action) {
        updatePrincipal();
        try {
            return client.getResourceAccessList(principal, action);
        } catch (ResourceException ex) {
            throw new ZMSClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new ZMSClientException(ZMSClientException.BAD_REQUEST, ex.getMessage());
        }
    }
}
