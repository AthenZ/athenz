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
package com.yahoo.athenz.zms;

import java.io.Closeable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.RoleAuthority;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.auth.token.RoleToken;

public class ZMSAuthorizer implements Authorizer, Closeable {
    
    String endpoint = null;
    String serviceDomain = null;
    protected ZMSClient client = null; 
    private static final Logger LOGGER = LoggerFactory.getLogger(ZMSAuthorizer.class);
    private static final PrincipalAuthority PRINCIPAL_AUTHORITY = new PrincipalAuthority();
    private static final RoleAuthority ROLE_AUTHORITY = new RoleAuthority();
    
    /**
     * Constructs a new ZMSAuthorizer object with the given resource service domain
     * name. The url for ZMS Server is automatically retrieved from the athenz
     * configuration file (zms_url field).
     * @param serviceDomain resource service domain name
     */
    public ZMSAuthorizer(String serviceDomain) {
        this(null, serviceDomain);
    }

    /**
     * Constructs a new ZMSAuthorizer object with the given ZMS Server endpoint and
     * given resource service domain name
     * @param endpoint ZMS Server url (e.g. http://server.athenzcompany.com:4443/zms/v1)
     * @param serviceDomain resource service domain name
     */
    public ZMSAuthorizer(String endpoint, String serviceDomain) {
        this.endpoint = endpoint;
        this.serviceDomain = serviceDomain;
        client = new ZMSClient(this.endpoint); 
    }

    /**
     * Close the ZMS Client object
     */
    public void close() {
        if (client != null) {
            client.close();
            client = null;
        }
    }

    /**
     * Set the authorizer to use the specified zms client object
     * @param client ZMSClient object to use for authorization checks
     */
    public void setZMSClient(ZMSClient client) {
        // if we already have a client then we need to close it
        close();
        this.client = client;
    }
    
    /**
     * Requests the ZMS to indicate whether or not the specific request for the
     * specified resource with authentication details will be granted or not.
     * @param action value of the action to be carried out (e.g. "UPDATE", "DELETE")
     * @param resource resource value
     * @param token either principal token (NToken) or role token (ZToken) that will
     *        be authenticated and checked for requested access
     * @param trustDomain (optional - usually null) if the access checks involves cross
     *        domain check only check the specified trusted domain and ignore all others
     *        If the token is a role token, this argument must be null.
     * @return boolean indicating whether or not the request will be granted or not
     */
    public boolean access(String action, String resource, String token, String trustDomain) {
        
        // first let's find out what type of token we're given
        // either Role Token with version Z1 or principal token
        // our token classes will always validate the given
        // token and throw exceptions so we'll always get a valid
        // principal object
        
        Principal principal;
        if (isRoleToken(token)) {
            RoleToken roleToken = new RoleToken(token);
            principal = SimplePrincipal.create(roleToken.getDomain(),
                    roleToken.getSignedToken(), roleToken.getRoles(), ROLE_AUTHORITY);
        } else {
            PrincipalToken principalToken = new PrincipalToken(token);
            principal = SimplePrincipal.create(principalToken.getDomain(),
                    principalToken.getName(), principalToken.getSignedToken(),
                    0, PRINCIPAL_AUTHORITY);
        }
        return access(action, resource, principal, trustDomain);
    }
    
    /**
     * Requests the ZMS to indicate whether or not the specific request for the
     * specified resource with authentication details will be granted or not.
     * @param action value of the action to be carried out (e.g. "UPDATE", "DELETE")
     * @param resource resource value
     * @param principal principal object that will be authenticated and checked for
     *        requested access
     * @param trustDomain (optional - usually null) if the access checks involves cross
     *        domain check only check the specified trusted domain and ignore all others
     * @return boolean indicating whether or not the request will be granted or not
     */
    public boolean access(String action, String resource, Principal principal, String trustDomain) {
        
        //the "resource" may be an entity name here, we need a full resource name
        
        String rn = (resource.contains(":")) ? resource : serviceDomain + ":" + resource;
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("ZMSAuthorizer.access({}, {}, {}, {})", action, rn,
                    principal != null ? principal.getFullName() : "null", trustDomain);
        }
        
        try {
            client.addCredentials(principal);
            return client.getAccess(action, rn, trustDomain).getGranted();
        } catch (ZMSClientException e) {
            
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("ZMSAuthorizer.access", e);
            }
            
            switch (e.getCode()) {
            case ResourceException.NOT_FOUND:
                throw new ZMSClientException(ResourceException.FORBIDDEN, "Not found: " + rn);
            default:
                throw e;
            }
        } catch (Throwable th) {
            throw new ZMSClientException(ResourceException.FORBIDDEN, "Cannot contact ZMS");
        }
    }
    
    boolean isRoleToken(String token) {
        
        // we're only looking for the version component
        // which is usually the first one so we're not
        // going to parse the full token
        
        boolean roleToken = false;
        for (String item : token.split(";")) {
            if ("v=Z1".equalsIgnoreCase(item)) {
                roleToken = true;
                break;
            }
        }
        return roleToken;
    }
}
