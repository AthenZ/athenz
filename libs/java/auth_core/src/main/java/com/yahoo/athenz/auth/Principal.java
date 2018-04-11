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
package com.yahoo.athenz.auth;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * A Principal is an authenticated entity that takes an action on a resource.
 */
public interface Principal {

    /** @return the domain of the authority over this principal, i.e. "user" */
    String getDomain();

    /** @return the name of the principal as a string, i.e. "joe" */
    String getName();

    /** @return the full name of the principal as a string, i.e. "user.joe" */
    String getFullName();
    
    /** @return the credentials token as a string */
    String getCredentials();
    
    /** @return the client certificate that the principal
     * was authenticated with if using the certificate authority */
    default X509Certificate getX509Certificate() {
        return null;
    }
    
    /** @return the credentials token as a string but will not contain a signature */
    String getUnsignedCredentials();

    /** @return the list of roles this principal is able to assume. This is null 
     * for user/service principals, but valid for a principal based on ZTokens. */
    List<String> getRoles();
    
    /** @return the authority over this principal. Can be null, if not authenticated. */
    Authority getAuthority();

    /** @return the issue time for the credentials */
    long getIssueTime();
    
    /** @return the service name that was authorized to use the Principal's UserToken */
    String getAuthorizedService();
    
    /** @return the associated IP address provided in the principal token */
    default String getIP() {
        return null;
    }
    
    /** @return the associated original requestor specified in the principal token */
    default String getOriginalRequestor() {
        return null;
    }
    
    /** @return the associated original key service specified in the principal token */
    default String getKeyService() {
        return null;
    }
    
    /** @return the private key identifier that was used to sign the service token */
    default String getKeyId() {
        return null;
    }
    
    /** @return the application ID */
    default String getApplicationId() {
        return null;
    }

}
