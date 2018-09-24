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

import javax.net.ssl.HostnameVerifier;

import com.yahoo.athenz.auth.Principal;

public class ZTSRDLGeneratedClientMock extends ZTSRDLGeneratedClient {
    
    public ZTSRDLGeneratedClientMock(String url) {
        super(url);
    }

    public ZTSRDLGeneratedClientMock(String url, Principal identity) {
        super(url);
        if (identity != null && identity.getAuthority() != null) {
            addCredentials(identity.getAuthority().getHeader(), identity.getCredentials());
        }
    }

    public ZTSRDLGeneratedClientMock(String url, Principal identity, HostnameVerifier hostnameVerifier) {
        super(url, hostnameVerifier);
        if (identity != null && identity.getAuthority() != null) {
            addCredentials(identity.getAuthority().getHeader(), identity.getCredentials());
        }
    }
    
    public HostnameVerifier getHostnameVerifier() {
        return client.getHostnameVerifier();
    }
}
