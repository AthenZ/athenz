/*
 * Copyright 2018 Yahoo Holdings, Inc.
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLContext;

import com.amazonaws.services.securitytoken.model.Credentials;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.ServiceIdentityProvider;

public class ZTSClientMock extends ZTSClient {

    public ZTSClientMock() {
    }

    public ZTSClientMock(String ztsUrl) {
        super(ztsUrl);
    }

    public ZTSClientMock(Principal identity) {
        super(identity);
    }

    public ZTSClientMock(String ztsUrl, Principal identity) {
        super(ztsUrl, identity);
    }

    public ZTSClientMock(String ztsUrl, SSLContext sslContext) {
        super(ztsUrl, sslContext);
    }

    public ZTSClientMock(String domainName, String serviceName, ServiceIdentityProvider siaProvider) {
        super(domainName, serviceName, siaProvider);
    }

    public ZTSClientMock(String ztsUrl, String domainName, String serviceName, ServiceIdentityProvider siaProvider) {
        super(ztsUrl, domainName, serviceName, siaProvider);
    }

    @Override
    Credentials assumeAWSRole(String account, String roleName) {
        
        Credentials creds = new Credentials();
        creds.setAccessKeyId("access");
        creds.setSecretAccessKey("secret");
        creds.setSessionToken("token");
        return creds;
    }
    
    @Override
    public InstanceIdentity postInstanceRegisterInformation(InstanceRegisterInformation info,
            Map<String, List<String>> responseHeaders) {
        InstanceIdentity identity = new InstanceIdentity();
        Path path = Paths.get("./src/test/resources/test_cert.pem");
        try {
            identity.setX509Certificate(new String(Files.readAllBytes(path)));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return identity;
    }
    
}
