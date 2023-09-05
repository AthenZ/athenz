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
package com.yahoo.athenz.auth.impl;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.yahoo.athenz.auth.KeyStore;

public class KeyStoreMock implements KeyStore {

    private final String servicePublicKeyStringK0;
    private final String servicePublicKeyStringK1;
    private final String ztsPublicKeyStringK0;
    private final String ztsPublicKeyStringK1;
    private final String hostPublic;

    public KeyStoreMock() throws IOException {
        Path path = Paths.get("./src/test/resources/fantasy_public_k0.key");
        servicePublicKeyStringK0 = new String(Files.readAllBytes(path));

        path = Paths.get("./src/test/resources/fantasy_public_k1.key");
        servicePublicKeyStringK1 = new String(Files.readAllBytes(path));

        path = Paths.get("./src/test/resources/zts_public_k0.key");
        ztsPublicKeyStringK0 = new String(Files.readAllBytes(path));

        path = Paths.get("./src/test/resources/zts_public_k1.key");
        ztsPublicKeyStringK1 = new String(Files.readAllBytes(path));

        path = Paths.get("./src/test/resources/host_public.key");
        hostPublic = new String(Files.readAllBytes(path));
    }

    @Override
    public String getPublicKey(String domain, String service, String keyId) {

        // special case for host certs - no domain and service

        if (domain == null && service == null) {
            return hostPublic;
        }

        // handle rest of the cases for other authorities

        if ("sports".equals(domain) && "fantasy".equals(service) && "0".equals(keyId)) {
            return servicePublicKeyStringK0;
        } else if ("sports".equals(domain) && "fantasy".equals(service) && "1".equals(keyId)) {
            return servicePublicKeyStringK1;
        } else if ("sports".equals(domain) && "nfl".equals(service) && "0".equals(keyId)) {
            return servicePublicKeyStringK0;
        } else if ("sports".equals(domain) && "nfl".equals(service) && "1".equals(keyId)) {
            return servicePublicKeyStringK1;
        } else if ("cd.project".equals(domain) && "authority".equals(service)
                && "0".equals(keyId)) {
            return servicePublicKeyStringK0;
        } else if ("cd.step".equals(domain) && "authority".equals(service) && "0".equals(keyId)) {
            return servicePublicKeyStringK0;
        } else if (RoleAuthority.SYS_AUTH_DOMAIN.equals(domain)
                && RoleAuthority.ZTS_SERVICE_NAME.equals(service) && "0".equals(keyId)) {
            return ztsPublicKeyStringK0;
        } else if (RoleAuthority.SYS_AUTH_DOMAIN.equals(domain)
                && RoleAuthority.ZTS_SERVICE_NAME.equals(service) && "1".equals(keyId)) {
            return ztsPublicKeyStringK1;
        } else if ("sys.auth".equals(domain) && "zms".equals(service) && "0".equals(keyId)) {
            return servicePublicKeyStringK0;
        }

        return null;
    }
}
