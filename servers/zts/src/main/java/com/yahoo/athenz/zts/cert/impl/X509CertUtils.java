/*
 * Copyright 2018 Oath Inc.
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
package com.yahoo.athenz.zts.cert.impl;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zts.ZTSConsts;

import java.security.cert.X509Certificate;
import java.util.List;

public class X509CertUtils {

    public static String extractRequestInstanceId(X509Certificate cert) {

        if (cert == null) {
            return null;
        }

        List<String> dnsNames = Crypto.extractX509CertDnsNames(cert);
        for (String dnsName : dnsNames) {
            int idx = dnsName.indexOf(ZTSConsts.ZTS_CERT_INSTANCE_ID);
            if (idx != -1) {
                return dnsName.substring(0, idx);
            }
        }

        return null;
    }
}
