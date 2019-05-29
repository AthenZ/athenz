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
package com.yahoo.athenz.zts.cert;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zts.ZTSConsts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.List;

public class X509CertUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(X509RoleCertRequest.class);
    private static final ThreadLocal<StringBuilder> TLS_BUILDER = ThreadLocal.withInitial(() -> new StringBuilder(256));

    public static String extractReqeustInstanceIdFromURI(final List<String> uriList) {

        for (String uri : uriList) {
            if (!uri.startsWith(ZTSConsts.ZTS_CERT_INSTANCE_ID_URI)) {
                continue;
            }
            // skip the provider value
            int idx = uri.substring(ZTSConsts.ZTS_CERT_INSTANCE_ID_URI.length()).indexOf('/');
            if (idx != -1) {
                return uri.substring(ZTSConsts.ZTS_CERT_INSTANCE_ID_URI.length() + idx + 1);
            }
        }

        return null;
    }

    public static String extractReqeustInstanceIdFromDnsNames(final List<String> dnsNames) {

        for (String dnsName : dnsNames) {
            int idx = dnsName.indexOf(ZTSConsts.ZTS_CERT_INSTANCE_ID_DNS);
            if (idx != -1) {
                return dnsName.substring(0, idx);
            }
        }

        return null;
    }

    public static String extractRequestInstanceId(X509Certificate cert) {

        if (cert == null) {
            return null;
        }

        // first we're going to look for our uri field to see
        // if we have an instance id uri available. the format is:
        // athenz://instanceid/<provider>/<instance-id>

        final List<String> uriList = Crypto.extractX509CertURIs(cert);
        final String instanceId = extractReqeustInstanceIdFromURI(uriList);
        if (instanceId != null) {
            return instanceId;
        }

        // if no uri, then we'll fall back to our old dnsName field

        final List<String> dnsNames = Crypto.extractX509CertDnsNames(cert);
        return extractReqeustInstanceIdFromDnsNames(dnsNames);
    }

    public static void logCert(final Logger certLogger, final Principal principal,
                final String ip, final String provider, final String instanceId,
                final X509Certificate x509Cert) {

        if (certLogger == null) {
            return;
        }

        // generate our cert object log record and log it
        // with the given logger

        try {
            certLogger.info(logRecord(principal, ip, provider, instanceId, x509Cert));
        } catch (Exception ex) {
            LOGGER.error("Unable to generate certificate log record: {}", ex.getMessage());
        }
    }

    public static String logRecord(final Principal principal, final String ip, final String provider,
            final String instanceId, final X509Certificate x509Cert) {

        StringBuilder buf = TLS_BUILDER.get();
        buf.setLength(0);

        // our format is going to be as follows
        // <ip> <principal> <provider> <instance-id> <subject> <issuer> <serial> <expiry-date>

        buf.append(ip);
        buf.append(' ');

        // now append our principal. if this is an instance register
        // operation then we have no principal so we're going to
        // just use - to indicate no principal

        if (principal != null) {
            buf.append(principal.getFullName());
        } else {
            buf.append('-');
        }
        buf.append(' ');

        // next our provider

        buf.append(provider);
        buf.append(' ');

        // next our instance id

        if (instanceId != null) {
            buf.append('"');
            buf.append(instanceId);
            buf.append('"');
        } else {
            buf.append('-');
        }
        buf.append(' ');

        // next our subject

        buf.append('"');
        buf.append(x509Cert.getSubjectX500Principal().getName());
        buf.append('"');
        buf.append(' ');

        // next we have our issuer

        buf.append('"');
        buf.append(x509Cert.getIssuerX500Principal().getName());
        buf.append('"');
        buf.append(' ');

        // next we have our serial number

        buf.append(x509Cert.getSerialNumber().toString());
        buf.append(' ');

        // finally we have our expiry date in milliseconds

        buf.append(x509Cert.getNotAfter().getTime());

        return buf.toString();
    }
}
