/**
 * Copyright 2017 Yahoo Inc.
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
package com.yahoo.athenz.example.centralized_authz;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.FileInputStream;
import java.io.InputStream;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import com.yahoo.athenz.zms.ZMSClientException;
import com.yahoo.athenz.zms.Access;

import com.yahoo.athenz.zms.ZMSClient;
import java.util.Enumeration;
import java.security.KeyStore;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.util.*;
import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;
import javax.net.ssl.SSLContext;

/*
  Very basic servlet.
*/
public class RecServlet extends HttpServlet {
    
    private static final long serialVersionUID = 2846506476975366921L;

    static final String URI_PREFIX = "/athenz-control/rec/v1";
    public static final String JAVAX_CERT_ATTR = "javax.servlet.request.X509Certificate";
    private String trustedIssuesFilePath = null;
    private List<String> trustedIssuers = new ArrayList<String>();
    private ZMSClient zmsClient = null;

    public void init() throws ServletException {
        String zmsUrl = System.getenv("ZMS_SERVER_URL");
        trustedIssuesFilePath = System.getenv("ATHENZ_ISSUERS_FILEPATH");
        String servletKeyPath = System.getenv("REC_SERVLET_ATHENZ_KEY_PATH");
        String servletCertPath = System.getenv("REC_SERVLET_ATHENZ_CERT_PATH");
        String servletTruststorePath = System.getenv("REC_SERVLET_ATHENZ_TRUSTSTORE_PATH");
        String servletTruststorePassword = System.getenv("REC_SERVLET_ATHENZ_TRUSTSTORE_PASSWORD");

        try {
            // Create our SSL Context object based on our private key and
            // certificate and jdk truststore

            KeyRefresher keyRefresher = Utils.generateKeyRefresher(servletTruststorePath, servletTruststorePassword,
                    servletCertPath, servletKeyPath);
            // Default refresh period is every hour.
            keyRefresher.startup();
            // Can be adjusted to use other values in milliseconds. However,
            // only one keyRefresher.startup call must be present.
            // keyRefresher.startup(900000);
            SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                    keyRefresher.getTrustManagerProxy());
            zmsClient = new ZMSClient(zmsUrl, sslContext);

        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
            ex.printStackTrace();
            System.exit(1);
        }

    }

    protected void doGet(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {

        // retrieve and verify that our request contains an Athenz
        // service X509 certificate
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(JAVAX_CERT_ATTR);
        X509Certificate x509cert = null;
        if (null != certs && certs.length != 0) {
            for (X509Certificate cert: certs) {
                if (null != cert) {
                    //find the first occurrence of non-null certificate
                    x509cert = cert;
                    break;
                }
            }
        }

        if (null == x509cert) {
            // fail as x509cert is missing
            response.sendError(403, "Forbidden - No Athenz X509 certificate provided in request");
            return;
        }

        // Initiate the valid issuers
        setX509CAIssuers(trustedIssuesFilePath);

        // validate the certificate against CAs
        X500Principal issuerx500Principal = x509cert.getIssuerX500Principal();
        String issuer = issuerx500Principal.getName();
        if (issuer == null || issuer.isEmpty()
                || !trustedIssuers.contains(issuer)) {
            //fail
            response.sendError(403, "Forbidden - X509 certificate issuer is not valid");
            return;
        }

        // our request starts with /athenz-control/rec/v1 so we're
        // going to skip that prefix
        try {
            String reqUri = request.getRequestURI().substring(URI_PREFIX.length());
            String responseText;
            String athenzResource;
            String athenzAction;
            switch (reqUri) {
                case "/movie":
                    responseText = "Name: Slap Shot; Director: George Roy Hill";
                    athenzResource = "rec.movie";
                    athenzAction = "read";
                    break;
                case "/tvshow":
                    responseText = "Name: Middle; Channel: ABC";
                    athenzResource = "rec.tvshow";
                    athenzAction = "read";
                    break;
                default:
                    response.sendError(404, "Unknown endpoint");
                    return;
            }

            // carry out the authorization check with the expected resource
            // and action values
            String principalName = x509cert.getSubjectX500Principal().getName();
            Access access = zmsClient.getAccess(athenzAction, athenzResource, null, principalName);
            boolean authorized = access.getGranted();
            if (!authorized) {
                response.sendError(403, "Forbidden - Athenz Authorization Rejected");
                return;
            }

            response.setContentType("text/plain");
            PrintWriter out = response.getWriter();
            out.println(responseText);
        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
            ex.printStackTrace();
            System.exit(1);
        }
    }

    protected void doPut(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
    }

    protected void doPost(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
    }

    protected void doDelete(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
    }

    private final void setX509CAIssuers(final String issuersFileName) {
        try {
            if (issuersFileName == null || issuersFileName.isEmpty()) {
                return;
            }
            Path path = Paths.get(issuersFileName);
            if (!path.isAbsolute()) {
                path = Paths.get(getClass().getClassLoader().getResource(issuersFileName).toURI());
            }

            KeyStore ks = null;
            try (InputStream in = new FileInputStream(path.toString())) {
                ks = KeyStore.getInstance(KeyStore.getDefaultType());
                ks.load(in, null);
            }
            for (Enumeration<?> e = ks.aliases(); e.hasMoreElements(); ) {
                String alias = (String) e.nextElement();
                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                X500Principal issuerx500Principal = cert.getIssuerX500Principal();
                String issuer = issuerx500Principal.getName();
                trustedIssuers.add(issuer);
            }
        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
            ex.printStackTrace();
            System.exit(1);
        }
    }
}

