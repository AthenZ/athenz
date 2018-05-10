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
package com.yahoo.athenz.example.instance.provider;

import java.io.File;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.rdl.JSON;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;

public class InstanceProviderHandlerImpl implements InstanceProviderHandler {

    private final String PROP_PROVIDER_NAME = "instance.provider_name";
    private final String PROP_PROVIDER_KEY_PATH = "instance.provider_key_path";
    private final String INSTANCE_ID = "instance-id";
    private final String JAVAX_CERT_ATTR = "javax.servlet.request.X509Certificate";

    private String instanceProvider;
    private PrivateKey providerKey;
    
    public InstanceProviderHandlerImpl() {
        
        instanceProvider = System.getProperty(PROP_PROVIDER_NAME);
        final String keyPath = System.getProperty(PROP_PROVIDER_KEY_PATH);
        providerKey = Crypto.loadPrivateKey(new File(keyPath));
    }

    @Override
    public ResourceContext newResourceContext(HttpServletRequest request, HttpServletResponse response) {
        return new ResourceContextImpl(request, response);
    }

    @Override
    public InstanceConfirmation postInstanceConfirmation(ResourceContext context,
            InstanceConfirmation confirmation) {
        
        System.out.println("Processing postInstanceConfirmation...");
        System.out.println(JSON.string(confirmation));
        
        // first checkout if we have established mutual tls
        // with the zts server and output the common name
        // of the certificate received
        
        HttpServletRequest servletRequest = context.request();
        X509Certificate[] certs = (X509Certificate[]) servletRequest.getAttribute(JAVAX_CERT_ATTR);
        X509Certificate x509cert = null;
        if (null != certs && certs.length != 0) {
            for (X509Certificate cert: certs) {
                System.out.println("Certificate CN: " + Crypto.extractX509CertCommonName(cert));
            }
        } else {
            System.out.println("No certificates were presented by ZTS Server");
        }
        
        // our attestation data is jws so we're going to validate
        // the signature first to make sure that it was signed by us
        
        Jws<Claims> claims = null;
        try {
            claims = Jwts.parser().setSigningKey(providerKey)
                .parseClaimsJws(confirmation.getAttestationData());
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        
        // we're going to verify that issuer specified in jwt
        // is indeed ourselves
        
        final String provider = claims.getBody().getIssuer();
        if (!instanceProvider.equals(provider)) {
            throw new ResourceException(ResourceException.BAD_REQUEST,
                    "Unknown provider: " + provider);
        }
        
        // we can do other validation possibly - maybe checking
        // with our manager service that the given instance
        // was indeed booted for the given domain and service
        
        // we're going to extract the instance id from our
        // attestation data and return that as part of the
        // confirmation object
        
        final String instanceId = claims.getBody().getId();
        Map<String, String> attributes = new HashMap<>();
        attributes.put(INSTANCE_ID, instanceId);
        confirmation.setAttributes(attributes);
        
        return confirmation;
    }
    
    @Override
    public InstanceConfirmation postRefreshConfirmation(ResourceContext context,
            InstanceConfirmation confirmation) {
        
        System.out.println("Processing postRefreshConfirmation...");
        System.out.println(JSON.string(confirmation));
        
        // our attestation data is jws so we're going to validate
        // the signature first to make sure that it was signed by us
        
        Jws<Claims> claims = null;
        try {
            claims = Jwts.parser().setSigningKey(providerKey)
                .parseClaimsJws(confirmation.getAttestationData());
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        
        // we're going to verify that issuer specified in jwt
        // is indeed ourselves
        
        final String provider = claims.getBody().getIssuer();
        if (!instanceProvider.equals(provider)) {
            throw new ResourceException(ResourceException.BAD_REQUEST,
                    "Unknown provider: " + provider);
        }
        
        // we can do other validation possibly - maybe checking
        // with our manager service that the given instance
        // was indeed booted for the given domain and service
        // and it is still running
        
        return confirmation;
    }
}
