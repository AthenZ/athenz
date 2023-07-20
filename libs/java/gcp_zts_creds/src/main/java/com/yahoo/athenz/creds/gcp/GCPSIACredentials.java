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
package com.yahoo.athenz.creds.gcp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zts.InstanceIdentity;
import com.yahoo.athenz.zts.InstanceRegisterInformation;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.GeneralName;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class GCPSIACredentials {

    // Configurations.
    public static int ZTS_CONNECT_TIMEOUT_MS = 5000;
    public static int ZTS_READ_TIMEOUT_MS = 30000;
    public static int ATTESTATION_CONNECT_TIMEOUT_MS = ZTS_CONNECT_TIMEOUT_MS;
    public static int ATTESTATION_READ_TIMEOUT_MS = ZTS_READ_TIMEOUT_MS;

    static String ATTESTATION_DATA_URL_PREFIX = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?format=full&audience=";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /** Response of {@link #getGCPFunctionServiceCertificate} */
    public static class X509KeyPair {
        public X509Certificate certificate;
        public String          certificatePem;
        public PrivateKey      privateKey;
        public String          privateKeyPem;
        public String          caCertificatesPem;
    }

    /**
     * For GCP cloud-functions generate a new private key, request an
     * x.509 certificate based on the requested CSR and return both to
     * the client in order to establish tls connections with other
     * Athenz enabled services.
     * @param athenzDomain name of the domain
     * @param athenzService name of the service
     * @param gcpProjectId GCP project-id that the function runs in
     * @param athenzProvider name of the provider service for GCP Cloud-Functions
     * @param ztsUrl ZTS Server URL e.g. https://zts.athenz.io:4443/zts/v1
     * @param sanDNSDomain String identifying the DNS domain for generating SAN fields.
     *                     For example, for the domain "sports", service "api" and certDomain "athenz.io",
     *                     the sanDNS entry in the certificate will be set to "api.sports.athenz.io"
     * @param rdnCountry Optional field in the certificate's Subject rdn (relative distinguished name).
     * @param rdnState Optional field in the certificate's Subject rdn (relative distinguished name).
     * @param rdnLocality Optional field in the certificate's Subject rdn (relative distinguished name).
     * @param rdnOrganization Optional field in the certificate's Subject rdn (relative distinguished name).
     * @param rdnOrganizationUnit Optional field in the certificate's Subject rdn (relative distinguished name).
     * @param spiffeTrustDomain Optional spiffe trust domain
     * @return private key and certificate from ZTS server.
     */
    public static X509KeyPair getGCPFunctionServiceCertificate(String athenzDomain, String athenzService,
            String gcpProjectId, String athenzProvider, String ztsUrl, String sanDNSDomain, String rdnCountry,
            String rdnState, String rdnLocality, String rdnOrganization, String rdnOrganizationUnit,
            String spiffeTrustDomain) throws Exception {

        athenzDomain = athenzDomain.toLowerCase();
        athenzService = athenzService.toLowerCase();
        athenzProvider = athenzProvider.toLowerCase();
        String athenzPrincipal = athenzDomain + "." + athenzService;

        // Build the certificate's Subject fields - as a single string.
        // At the end, certDn would look something like this:    "c=US, s=CA, ou=Eng"
        String certDn = buildCertDn(rdnCountry, rdnState, rdnLocality, rdnOrganization, rdnOrganizationUnit);

        // Get GCP attestation data for GCP Function.
        String attestationData = getGcpFunctionAttestationData(ztsUrl);

        // Generate a private-key.
        X509KeyPair response = new X509KeyPair();
        response.privateKey = Crypto.generateRSAPrivateKey(2048);
        response.privateKeyPem = Crypto.convertToPEMFormat(response.privateKey);

        // Build the Alternative DNS names (SAN's).
        GeneralName[] sanArray = buildAlternativeDnsNames(athenzDomain, athenzService, athenzProvider,
                gcpProjectId, sanDNSDomain, spiffeTrustDomain);

        // Build a CSR.
        String csr = Crypto.generateX509CSR(
                response.privateKey,
                certDn + ",cn=" + athenzPrincipal, sanArray);

        // Request the Athenz certificate from ZTS server.
        InstanceIdentity identity = postInstanceRegisterInformation(athenzDomain, athenzService,
                athenzProvider, ztsUrl, attestationData, csr);

        response.certificatePem = identity.x509Certificate;
        response.certificate = Crypto.loadX509Certificate(identity.x509Certificate);
        response.caCertificatesPem = identity.x509CertificateSigner;
        return response;
    }

    /**
     * Build the certificate's Subject fields - as a single string.
     * At the end, certDn would look something like this:    "c=US, s=CA, ou=Eng"
     */
    private static String buildCertDn(final String rdnCountry, final String rdnState, final String rdnLocality,
            final String rdnOrganization, final String rdnOrganizationUnit) {

        String certDn = "";
        if ((rdnCountry != null) && (!rdnCountry.isEmpty())) {
            certDn += "c=" + rdnCountry + ", ";
        }
        if ((rdnState != null) && (!rdnState.isEmpty())) {
            certDn += "s=" + rdnState + ", ";
        }
        if ((rdnLocality != null) && (!rdnLocality.isEmpty())) {
            certDn += "l=" + rdnLocality + ", ";
        }
        if ((rdnOrganization != null) && (!rdnOrganization.isEmpty())) {
            certDn += "o=" + rdnOrganization + ", ";
        }
        if ((rdnOrganizationUnit != null) && (!rdnOrganizationUnit.isEmpty())) {
            certDn += "ou=" + rdnOrganizationUnit + ", ";
        }
        return certDn.replaceAll(", $", "");   // Remove dangling ", " tail
    }

    /** Get GCP attestation data for GCP Function. */
    private static String getGcpFunctionAttestationData(String ztsUrl) throws Exception {
        String gcpIdentityUrl = ATTESTATION_DATA_URL_PREFIX + ztsUrl;
        HttpURLConnection httpConnection = null;
        try {
            httpConnection = (HttpURLConnection) new URL(gcpIdentityUrl).openConnection();
            httpConnection.setRequestMethod("GET");
            httpConnection.setRequestProperty("Metadata-Flavor", "Google");
            httpConnection.setConnectTimeout(ATTESTATION_CONNECT_TIMEOUT_MS);
            httpConnection.setReadTimeout(ATTESTATION_READ_TIMEOUT_MS);
            int status = httpConnection.getResponseCode();
            String identityToken = new String(httpConnection.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            if (status != 200) {
                throw new Exception("Unable to generate GCF attestation data from URL \"" + gcpIdentityUrl + "\" : HTTP code " + status + " != 200");
            }
            return "{\"identityToken\":\"" + identityToken + "\"}";
        } catch (IOException exception) {
            throw new Exception("Unable to generate GCF attestation data from URL \"" + gcpIdentityUrl + "\" : ", exception);
        } finally {
            if (httpConnection != null) {
                httpConnection.disconnect();
            }
        }
    }

    static String getSpiffeUri(final String spiffeTrustDomain, final String athenzDomain, final String athenzService) {
        if (spiffeTrustDomain != null && !spiffeTrustDomain.isEmpty()) {
            return "spiffe://" + spiffeTrustDomain + "/ns/default/sa/" + athenzDomain + "." + athenzService;
        } else {
            return "spiffe://" + athenzDomain + "/sa/" + athenzService;
        }
    }

    /** Build the Alternative DNS names (SAN's) */
    private static GeneralName[] buildAlternativeDnsNames(final String athenzDomain, final String athenzService,
            final String athenzProvider, final String gcpProjectId, final String sanDNSDomain,
            final String spiffeTrustDomain) {

        return new GeneralName[]{
                new GeneralName(
                        GeneralName.dNSName,
                        new DERIA5String(athenzService + '.' + athenzDomain.replace('.', '-') + '.' + sanDNSDomain)),
                new GeneralName(
                        GeneralName.uniformResourceIdentifier,
                        new DERIA5String(getSpiffeUri(spiffeTrustDomain, athenzDomain, athenzService))),
                new GeneralName(
                        GeneralName.uniformResourceIdentifier,
                        new DERIA5String("athenz://instanceid/" + athenzProvider + "/gcp-function-" + gcpProjectId)),
        };
    }

    /** Request the Athenz certificate from ZTS server */
    private static InstanceIdentity postInstanceRegisterInformation(final String athenzDomain,
            final String athenzService, final String athenzProvider, final String ztsUrl,
            final String attestationData, final String csr) throws Exception {

        // Construct an HTTP client.
        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout(ZTS_CONNECT_TIMEOUT_MS)
                .setSocketTimeout(ZTS_READ_TIMEOUT_MS)
                .setRedirectsEnabled(false)
                .build();
        try (CloseableHttpClient httpClient = HttpClients.custom()
                .setDefaultRequestConfig(config)
                .build()) {

            // Construct an HTTP POST request.
            InstanceRegisterInformation postPayloadObject = new InstanceRegisterInformation()
                    .setDomain(athenzDomain)
                    .setService(athenzService)
                    .setProvider(athenzProvider)
                    .setAttestationData(attestationData)
                    .setCsr(csr);

            final String postPayload = OBJECT_MAPPER.writeValueAsString(postPayloadObject);
            HttpEntity httpEntity = new StringEntity(postPayload, ContentType.APPLICATION_JSON);
            HttpUriRequest httpUriRequest = RequestBuilder.post()
                    .setUri(ztsUrl + "/instance")
                    .setEntity(httpEntity)
                    .addHeader("Content-Type", "application/json")
                    .build();

            // Execute the request and process the response.
            HttpEntity httpResponseEntity = null;
            try (CloseableHttpResponse httpResponse = httpClient.execute(httpUriRequest)) {
                int statusCode = httpResponse.getStatusLine().getStatusCode();
                httpResponseEntity = httpResponse.getEntity();
                if ((statusCode == 200) || (statusCode == 201)) {
                    return OBJECT_MAPPER.readValue(httpResponseEntity.getContent(), InstanceIdentity.class);
                } else {
                    final String errorBody = (httpResponseEntity == null) ? "<no response body>" : EntityUtils.toString(httpResponseEntity);
                    throw new Exception("Unable to register instance with Athenz. HTTP status: " + statusCode + ". Response: " + errorBody);
                }
            } finally {
                EntityUtils.consumeQuietly(httpResponseEntity);
            }
        }
    }
}
