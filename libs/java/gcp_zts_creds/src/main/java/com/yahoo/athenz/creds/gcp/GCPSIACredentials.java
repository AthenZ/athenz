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
import com.yahoo.athenz.zts.InstanceRefreshInformation;
import com.yahoo.athenz.zts.InstanceRegisterInformation;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.config.TlsConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.TlsSocketStrategy;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.apache.hc.core5.http.ssl.TLS;
import org.apache.hc.core5.pool.PoolConcurrencyPolicy;
import org.apache.hc.core5.pool.PoolReusePolicy;
import org.apache.hc.core5.util.Timeout;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.GeneralName;

import javax.net.ssl.SSLContext;
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
    static String INSTANCE_ID_META_DATA_URL = "http://metadata/computeMetadata/v1/instance/id";

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
     * For GCP Cloud Functions generate a new private key,
     * request an x.509 certificate based on the requested CSR and return
     * both to the client in order to establish mtls connections with other
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

        final String instanceId = "gcp-function-" + gcpProjectId;
        return getWorkloadServiceCertificate(athenzDomain, athenzService, athenzProvider, ztsUrl,
                sanDNSDomain, rdnCountry, rdnState, rdnLocality, rdnOrganization, rdnOrganizationUnit,
                spiffeTrustDomain, instanceId, null);
    }

    /**
     * For GCP workloads generate a new private key,
     * request an x.509 certificate based on the requested CSR and return
     * both to the client in order to establish mtls connections with other
     * Athenz enabled services.
     * @param athenzDomain name of the domain
     * @param athenzService name of the service
     * @param athenzProvider name of the provider service for GCP Workloads
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
    public static X509KeyPair getGCPWorkloadServiceCertificate(String athenzDomain, String athenzService,
            String athenzProvider, String ztsUrl, String sanDNSDomain, String rdnCountry,
            String rdnState, String rdnLocality, String rdnOrganization, String rdnOrganizationUnit,
            String spiffeTrustDomain) throws Exception {

        final String instanceId = getGcpWorkloadInstanceId();
        return getWorkloadServiceCertificate(athenzDomain, athenzService, athenzProvider, ztsUrl,
                sanDNSDomain, rdnCountry, rdnState, rdnLocality, rdnOrganization, rdnOrganizationUnit,
                spiffeTrustDomain, instanceId, null);
    }

    /**
     * Refresh the registered instance with ZTS server by generating a new private key,
     * requesting a new x.509 certificate based on the generated CSR and return
     * both to the client in order to establish mtls connections with other
     * Athenz enabled services. The client is required to provide the SSLContext
     * that was created based on the previous certificate and private key.
     * @param athenzDomain name of the domain
     * @param athenzService name of the service
     * @param athenzProvider name of the provider service for GCP Workloads
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
     * @param sslContext SSLContext that was created based on the previous certificate and private key.
     * @return private key and certificate from ZTS server.
     */
    public static X509KeyPair refreshGCPWorkloadServiceCertificate(String athenzDomain, String athenzService,
            String athenzProvider, String ztsUrl, String sanDNSDomain, String rdnCountry,
            String rdnState, String rdnLocality, String rdnOrganization, String rdnOrganizationUnit,
            String spiffeTrustDomain, SSLContext sslContext) throws Exception {

        final String instanceId = getGcpWorkloadInstanceId();
        return getWorkloadServiceCertificate(athenzDomain, athenzService, athenzProvider, ztsUrl,
                sanDNSDomain, rdnCountry, rdnState, rdnLocality, rdnOrganization, rdnOrganizationUnit,
                spiffeTrustDomain, instanceId, sslContext);
    }

    private static X509KeyPair getWorkloadServiceCertificate(String athenzDomain, String athenzService,
            String athenzProvider, String ztsUrl, String sanDNSDomain, String rdnCountry,
            String rdnState, String rdnLocality, String rdnOrganization, String rdnOrganizationUnit,
            String spiffeTrustDomain, String instanceId, SSLContext sslContext) throws Exception {

        athenzDomain = athenzDomain.toLowerCase();
        athenzService = athenzService.toLowerCase();
        athenzProvider = athenzProvider.toLowerCase();
        final String athenzPrincipal = athenzDomain + "." + athenzService;

        // Build the certificate's Subject fields - as a single string.
        // At the end, certDn would look something like this:    "c=US, s=CA, ou=Eng"

        final String certDn = buildCertDn(rdnCountry, rdnState, rdnLocality, rdnOrganization, rdnOrganizationUnit);

        // Get GCP attestation data for GCP Function.

        final String attestationData = getGcpAttestationData(ztsUrl);

        // Generate a private-key.

        X509KeyPair response = new X509KeyPair();
        response.privateKey = Crypto.generateRSAPrivateKey(2048);
        response.privateKeyPem = Crypto.convertToPEMFormat(response.privateKey);

        // Build the Alternative DNS names (SAN's).

        GeneralName[] sanArray = buildAlternativeDnsNames(athenzDomain, athenzService, athenzProvider,
                sanDNSDomain, spiffeTrustDomain, instanceId);

        // Build a CSR.

        final String x500Principal = certDn.isEmpty() ? "cn=" + athenzPrincipal : certDn + ",cn=" + athenzPrincipal;
        String csr = Crypto.generateX509CSR(response.privateKey, x500Principal, sanArray);

        // Request the Athenz certificate from ZTS server. If the SSL Context is provided,
        // then it's a refresh operation as opposed to a new register operation

        InstanceIdentity identity = sslContext == null ?
                postInstanceRegisterInformation(athenzDomain, athenzService, athenzProvider, ztsUrl,
                        attestationData, csr) :
                postInstanceRefreshInformation(athenzDomain, athenzService, athenzProvider, instanceId,
                        ztsUrl, attestationData, csr, sslContext);

        response.certificatePem = identity.x509Certificate;
        response.certificate = Crypto.loadX509Certificate(identity.x509Certificate);
        response.caCertificatesPem = identity.x509CertificateSigner;
        return response;
    }

    /**
     * Build the certificate's Subject fields - as a single string.
     * At the end, certDn would look something like this: "c=US, s=CA, ou=Eng"
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
            certDn += "ou=" + rdnOrganizationUnit;
        }
        return certDn.replaceAll(", $", "");   // Remove dangling ", " tail
    }

    /** Get GCP attestation data for GCP Workloads */
    private static String getGcpAttestationData(String ztsUrl) throws Exception {
        final String identityToken = getGcpMetadata(ATTESTATION_DATA_URL_PREFIX + ztsUrl);
        return "{\"identityToken\":\"" + identityToken + "\"}";
    }

    /** Get GCP workload instance id */
    private static String getGcpWorkloadInstanceId() throws Exception {
        return getGcpMetadata(INSTANCE_ID_META_DATA_URL);
    }

    private static String getGcpMetadata(final String url) throws Exception {
        HttpURLConnection httpConnection = null;
        try {
            httpConnection = (HttpURLConnection) new URL(url).openConnection();
            httpConnection.setRequestMethod("GET");
            httpConnection.setRequestProperty("Metadata-Flavor", "Google");
            httpConnection.setConnectTimeout(ATTESTATION_CONNECT_TIMEOUT_MS);
            httpConnection.setReadTimeout(ATTESTATION_READ_TIMEOUT_MS);
            int status = httpConnection.getResponseCode();
            String responseData = new String(httpConnection.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            if (status != 200) {
                throw new Exception("Unable to obtain metadata from \"" + url + "\" : HTTP code " + status);
            }
            return responseData;
        } catch (IOException exception) {
            throw new Exception("Unable to obtain metadata from \"" + url + "\" : ", exception);
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
            final String athenzProvider, final String sanDNSDomain, final String spiffeTrustDomain,
            final String instanceId) {

        return new GeneralName[]{
                new GeneralName(
                        GeneralName.dNSName,
                        new DERIA5String(athenzService + '.' + athenzDomain.replace('.', '-') + '.' + sanDNSDomain)),
                new GeneralName(
                        GeneralName.uniformResourceIdentifier,
                        new DERIA5String(getSpiffeUri(spiffeTrustDomain, athenzDomain, athenzService))),
                new GeneralName(
                        GeneralName.uniformResourceIdentifier,
                        new DERIA5String("athenz://instanceid/" + athenzProvider + "/" + instanceId)),
        };
    }

    /** Request the Athenz certificate from ZTS server */
    private static InstanceIdentity postInstanceRefreshInformation(final String athenzDomain,
            final String athenzService, final String athenzProvider, final String athenzInstanceId, final String ztsUrl,
            final String attestationData, final String csr, SSLContext sslContext) throws Exception {

        // construct the payload and http uri request for the refresh operation

        InstanceRefreshInformation postPayloadObject = new InstanceRefreshInformation()
                .setAttestationData(attestationData)
                .setCsr(csr);

        final String uri = ztsUrl + "/instance/" + athenzProvider + "/" + athenzDomain + "/" +
                athenzService + "/" + athenzInstanceId;

        final String postPayload = OBJECT_MAPPER.writeValueAsString(postPayloadObject);
            HttpEntity httpEntity = new StringEntity(postPayload, ContentType.APPLICATION_JSON);
            ClassicHttpRequest httpUriRequest = ClassicRequestBuilder.post()
                    .setUri(uri)
                    .setEntity(httpEntity)
                    .addHeader("Content-Type", "application/json")
                    .build();

        return getServiceIdentity(httpUriRequest, sslContext);
    }

    /** Request the Athenz certificate from ZTS server */
    private static InstanceIdentity postInstanceRegisterInformation(final String athenzDomain,
            final String athenzService, final String athenzProvider, final String ztsUrl,
            final String attestationData, final String csr) throws Exception {

        // construct the payload and http uri request for the register operation

        InstanceRegisterInformation postPayloadObject = new InstanceRegisterInformation()
                .setDomain(athenzDomain)
                .setService(athenzService)
                .setProvider(athenzProvider)
                .setAttestationData(attestationData)
                .setCsr(csr);

        final String postPayload = OBJECT_MAPPER.writeValueAsString(postPayloadObject);
        HttpEntity httpEntity = new StringEntity(postPayload, ContentType.APPLICATION_JSON);
        ClassicHttpRequest httpUriRequest = ClassicRequestBuilder.post()
                .setUri(ztsUrl + "/instance")
                .setEntity(httpEntity)
                .addHeader("Content-Type", "application/json")
                .build();

        return getServiceIdentity(httpUriRequest, null);
    }

    protected static PoolingHttpClientConnectionManager createConnectionPooling(SSLContext sslContext) {

        // if we're not given an ssl context then there is no need to
        // create a connection pooling manager

        if (sslContext == null) {
            return null;
        }

        final TlsSocketStrategy tlsStrategy = new DefaultClientTlsStrategy(sslContext);

        return PoolingHttpClientConnectionManagerBuilder.create()
                .setTlsSocketStrategy(tlsStrategy)
                .setDefaultTlsConfig(TlsConfig.custom()
                        .setSupportedProtocols(TLS.V_1_2, TLS.V_1_3)
                        .build())
                .setPoolConcurrencyPolicy(PoolConcurrencyPolicy.STRICT)
                .setConnPoolPolicy(PoolReusePolicy.LIFO)
                .setDefaultConnectionConfig(ConnectionConfig.custom()
                        .setSocketTimeout(Timeout.ofMilliseconds(ZTS_READ_TIMEOUT_MS))
                        .setConnectTimeout(Timeout.ofMilliseconds(ZTS_CONNECT_TIMEOUT_MS))
                        .build())
                .build();
    }

    /** Request the Athenz certificate from ZTS server */

    private static InstanceIdentity getServiceIdentity(ClassicHttpRequest httpUriRequest, SSLContext sslContext)
            throws Exception {

        PoolingHttpClientConnectionManager connectionManager = createConnectionPooling(sslContext);

        // Construct an HTTP client.

        RequestConfig config = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .build();

        try (CloseableHttpClient httpClient = HttpClients.custom()
                .setDefaultRequestConfig(config)
                .setConnectionManager(connectionManager)
                .build()) {

            // Execute the request and process the response.
            HttpEntity httpResponseEntity = null;
            try (CloseableHttpResponse httpResponse = httpClient.execute(httpUriRequest)) {
                int statusCode = httpResponse.getCode();
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
