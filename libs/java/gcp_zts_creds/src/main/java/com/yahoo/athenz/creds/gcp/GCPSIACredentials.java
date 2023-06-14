package com.yahoo.athenz.creds.gcp;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.util.Crypto;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.invoke.MethodHandles;
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

    /** Response of {@link #getGCPFunctionServiceCertificate} */
    public static class PrivateAndCertificate {
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
     * @param ztsUrl Something like: https://...:.../zts/v1
     * @param certDomain TODO: Abhijeet - explain what this is...
     * @param optionalCountry Optional field in the certificate's Subject.
     * @param optionalState Optional field in the certificate's Subject.
     * @param optionalLocality Optional field in the certificate's Subject.
     * @param optionalOrganization Optional field in the certificate's Subject.
     * @param optionalOrganizationUnit Optional field in the certificate's Subject.
     * @return GCPFunctionIdentity with private key and certificate
     */
    public static PrivateAndCertificate getGCPFunctionServiceCertificate(
            String athenzDomain,
            String athenzService,
            String gcpProjectId,
            String athenzProvider,
            String ztsUrl,
            String certDomain,
            String optionalCountry,
            String optionalState,
            String optionalLocality,
            String optionalOrganization,
            String optionalOrganizationUnit)
            throws Exception {

        athenzDomain   = athenzDomain.toLowerCase();
        athenzService  = athenzService.toLowerCase();
        athenzProvider = athenzProvider.toLowerCase();
        String athenzPrincipal = athenzDomain + "." + athenzService;

        // Build the certificate's Subject fields - as a single string.
        // At the end, certDn would look something like this:    "c=US, s=CA, ou=Eng"
        // Build the certificate's Subject fields - as a single string.
        // At the end, certDn would look something like this:    "c=US, s=CA, ou=Eng"
        String certDn = buildCertDn(
                optionalCountry,
                optionalState,
                optionalLocality,
                optionalOrganization,
                optionalOrganizationUnit);

        // Get GCP attestation data for GCP Function.
        String attestationData = getGcpFunctionAttestationData(ztsUrl);

        // Generate a private-key.
        PrivateAndCertificate response = new PrivateAndCertificate();
        response.privateKey = Crypto.generateRSAPrivateKey(2048);
        response.privateKeyPem = Crypto.convertToPEMFormat(response.privateKey);

        // Build the Alternative DNS names (SAN's).
        GeneralName[] sanArray = buildAlternativeDnsNames(
                athenzDomain,
                athenzService,
                gcpProjectId,
                certDomain);

        // Build a CSR.
        String csr = Crypto.generateX509CSR(
                response.privateKey,
                "cn=" + athenzPrincipal + ',' + certDn, sanArray);

        // Request the Athenz certificate from ZTS server.
        InstanceIdentity identity = postInstanceRegisterInformation(
                athenzDomain,
                athenzService,
                athenzProvider,
                ztsUrl,
                attestationData,
                csr);

        response.certificatePem = identity.x509Certificate;
        response.certificate = Crypto.loadX509Certificate(identity.x509Certificate);
        response.caCertificatesPem = identity.x509CertificateSigner;
        return response;
    }

    /**
     * Build the certificate's Subject fields - as a single string.
     * At the end, certDn would look something like this:    "c=US, s=CA, ou=Eng"
     */
    private static String buildCertDn(
            String optionalCountry,
            String optionalState,
            String optionalLocality,
            String optionalOrganization,
            String optionalOrganizationUnit) {
        String certDn = "";
        if ((optionalCountry != null) && (!optionalCountry.isEmpty())) {
            certDn += "c=" + optionalCountry + ", ";
        }
        if ((optionalState != null) && (!optionalState.isEmpty())) {
            certDn += "s=" + optionalState + ", ";
        }
        if ((optionalLocality != null) && (!optionalLocality.isEmpty())) {
            certDn += "l=" + optionalLocality + ", ";
        }
        if ((optionalOrganization != null) && (!optionalOrganization.isEmpty())) {
            certDn += "o=" + optionalOrganization + ", ";
        }
        if ((optionalOrganizationUnit != null) && (!optionalOrganizationUnit.isEmpty())) {
            certDn += "ou=" + optionalOrganizationUnit + ", ";
        }
        return certDn.replaceAll(", $", "");   // Remove dangling ", " tail
    }

    /** Get GCP attestation data for GCP Function. */
    private static String getGcpFunctionAttestationData(String ztsUrl) throws Exception {
        String gcpIdentityUrl = ATTESTATION_DATA_URL_PREFIX + ztsUrl;
        // LOG.debug("Getting GCF attestation-data from: {}", gcpIdentityUrl);
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
            // LOG.debug("GCF attestation-data: {}", identityToken);
            return "{\"identityToken\":\"" + identityToken + "\"}";
        } catch (IOException exception) {
            throw new Exception("Unable to generate GCF attestation data from URL \"" + gcpIdentityUrl + "\" : ", exception);
        } finally {
            if (httpConnection != null) {
                httpConnection.disconnect();
            }
        }
    }

    /** Build the Alternative DNS names (SAN's) */
    private static GeneralName[] buildAlternativeDnsNames(
            String athenzDomain,
            String athenzService,
            String gcpProjectId,
            String certDomain) {
        return new GeneralName[]{
                new GeneralName(
                        GeneralName.dNSName,
                        new DERIA5String(athenzService + '.' + athenzDomain.replace('.', '-') + '.' + certDomain)),
                new GeneralName(
                        GeneralName.dNSName,
                        new DERIA5String("gcf-" + gcpProjectId + '-' + athenzService + ".instanceid.athenz." + certDomain)),    // TODO: Not sure about this
                new GeneralName(
                        GeneralName.uniformResourceIdentifier,
                        new DERIA5String("spiffe://" + athenzDomain + "/sa/" + athenzService)),
        };
    }

    /** Request the Athenz certificate from ZTS server */
    private static InstanceIdentity postInstanceRegisterInformation(
            String athenzDomain,
            String athenzService,
            String athenzProvider,
            String ztsUrl,
            String attestationData,
            String csr)
            throws Exception {

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
            String postPayload = "{" +
                    "\"domain\": " + OBJECT_MAPPER.writeValueAsString(athenzDomain) + "," +
                    "\"service\": " + OBJECT_MAPPER.writeValueAsString(athenzService) + "," +
                    "\"provider\": " + OBJECT_MAPPER.writeValueAsString(athenzProvider) + "," +
                    "\"attestationData\": " + OBJECT_MAPPER.writeValueAsString(attestationData) + "," +
                    "\"csr\": " + OBJECT_MAPPER.writeValueAsString(csr) +
                    "}";
            // LOG.debug("Getting identity from ZTS: requesting \"{}/instance\" with payload: {}", ztsUrl, postPayload);
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
                    InstanceIdentity response = OBJECT_MAPPER.readValue(httpResponseEntity.getContent(), InstanceIdentity.class);
                    // LOG.debug("Got identity from ZTS:    x509Certificate={}    x509CertificateSigner={}", OBJECT_MAPPER.writeValueAsString(response.x509Certificate), OBJECT_MAPPER.writeValueAsString(response.x509CertificateSigner));
                    return response;
                } else {
                    final String errorBody = (httpResponseEntity == null) ? "<no response body>" : EntityUtils.toString(httpResponseEntity);
                    throw new Exception("Unable to register instance with Athenz. HTTP status: " + statusCode + ". Response: " + errorBody);
                }
            } finally {
                EntityUtils.consumeQuietly(httpResponseEntity);
            }
        }
    }

    /** Used to parse ZTS response */
    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class InstanceIdentity {
        public String x509Certificate;
        public String x509CertificateSigner;
    }

    static String ATTESTATION_DATA_URL_PREFIX = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?format=full&audience=";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
}
