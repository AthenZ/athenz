package com.yahoo.athenz.creds.gcp;

import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSClient;
import com.yahoo.athenz.zts.ZTSClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class GCPSIACredentials {

    private static final Logger LOG = LoggerFactory.getLogger(ZTSClient.class);

    /**
     * For GCP cloud-functions generate a new private key, request a
     * x.509 certificate based on the requested CSR and return both to
     * the client in order to establish tls connections with other
     * Athenz enabled services.
     * @param domainName name of the domain
     * @param serviceName name of the service
     * @param gcpProjectId GCP project-id that the function runs in
     * @param provider name of the provider service for GCP Cloud-Functions
     * @return GCPFunctionIdentity with private key and certificate
     */
    public static GCPFunctionIdentity getGCPFunctionServiceCertificate(
            ZTSClient ztsClient,
            String domainName,
            String serviceName,
            String gcpProjectId,
            String provider) {

        if (gcpProjectId == null || provider == null) {
            throw new IllegalArgumentException("GCP gcpProjectId and Provider must be specified");
        }

        String attestationData = getGcpFunctionAttestationData(ztsClient.getZTSUrl());

        GCPFunctionIdentity cloudIdentity = new GCPFunctionIdentity();

        ztsClient.getCloudServiceCertificate(
                domainName,
                serviceName,
                "gcf-" + gcpProjectId,  // TODO: Not sure about this
                provider,
                attestationData,
                cloudIdentity);

        return cloudIdentity;
    }

    static String getGcpFunctionAttestationData(String ztsUrl) {

        String gcpIdentityUrl = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=" + ztsUrl + "&format=full";
        LOG.debug("Getting GCF identity from: {}", gcpIdentityUrl);
        HttpURLConnection httpConnection = null;
        try {
            httpConnection = (HttpURLConnection) new URL(gcpIdentityUrl).openConnection();
            httpConnection.setRequestMethod("GET");
            httpConnection.setRequestProperty("Metadata-Flavor", "Google");
            int status = httpConnection.getResponseCode();
            String identityToken = new String(httpConnection.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            if (status != 200) {
                throw new IOException("HTTP code " + status + " != 200");
            }
            return "{\"identityToken\":\"" + identityToken + "\"}";
        } catch (IOException ex) {
            LOG.error("Unable to generate GCF attestation data from URL \"{}\" : {}", gcpIdentityUrl, ex.getMessage());
            throw new ZTSClientException(ResourceException.BAD_REQUEST, ex.getMessage());
        } finally {
            if (httpConnection != null) {
                httpConnection.disconnect();
            }
        }
    }
}
