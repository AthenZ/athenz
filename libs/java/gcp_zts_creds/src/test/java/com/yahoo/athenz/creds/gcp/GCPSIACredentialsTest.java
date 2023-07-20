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

import static org.testng.Assert.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.yahoo.athenz.zts.InstanceRegisterInformation;
import org.testng.annotations.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Scanner;

public class GCPSIACredentialsTest {

    private static final String MOCK_ATHENZ_CERT =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIDfTCCAwOgAwIBAgIRAJV1m8LU1u1CT9mLHk3GcjwwCgYIKoZIzj0EAwMwTzEL\n" +
                    "MAkGA1UEBhMCVVMxDjAMBgNVBAoTBVlhaG9vMRYwFAYDVQQLEw11cy13ZXN0LTIt\n" +
                    "Z2NwMRgwFgYDVQQDEw9ZYWhvbyBBdGhlbnogQ0EwHhcNMjMwNjEzMTQ1MDMyWhcN\n" +
                    "MjMwNjIwMTU1MDMyWjBCMQ0wCwYDVQQKEwRPYXRoMQ8wDQYDVQQLEwZBdGhlbnox\n" +
                    "IDAeBgNVBAMTF2NhbHlwc28ubm9ucHJvZC5iYXN0aW9uMIIBIjANBgkqhkiG9w0B\n" +
                    "AQEFAAOCAQ8AMIIBCgKCAQEA5XJzKNyFhYqaWnExqKQParzLaHA/yFA5ti/t4SrN\n" +
                    "qqxGNfi3jp3BQ2hQLl6TYzPd4YKLhAzGtczNLDYWA6rH0ASfNbjTN32FZHUi13zn\n" +
                    "A0txFiFZOFZQSgtrkoZb37oWHlvSXfgLJEdQsg04MXfC9/ph0eVzwbcxzcTVj3sV\n" +
                    "3IJlFqQDDmH/Hw7813Zhq3NKBP+hMMCcj4gyYSsCA8WJdElaCkykLgImSpVcwZEx\n" +
                    "Apvzvs2xLJ/RKqRHhar4GQsJLzS0w9qZ4hSBwePOcsvvy5bIah/Kg1gngUCqrBXX\n" +
                    "3C4GWDizL1WN0kksed0ISswWsIoSg2bCUWvErwYzggPNmQIDAQABo4IBADCB/TAO\n" +
                    "BgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMAwG\n" +
                    "A1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUU9M9M/IZIXQjG1SvHxT6qVFWaCUwgZwG\n" +
                    "A1UdEQSBlDCBkYInYmFzdGlvbi5jYWx5cHNvLW5vbnByb2QuZ2NwLnlhaG9vLmNs\n" +
                    "b3VkgkFnY2YtZ2NwLWNhbHlwc28tbm9ucHJvZC1iYXN0aW9uLmluc3RhbmNlaWQu\n" +
                    "YXRoZW56LmdjcC55YWhvby5jbG91ZIYjc3BpZmZlOi8vY2FseXBzby5ub25wcm9k\n" +
                    "L3NhL2Jhc3Rpb24wCgYIKoZIzj0EAwMDaAAwZQIxANhRx5w6RppPHTsaDhJQHva9\n" +
                    "/HOR8ZODbFJbPZUNzsA6G6E7KDcEwdFd6zhtkbPnKAIwa66aqHw+e3vdryynNpSF\n" +
                    "tpd0tFqsGKp1jjnmMIQ/g0usCxIXVMwF0UPywuh/qtf8\n" +
                    "-----END CERTIFICATE-----\n";

    private static final String MOCK_ATHENZ_CERT_JSON = '"' + MOCK_ATHENZ_CERT.replaceAll("\n", "\\\\n") + '"';
    private static final String MOCK_CA_CERTS = "-----BEGIN CERTIFICATE----- MOCK CA CERTIFICATES -----END CERTIFICATE-----";

    @Test
    public void testAllGood() throws Exception {
        GCPSIACredentials.ATTESTATION_DATA_URL_PREFIX = "http://localhost:7356/mock-gcf-attestation-data?zts=";
        MockGcfAttestationDataGoodHandler mockGcfAttestationDataHandler = new MockGcfAttestationDataGoodHandler();
        MockZtsInstanceGoodHandler mockZtsInstanceHandler = new MockZtsInstanceGoodHandler();
        try (AutoCloseable ignored = startHttpServerForAttestationAndZtsInstance(
                mockGcfAttestationDataHandler,
                mockZtsInstanceHandler)) {
            GCPSIACredentials.X509KeyPair x509KeyPair = GCPSIACredentials.getGCPFunctionServiceCertificate(
                    "athenzDomain",
                    "athenzService",
                    "gcpProjectId",
                    "athenzProvider",
                    "http://localhost:7356/mock-zts-instance",
                    "certDomain",
                    "optionalCountry",
                    "optionalState",
                    "optionalLocality",
                    "optionalOrganization",
                    "optionalOrganizationUnit",
                    "");
            assertEquals(mockGcfAttestationDataHandler.requestedUri, "/mock-gcf-attestation-data?zts=http://localhost:7356/mock-zts-instance");
            assertEquals(mockZtsInstanceHandler.requestedUri, "/mock-zts-instance/instance");
            InstanceRegisterInformation requestBody = new ObjectMapper().readValue(mockZtsInstanceHandler.requestedBody, InstanceRegisterInformation.class);
            assertEquals(requestBody.domain, "athenzdomain");
            assertEquals(requestBody.service, "athenzservice");
            assertEquals(requestBody.provider, "athenzprovider");
            assertEquals(requestBody.attestationData, "{\"identityToken\":\"<MOCK-ATTESTATION-DATA>\"}");
            assertEquals(x509KeyPair.certificatePem, MOCK_ATHENZ_CERT);
            assertEquals(x509KeyPair.caCertificatesPem, MOCK_CA_CERTS);
        }
    }

    @Test
    public void testAttestationInvalidCode() {
        GCPSIACredentials.ATTESTATION_DATA_URL_PREFIX = "http://localhost:7356/mock-gcf-attestation-data?zts=";
        MockGcfAttestationDataInvalidCodeHandler mockGcfAttestationDataHandler = new MockGcfAttestationDataInvalidCodeHandler();
        MockZtsInstanceGoodHandler mockZtsInstanceHandler = new MockZtsInstanceGoodHandler();
        try (AutoCloseable ignored = startHttpServerForAttestationAndZtsInstance(
                mockGcfAttestationDataHandler,
                mockZtsInstanceHandler)) {
            GCPSIACredentials.getGCPFunctionServiceCertificate(
                    "athenzDomain",
                    "athenzService",
                    "gcpProjectId",
                    "athenzProvider",
                    "http://localhost:7356/mock-zts-instance/instance",
                    "certDomain",
                    "optionalCountry",
                    "optionalState",
                    "optionalLocality",
                    "optionalOrganization",
                    "optionalOrganizationUnit",
                    "");
            fail("Should have thrown exception");
        } catch (Exception exception) {
            assertEquals(exception.getMessage(), "Unable to generate GCF attestation data from URL \"http://localhost:7356/mock-gcf-attestation-data?zts=http://localhost:7356/mock-zts-instance/instance\" : HTTP code 202 != 200");
        }
    }

    @Test
    public void testAttestationError() {
        GCPSIACredentials.ATTESTATION_DATA_URL_PREFIX = "http://localhost:7356/mock-gcf-attestation-data?zts=";
        MockGcfAttestationDataErrorHandler mockGcfAttestationDataHandler = new MockGcfAttestationDataErrorHandler();
        MockZtsInstanceGoodHandler mockZtsInstanceHandler = new MockZtsInstanceGoodHandler();
        try (AutoCloseable ignored = startHttpServerForAttestationAndZtsInstance(
                mockGcfAttestationDataHandler,
                mockZtsInstanceHandler)) {
            GCPSIACredentials.getGCPFunctionServiceCertificate(
                    "athenzDomain",
                    "athenzService",
                    "gcpProjectId",
                    "athenzProvider",
                    "http://localhost:7356/mock-zts-instance/instance",
                    "certDomain",
                    "optionalCountry",
                    "optionalState",
                    "optionalLocality",
                    "optionalOrganization",
                    "optionalOrganizationUnit",
                    null);
            fail("Should have thrown exception");
        } catch (Exception exception) {
            assertEquals(exception.getMessage(), "Unable to generate GCF attestation data from URL \"http://localhost:7356/mock-gcf-attestation-data?zts=http://localhost:7356/mock-zts-instance/instance\" : ");
        }
    }

    @Test
    public void testZtsForbidden() {
        GCPSIACredentials.ATTESTATION_DATA_URL_PREFIX = "http://localhost:7356/mock-gcf-attestation-data?zts=";
        MockGcfAttestationDataGoodHandler mockGcfAttestationDataHandler = new MockGcfAttestationDataGoodHandler();
        MockZtsInstanceForbiddenHandler mockZtsInstanceHandler = new MockZtsInstanceForbiddenHandler();
        try (AutoCloseable ignored = startHttpServerForAttestationAndZtsInstance(
                mockGcfAttestationDataHandler,
                mockZtsInstanceHandler)) {
            GCPSIACredentials.getGCPFunctionServiceCertificate(
                    "athenzDomain",
                    "athenzService",
                    "gcpProjectId",
                    "athenzProvider",
                    "http://localhost:7356/mock-zts-instance/instance",
                    "certDomain",
                    "optionalCountry",
                    "optionalState",
                    "optionalLocality",
                    "optionalOrganization",
                    "optionalOrganizationUnit",
                    null);
            fail("Should have thrown exception");
        } catch (Exception exception) {
            assertEquals(exception.getMessage(), "Unable to register instance with Athenz. HTTP status: 403. Response: <MOCK ZTS FORBIDDEN>");
        }
    }

    @Test
    public void testDefaultConstructor() {
        GCPSIACredentials credentials = new GCPSIACredentials();
        assertNotNull(credentials);
    }

    @Test
    public void testGetSpiffeUri() {
        assertEquals("spiffe://sports/sa/api", GCPSIACredentials.getSpiffeUri(null, "sports", "api"));
        assertEquals("spiffe://sports/sa/api", GCPSIACredentials.getSpiffeUri("", "sports", "api"));
        assertEquals("spiffe://athenz.io/ns/default/sa/sports.api", GCPSIACredentials.getSpiffeUri("athenz.io", "sports", "api"));
    }

    static AutoCloseable startHttpServerForAttestationAndZtsInstance(
            HttpHandler mockGcfAttestationDataHandler,
            HttpHandler mockZtsInstanceHandler)
            throws Exception {

        HttpServer server = HttpServer.create(new InetSocketAddress(7356), 0);

        server.createContext("/mock-gcf-attestation-data", mockGcfAttestationDataHandler);
        server.createContext("/mock-zts-instance", mockZtsInstanceHandler);

        server.setExecutor(null); // creates a default executor
        server.start();

        return () -> server.stop(0);
    }

    // ================================= MOCK ATTESTATION-DATA HANDLERS ==================================

    static class MockGcfAttestationDataGoodHandler implements HttpHandler {
        public String requestedUri;
        @Override
        public void handle(HttpExchange httpExchange) throws IOException {
            requestedUri = httpExchange.getRequestURI().toString();
            String response = "<MOCK-ATTESTATION-DATA>";
            httpExchange.sendResponseHeaders(200, response.length());
            OutputStream os = httpExchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    static class MockGcfAttestationDataInvalidCodeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange httpExchange) throws IOException {
            String response = "<MOCK-ATTESTATION-INVALID-CODE>";
            httpExchange.sendResponseHeaders(202, response.length());
            OutputStream os = httpExchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    static class MockGcfAttestationDataErrorHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange httpExchange) throws IOException {
            throw new IOException("Mock GCF Attestation Data Error");
        }
    }

    // ================================= MOCK ZTS HANDLERS ==================================

    static class MockZtsInstanceGoodHandler implements HttpHandler {
        public String requestedUri;
        public String requestedBody;
        @Override
        public void handle(HttpExchange httpExchange) throws IOException {
            requestedUri = httpExchange.getRequestURI().toString();

            // Read the request body
            InputStream is = httpExchange.getRequestBody();
            Scanner s = new Scanner(is).useDelimiter("\\A");
            requestedBody = s.hasNext() ? s.next() : "";

            String response = "{" +
                    "\"x509Certificate\": " + MOCK_ATHENZ_CERT_JSON + "," +
                    "\"x509CertificateSigner\": \"" + MOCK_CA_CERTS + "\"\n" +
                    "}";
            httpExchange.sendResponseHeaders(200, response.length());

            OutputStream os = httpExchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    static class MockZtsInstanceForbiddenHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange httpExchange) throws IOException {
            String response = "<MOCK ZTS FORBIDDEN>";
            httpExchange.sendResponseHeaders(403, response.length());
            OutputStream os = httpExchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }
 }
