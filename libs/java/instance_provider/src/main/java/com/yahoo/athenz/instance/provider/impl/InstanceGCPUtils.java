/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.instance.provider.impl;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.ArrayMap;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigDecimal;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;

public class InstanceGCPUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceGCPUtils.class);
    GoogleIdTokenVerifier googleIdTokenVerifier;
    static final String GCP_PROP_EXPECTED_AUDIENCE = "athenz.zts.gcp_identity_expected_audience";
    private static final String GCP_ATTESTATION_KEY_GOOGLE = "google";
    private static final String GCP_ATTESTATION_KEY_COMPUTE_ENGINE = "compute_engine";
    private static final String GCP_SERVICE_ACCOUNT_EMAIL_SEPARATOR = "@";
    private static final String DOT = ".";
    private static final String GCP_REGION_ZONE_SEPARATOR = "-";

    private static final String GCP_OPTIONAL_ATTR_PROJECT_NUMBER = "project_number";
    private static final String GCP_OPTIONAL_ATTR_PROJECT_ID = "project_id";
    private static final String GCP_OPTIONAL_ATTR_ZONE = "zone";
    private static final String GCP_OPTIONAL_ATTR_INSTANCE_NAME = "instance_name";
    private static final String GCP_OPTIONAL_ATTR_INSTANCE_ID = "instance_id";
    private static final String GCP_OPTIONAL_ATTR_INSTANCE_CREATION_TIMESTAMP = "instance_creation_timestamp";

    public InstanceGCPUtils() {
        this(new NetHttpTransport(), new GsonFactory());
    }

    public void setGoogleIdTokenVerifier(final GoogleIdTokenVerifier googleIdTokenVerifier) {
        this.googleIdTokenVerifier = googleIdTokenVerifier;
    }

    public InstanceGCPUtils(HttpTransport httpTransport, JsonFactory jsonFactory) {
        final String expectedAudience = System.getProperty(GCP_PROP_EXPECTED_AUDIENCE, "");
        if (StringUtil.isEmpty(expectedAudience)) {
            LOGGER.error("Expected audience in the GCP Identity token is not specified. No identity will be issued.");
        }
        googleIdTokenVerifier = new GoogleIdTokenVerifier
                .Builder(httpTransport, jsonFactory)
                .setAudience(List.of(expectedAudience))
                .build();
    }

    public GoogleIdToken.Payload validateGCPIdentityToken(final String token, StringBuilder errMsg) {

        try {
            GoogleIdToken validatedToken = googleIdTokenVerifier.verify(token);
            if (validatedToken != null) {
                /* Sample decoded token by GCE metadata server ( with format=full optional parameter to the metadata server)
                {"aud":"https://my-zts-server","azp":"102023896904281105569","email":"my-sa@my-gcp-project.iam.gserviceaccount.com",
                "email_verified":true,"exp":1678259131,"iat":1678255531,"iss":"https://accounts.google.com","sub":"102023896904281105569",
                "google":{"compute_engine":{"instance_creation_timestamp":1677459985,"instance_id":"3692465099344887023",
                "instance_name":"my-vm","project_id":"my-gcp-project","project_number":1234567890123,"zone":"us-west1-a"}}}

                Sample decoded token by GKE metadata server
                {"aud":"https://my-zts-server","azp":"102023896904281105569","email":"my-sa@my-gcp-project.iam.gserviceaccount.com",
                "email_verified":true,"exp":1678259131,"iat":1678255531,"iss":"https://accounts.google.com","sub":"102023896904281105569"}
                 */
                return validatedToken.getPayload();
            } else {
                errMsg.append("ID token was not verified by GCP. Possible reasons: expired token/invalid issuer or audience/invalid signature");
            }
        } catch (IllegalArgumentException | GeneralSecurityException | IOException e) {
            LOGGER.error("unable to validate GCP instance identity token error={} type={}", e.getMessage(), e.getClass());
            errMsg.append("unable to validate GCP instance identity token. Reason=")
                    .append(e.getMessage());
        }
        return null;
    }

    public void populateAttestationData(GoogleIdToken.Payload validatedPayload,
                                        GCPDerivedAttestationData derivedAttestationData) {
        derivedAttestationData.setAudience(validatedPayload.getAudienceAsList());
        derivedAttestationData.setEmail(validatedPayload.getEmail());
        derivedAttestationData.setEmailVerified(validatedPayload.getEmailVerified());
        derivedAttestationData.setIssuer(validatedPayload.getIssuer());
        derivedAttestationData.setAuthorizedParty(validatedPayload.getAuthorizedParty());

        Object googleObjValue = validatedPayload.get(GCP_ATTESTATION_KEY_GOOGLE);
        if (googleObjValue instanceof ArrayMap) {
            Map<String, Map<String, Object>> googleValueMap = (ArrayMap) googleObjValue;
            if (googleValueMap.containsKey(GCP_ATTESTATION_KEY_COMPUTE_ENGINE)) {

                Map<String, Object> computeEngineExtras = googleValueMap.get(GCP_ATTESTATION_KEY_COMPUTE_ENGINE);
                GCPAdditionalAttestationData additionalAttestationData = new GCPAdditionalAttestationData();

                additionalAttestationData.setProjectNumber(computeEngineExtras.get(GCP_OPTIONAL_ATTR_PROJECT_NUMBER).toString());
                additionalAttestationData.setProjectId((String) computeEngineExtras.get(GCP_OPTIONAL_ATTR_PROJECT_ID));
                additionalAttestationData.setZone((String) computeEngineExtras.get(GCP_OPTIONAL_ATTR_ZONE));
                additionalAttestationData.setInstanceName((String) computeEngineExtras.get(GCP_OPTIONAL_ATTR_INSTANCE_NAME));
                additionalAttestationData.setInstanceId((String) computeEngineExtras.get(GCP_OPTIONAL_ATTR_INSTANCE_ID));
                additionalAttestationData.setInstanceCreationTimestamp((BigDecimal) computeEngineExtras.get(GCP_OPTIONAL_ATTR_INSTANCE_CREATION_TIMESTAMP));

                derivedAttestationData.setAdditionalAttestationData(additionalAttestationData);
            }
        }
    }

    public String getServiceNameFromAttestedData(GCPDerivedAttestationData derivedAttestationData) {
        String service = "";
        String gcpProject = "";
        if (derivedAttestationData.isEmailVerified() &&
                derivedAttestationData.getEmail().contains(GCP_SERVICE_ACCOUNT_EMAIL_SEPARATOR) &&
                derivedAttestationData.getEmail().contains(DOT)) {
            service = derivedAttestationData.getEmail()
                    .substring(0, derivedAttestationData.getEmail().indexOf(GCP_SERVICE_ACCOUNT_EMAIL_SEPARATOR));
            gcpProject = derivedAttestationData.getEmail()
                    .substring(derivedAttestationData.getEmail().indexOf(GCP_SERVICE_ACCOUNT_EMAIL_SEPARATOR) + 1,
                            derivedAttestationData.getEmail().indexOf(DOT));
        }
        return gcpProject + "." + service;
    }

    public String getProjectIdFromAttestedData(GCPDerivedAttestationData derivedAttestationData) {
        String gcpProject = "";
        if (derivedAttestationData.isEmailVerified() &&
                derivedAttestationData.getEmail().contains(GCP_SERVICE_ACCOUNT_EMAIL_SEPARATOR)
                && derivedAttestationData.getEmail().contains(DOT)) {
            gcpProject = derivedAttestationData.getEmail()
                    .substring(derivedAttestationData.getEmail().indexOf(GCP_SERVICE_ACCOUNT_EMAIL_SEPARATOR) + 1,
                            derivedAttestationData.getEmail().indexOf(DOT));
        }
        return gcpProject;
    }

    public String getGCPRegionFromZone(final String zone) {
        if (zone != null) {
            int zoneIdIndex = zone.lastIndexOf(GCP_REGION_ZONE_SEPARATOR);
            if (zoneIdIndex != -1) {
                return zone.substring(0, zoneIdIndex);
            }
        }
        return zone;
    }
}
