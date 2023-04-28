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
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigLong;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ResourceException;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Timestamp;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.math.BigDecimal;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.common.server.util.config.ConfigManagerSingleton.CONFIG_MANAGER;

public class InstanceGCPProvider implements InstanceProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceGCPProvider.class);

    static final String GCP_PROP_GKE_DNS_SUFFIX   = "athenz.zts.gcp_gke_dns_suffix";

    static final String GCP_PROP_BOOT_TIME_OFFSET = "athenz.zts.gcp_boot_time_offset";
    static final String GCP_PROP_DNS_SUFFIX       = "athenz.zts.gcp_dns_suffix";
    static final String GCP_PROP_REGION_NAME      = "athenz.zts.gcp_region_name";

    static final String GCP_PROP_CERT_VALIDITY_NO_ADDITIONAL_INFO = "athenz.zts.gcp_cert_validity_no_additional_info";

    DynamicConfigLong bootTimeOffsetSeconds; // boot time offset in seconds
    long certValidityTime;                   // cert validity for STS creds only case
    boolean supportRefresh = false;
    String gcpRegion;
    Set<String> dnsSuffixes = null;
    List<String> gkeDnsSuffixes = null;
    InstanceGCPUtils gcpUtils = null;

    public long getTimeOffsetInMilli() {
        return bootTimeOffsetSeconds.get() * 1000;
    }

    @Override
    public Scheme getProviderScheme() {
        return Scheme.HTTP;
    }
    @Override
    public void initialize(String provider, String endpoint, SSLContext sslContext, KeyStore keyStore) {

        // create our helper object to validate gcp identity token

        gcpUtils = new InstanceGCPUtils();

        // how long the instance must be booted in the past before we
        // stop validating the instance requests

        long timeout = TimeUnit.SECONDS.convert(5, TimeUnit.MINUTES);
        bootTimeOffsetSeconds = new DynamicConfigLong(CONFIG_MANAGER, GCP_PROP_BOOT_TIME_OFFSET, timeout);

        // determine the dns suffix. if this is not specified we'll
        // be rejecting all entries

        dnsSuffixes = new HashSet<>();
        final String dnsSuffix = System.getProperty(GCP_PROP_DNS_SUFFIX);
        if (StringUtil.isEmpty(dnsSuffix)) {
            LOGGER.error("GCP DNS Suffix not specified - no instance requests will be authorized");
        } else {
            dnsSuffixes.addAll(Arrays.asList(dnsSuffix.split(",")));
        }

        gkeDnsSuffixes = InstanceUtils.processK8SDnsSuffixList(GCP_PROP_GKE_DNS_SUFFIX);

        // default certificate expiry for requests without instance
        // identity document

        int certValidityDays = Integer.parseInt(System.getProperty(GCP_PROP_CERT_VALIDITY_NO_ADDITIONAL_INFO, "7"));
        certValidityTime = TimeUnit.MINUTES.convert(certValidityDays, TimeUnit.DAYS);

        // get the gcp region

        gcpRegion = System.getProperty(GCP_PROP_REGION_NAME);
    }

    public ResourceException error(String message) {
        return error(ResourceException.FORBIDDEN, message);
    }

    public ResourceException error(int errorCode, String message) {
        LOGGER.error(message);
        return new ResourceException(errorCode, message);
    }

    protected Set<String> getDnsSuffixes() {
        return dnsSuffixes;
    }

    boolean validateGCPProject(final String gcpProject, final String docProject, StringBuilder errMsg) {

        if (!gcpProject.equalsIgnoreCase(docProject)) {
            LOGGER.error("ZTS GCP Domain Lookup project id: {}", gcpProject);
            errMsg.append("mismatch between project values - instance identity value= ").append(docProject);
            return false;
        }

        return true;
    }

    boolean validateGCPProvider(final String provider, final String region, StringBuilder errMsg) {

        final String suffix = "." + region;
        if (!provider.endsWith(suffix)) {
            errMsg.append("provider ").append(provider).append(" does not end with expected suffix ").append(region);
            return false;
        }

        return true;
    }

    boolean validateGCPInstanceId(final String reqInstanceId, final String docInstanceId,
                                  StringBuilder errMsg) {

        if (!reqInstanceId.equalsIgnoreCase(docInstanceId)) {
            errMsg.append("mismatch between instance-id values: request= ").append(reqInstanceId)
                    .append(" vs. attested= ").append(docInstanceId);
            return false;
        }

        return true;
    }

    protected boolean validateIdentityToken(final String provider, GCPAttestationData attestationData,
                                            GCPDerivedAttestationData derivedAttestationData,
                                            final String gcpProject, final String instanceId, boolean checkTime,
                                            StringBuilder errMsg) {

        GoogleIdToken.Payload validatedPayload = gcpUtils.validateGCPIdentityToken(attestationData.getIdentityToken(), errMsg);

        if (validatedPayload == null) {
            return false;
        }

        // create a derived attestation data object from validated token's payload for further use

        gcpUtils.populateAttestationData(validatedPayload, derivedAttestationData);

        // verify that the project lookup and the project in the document match

        if (!validateGCPProject(gcpProject, gcpUtils.getProjectIdFromAttestedData(derivedAttestationData), errMsg)) {
            return false;
        }

        if (derivedAttestationData.getAdditionalAttestationData() != null) {

            if (!validateGCPProvider(provider,
                    gcpUtils.getGCPRegionFromZone(derivedAttestationData.getAdditionalAttestationData().getZone()),
                    errMsg)) {
                return false;
            }

            final String attestedInstanceId = derivedAttestationData.getAdditionalAttestationData().getInstanceId();
            if (!validateGCPInstanceId(instanceId, attestedInstanceId, errMsg)) {
                return false;
            }
            // verify that the boot uptime for the instance is now
            return !checkTime || validateInstanceBootTime(derivedAttestationData.getAdditionalAttestationData().getInstanceCreationTimestamp(), errMsg);
        }

        return true;
    }

    boolean validateInstanceBootTime(BigDecimal bootTimestamp, StringBuilder errMsg) {

        // first check to see if the boot time enforcement is enabled

        if (getTimeOffsetInMilli() <= 0) {
            return true;
        }
        // bootTimestamp is in seconds
        Timestamp bootTime = Timestamp.fromMillis(bootTimestamp.longValue() * 1000);
        if (bootTime.millis() < System.currentTimeMillis() - getTimeOffsetInMilli()) {
            errMsg.append("Instance boot time is not recent enough: ");
            errMsg.append(bootTime);
            return false;
        }

        return true;
    }

    @Override
    public InstanceConfirmation confirmInstance(InstanceConfirmation confirmation) {

        GCPAttestationData attestationData = JSON.fromString(confirmation.getAttestationData(),
                GCPAttestationData.class);
        GCPDerivedAttestationData derivedAttestationData = new GCPDerivedAttestationData();
        StringBuilder errMsg = new StringBuilder(256);

        final Map<String, String> instanceAttributes = confirmation.getAttributes();
        final String instanceDomain = confirmation.getDomain();
        final String instanceService = confirmation.getService();

        // make sure request is for a valid gcp project

        final String gcpProject = InstanceUtils.getInstanceProperty(instanceAttributes, ZTS_INSTANCE_GCP_PROJECT);
        if (StringUtil.isEmpty(gcpProject)) {
            throw error("Unable to find GCP Project id");
        }

        // validate the certificate host names

        StringBuilder instanceId = new StringBuilder(256);
        if (!InstanceUtils.validateCertRequestSanDnsNames(instanceAttributes, instanceDomain,
                instanceService, getDnsSuffixes(), gkeDnsSuffixes, null, true, instanceId)) {
            throw error("Unable to validate certificate request hostnames");
        }

        validateAttestationData(confirmation, attestationData, derivedAttestationData, gcpProject,
                instanceId.toString(), true, errMsg);

        // validate that the domain/service given in the confirmation
        // request match the attestation data
        // we are using gcpProject name instead of domain name here since there is a 1:1
        // mapping between gcp project and Athenz domain.

        validateAthenzService(derivedAttestationData, instanceService, gcpProject);

        // set the attributes to be returned to the ZTS server
        // additional metadata is only available on GCE so using that
        // as a basis to provide SSH host certificate

        setConfirmationAttributes(confirmation, derivedAttestationData.getAdditionalAttestationData() != null);

        return confirmation;
    }

    @Override
    public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) {
        // if we don't have an attestation data then we're going to
        // return not found exception unless the provider is required
        // to support refresh and in that case we'll return forbidden

        final String attestationDataStr = confirmation.getAttestationData();
        if (attestationDataStr == null || attestationDataStr.isEmpty()) {
            int errorCode = supportRefresh ? ResourceException.FORBIDDEN : ResourceException.NOT_FOUND;
            throw error(errorCode, "No attestation data provided during refresh");
        }

        GCPAttestationData attestationData = JSON.fromString(attestationDataStr, GCPAttestationData.class);
        GCPDerivedAttestationData derivedAttestationData = new GCPDerivedAttestationData();
        StringBuilder errMsg = new StringBuilder(256);

        final Map<String, String> instanceAttributes = confirmation.getAttributes();
        final String instanceService = confirmation.getService();

        // make sure request is for a valid gcp project

        final String gcpProject = InstanceUtils.getInstanceProperty(instanceAttributes, ZTS_INSTANCE_GCP_PROJECT);
        if (StringUtil.isEmpty(gcpProject)) {
            throw error("Unable to find GCP Project id");
        }

        // extract the instance id as well

        final String instanceId = InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_ID);
        if (instanceId == null) {
            throw error("Unable to extract Instance Id");
        }

        validateAttestationData(confirmation, attestationData, derivedAttestationData,
                gcpProject, instanceId, false, errMsg);

        validateAthenzService(derivedAttestationData, instanceService, gcpProject);

        // set the attributes to be returned to the ZTS server
        setConfirmationAttributes(confirmation, derivedAttestationData.getAdditionalAttestationData() != null);


        return confirmation;
    }

    private void validateAttestationData(InstanceConfirmation confirmation, GCPAttestationData attestationData, GCPDerivedAttestationData derivedAttestationData, String gcpProject, String instanceId,
                                         boolean checkTime, StringBuilder errMsg) {

        // validate the instance identity token

        if (!validateIdentityToken(confirmation.getProvider(), attestationData, derivedAttestationData, gcpProject,
                instanceId, checkTime, errMsg)) {
            throw error("Unable to validate instance identity token: " + errMsg);
        }
    }

    private void validateAthenzService(GCPDerivedAttestationData derivedAttestationData, String instanceService, String gcpProject) {
        // validate that the gcp project/service given in the confirmation
        // request match the attestation data
        // we are using gcp project name instead of domain name here since there is a 1:1
        // mapping between gcp project and Athenz domain.

        final String serviceName = gcpProject + "." + instanceService;
        final String attestedServiceName = gcpUtils.getServiceNameFromAttestedData(derivedAttestationData);
        if (!serviceName.equals(attestedServiceName)) {
            throw error("Service name mismatch: attested=" + attestedServiceName + " vs. requested=" + serviceName);
        }
    }

    protected void setConfirmationAttributes(InstanceConfirmation confirmation, boolean additionalMetadataAvailable) {

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_CERT_SSH, Boolean.toString(additionalMetadataAvailable));
        if (!additionalMetadataAvailable) {
            attributes.put(InstanceProvider.ZTS_CERT_EXPIRY_TIME, Long.toString(certValidityTime));
        }
        confirmation.setAttributes(attributes);
    }

}
