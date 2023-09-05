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

package com.yahoo.athenz.common.server.msd;

import com.yahoo.athenz.common.server.msd.net.InetAddressMap;
import com.yahoo.athenz.common.server.msd.net.InetWorkload;
import com.yahoo.athenz.msd.*;

import java.io.Closeable;
import java.util.*;

/**
 * Storage interface for storing MicroSegmentation Daemon data
 */
public interface MsdStoreConnection extends Closeable {

    /**
     * putStaticWorkload stores the Workload value into the underlying storage that can be an RDMS or NoSQL
     * @param workload static workload to be stored in the underlying storage
     */
    default void putStaticWorkload(StaticWorkload workload) {
    }

    /**
     * deleteStaticWorkload deletes the Workload from the underlying storage that can be an RDMS or NoSQL
     * @param domainName name of the domain
     * @param serviceName name of the service
     * @param instanceId instance id
     */
    default void deleteStaticWorkload(String domainName, String serviceName, String instanceId) {
    }

    /**
     * putDynamicWorkLoad stores the Workload value into the underlying storage that can be an RDMS or NoSQL
     * @param workload workload to be stored in the underlying storage
     * @param options workload options to be passed to the api
     */
    default void putDynamicWorkload(DynamicWorkload workload, WorkloadOptions options) {
    }

    /**
     * deleteDynamicWorkLoad delete the Workload from the underlying storage that can be an RDMS or NoSQL
     * @param domainName name of the domain
     * @param serviceName name of the service
     * @param instanceId instance id
     */
    default void deleteDynamicWorkload(String domainName, String serviceName, String instanceId) {
    }

    /**
     * putTransportPolicyValidationStatus stores the validation status into the underlying storage that can be an RDMS or NoSQL
     * @param validationResponse response object to be stored in the underlying storage
     */
    default void putTransportPolicyValidationStatus(TransportPolicyValidationResponse validationResponse) {
    }

    /**
     * getWorkloadsBySvc looks up all workloads for the requested service in the MSD storage
     * @param domain of the service to look up
     * @param service name of the service to look up
     * @return Workloads object containing static and dynamic workloads
     */
    default Workloads getWorkloadsBySvc(String domain, String service) {
        Workloads workloads = new Workloads();
        workloads.setWorkloadList(new ArrayList<>());
        return workloads;
    }

    /**
     * getWorkloadsByIp looks up all workloads for the requested ip in the MSD Storage
     * @param ip to lookup
     * @return a List of Workload
     */
    default Workloads getWorkloadsByIp(String ip) {
        Workloads workloads = new Workloads();
        workloads.setWorkloadList(new ArrayList<>());
        return workloads;
    }

    /**
     * getTransportPolicyValidationStatus looks up validation status
     * @param assertionIdList list of assertion IDs to  lookup
     * @return TransportPolicyValidationResponseList object containing list of TransportPolicyValidationResponse
     */
    default TransportPolicyValidationResponseList getTransportPolicyValidationStatus(List<Long> assertionIdList) {
        TransportPolicyValidationResponseList responseList = new TransportPolicyValidationResponseList();
        responseList.setResponseList(new ArrayList<>());
        return responseList;
    }

    /**
     * retrieve static workload services by its type 
     * @param serviceType StaticWorkloadType in String representation 
     * @param serviceValue specific service value
     * @return StaticWorkloadServices object contains list of StaticWorkloadService
     */
    default StaticWorkloadServices getStaticWorkloadServices(String serviceType, String serviceValue) {
        StaticWorkloadServices staticWorkloadServices = new StaticWorkloadServices();
        staticWorkloadServices.setStaticWorkloadServices(new ArrayList<>());
        return staticWorkloadServices;
    }

    /**
     * getServiceModifiedTag returns a tag to indicate the change in workloads of the service.
     * The change could be an addition of an IP to an existing workload, or a new workload getting added
     * The tag itself could be a hash value or last modified timestamp
     * @param domain of the service to look up
     * @param service name of the service to look up
     * @return a tag as a string
     */
    default String getServiceModifiedTag(String domain, String service) {
        return "";
    }

    // Transaction commands
    default void close() {
    }

    default void commitChanges() {
    }

    default void rollbackChanges() {
    }

    /**
     * set timeout for operations with underlying storage
     * @param opTimout
     */
    default void setOperationTimeout(int opTimout) {
    }

    /**
     * construct IP to Workload mapping for building cache
     * @return InetWorkload containing dynamic ips and static ips
     */
    default InetWorkload buildIpToWorkload() {
        return new InetWorkload(new InetAddressMap<>(new TreeMap<>(), new TreeMap<>()), new InetAddressMap<>(new TreeMap<>(), new TreeMap<>()));
    }
}
