/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package com.yahoo.athenz.msd;

import com.yahoo.rdl.Timestamp;

import java.io.Closeable;
import java.util.Collections;
import java.util.List;

public class MSDRDLClientMock extends MSDRDLGeneratedClient implements Closeable {

    public MSDRDLClientMock() {
        super("https://localhost:4443/msd/v1");
    }

    @Override
    public TransportPolicyRules getTransportPolicyRules(String matchingTag, java.util.Map<String, java.util.List<String>> headers) {

        if ("throw-ex".equals(matchingTag)) {
            throw new ResourceException(403, "invalid request");
        } else if ("throw-io".equals(matchingTag)) {
            throw new IndexOutOfBoundsException("out of bounds ex");
        } else if ("send-null".equals(matchingTag)) {
            return null;
        }

        TransportPolicyPort tpp1 = new TransportPolicyPort().setProtocol(TransportPolicyProtocol.TCP).setPort(1).setEndPort(1024);
        List<TransportPolicyPort> tppList1 = Collections.singletonList(tpp1);
        TransportPolicySubject tps1 = new TransportPolicySubject().setDomainName("dom1").setServiceName("svc1");
        TransportPolicyCondition tpc1 = new TransportPolicyCondition().setEnforcementState(TransportPolicyEnforcementState.ENFORCE).setScope(Collections.singletonList(TransportPolicyScope.ONPREM));
        tpc1.setInstances(Collections.singletonList("host1"));
        List<TransportPolicyCondition> tpcList1 = Collections.singletonList(tpc1);
        TransportPolicyMatch tpm1 = new TransportPolicyMatch().setAthenzService(tps1).setConditions(tpcList1);

        TransportPolicyEntitySelector tpes1 = new TransportPolicyEntitySelector().setPorts(tppList1).setMatch(tpm1);

        List<TransportPolicySubject> tpsList1 = Collections.singletonList(tps1);
        TransportPolicyPeer tppeer1 = new TransportPolicyPeer().setAthenzServices(tpsList1).setPorts(tppList1);

        TransportPolicyIngressRule tpir1 = new TransportPolicyIngressRule().setEntitySelector(tpes1).setFrom(tppeer1).setId(12345678L).setLastModified(
                Timestamp.fromMillis(123456789123L));

        TransportPolicyEgressRule tper1 = new TransportPolicyEgressRule().setEntitySelector(tpes1).setTo(tppeer1).setId(12345678L).setLastModified(
                Timestamp.fromMillis(123456789123L));

        List<TransportPolicyIngressRule> ingressRuleList1 = Collections.singletonList(tpir1);
        List<TransportPolicyEgressRule> egressRuleList1 = Collections.singletonList(tper1);

        return new TransportPolicyRules().setIngress(ingressRuleList1).setEgress(egressRuleList1);
    }

    @Override
    public Workloads getWorkloadsByService(String domainName, String serviceName, String matchingTag, java.util.Map<String, java.util.List<String>> headers) {
        if ("bad-domain".equals(domainName)) {
            throw new ResourceException(404, "unknown domain");
        }
        if ("bad-req".equals(domainName)) {
            throw new RuntimeException("bad request");
        }
        DynamicWorkload wl = new DynamicWorkload().setProvider("openstack").setIpAddresses(Collections.singletonList("10.0.0.1"))
                .setUuid("avve-resw").setUpdateTime(Timestamp.fromMillis(System.currentTimeMillis()));
        return new Workloads().setDynamicWorkloadList(Collections.singletonList(wl));
    }

    @Override
    public Workloads getWorkloadsByIP(String ip, String matchingTag, java.util.Map<String, java.util.List<String>> headers) {
        if ("127.0.0.1".equals(ip)) {
            throw new ResourceException(404, "unknown ip");
        }
        if ("bad-req".equals(ip)) {
            throw new RuntimeException("bad request");
        }
        DynamicWorkload wl = new DynamicWorkload().setProvider("openstack").setDomainName("athenz").setServiceName("api")
                .setUuid("avve-resw").setUpdateTime(Timestamp.fromMillis(System.currentTimeMillis()));
        return new Workloads().setDynamicWorkloadList(Collections.singletonList(wl));
    }

    @Override
    public WorkloadOptions putDynamicWorkload(String domain, String service, WorkloadOptions options) {
        if ("bad-domain".equals(domain)) {
            throw new ResourceException(404, "unknown domain");
        }
        if (options == null) {
            throw new RuntimeException("bad request");
        }
        return null;
    }

    @Override
    public WorkloadOptions deleteDynamicWorkload(String domain, String service, String instanceId) {
        if ("bad-domain".equals(domain)) {
            throw new ResourceException(404, "unknown domain");
        }
        if (service == null) {
            throw new RuntimeException("bad request");
        }
        return null;
    }

    @Override
    public StaticWorkload putStaticWorkload(String domain, String service, StaticWorkload staticWorkload) {
        if ("bad-domain".equals(domain)) {
            throw new ResourceException(404, "unknown domain");
        }
        if (staticWorkload == null) {
            throw new RuntimeException("bad request");
        }
        return null;
    }

    @Override
    public StaticWorkload deleteStaticWorkload(String domain, String service, String name) {
        if ("bad-domain".equals(domain)) {
            throw new ResourceException(404, "unknown domain");
        }
        if (service == null) {
            throw new RuntimeException("bad request");
        }
        return null;
    }
}
