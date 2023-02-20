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
package com.yahoo.athenz.zts;

import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.common.server.workload.WorkloadRecord;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.AssertionEffect;
import com.yahoo.athenz.zms.Policy;
import com.yahoo.athenz.zms.ServiceIdentity;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.rdl.Timestamp;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.security.PrivateKey;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class ZTSTestUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZTSTestUtils.class);

    public static void deleteDirectory(File file) {
        if (!file.exists()) {
            return;
        }

        if (file.isDirectory()) {

            File[] fileList = file.listFiles();
            if (fileList != null) {
                for (File ff : fileList) {
                    deleteDirectory(ff);
                }
            }
        }
        if (!file.delete()) {
            throw new RuntimeException("cannot delete file: {}" + file.getAbsolutePath());
        }
    }

    public static boolean verifyGroupMemberName(List<GroupMember> groupMembers, final String memberName) {
        for (GroupMember groupMember : groupMembers) {
            if (groupMember.getMemberName().equalsIgnoreCase(memberName)) {
                return true;
            }
        }
        return false;
    }

    public static boolean verifyGroupMemberGroup(List<GroupMember> groupMembers, final String groupName) {
        for (GroupMember groupMember : groupMembers) {
            if (groupMember.getGroupName().equalsIgnoreCase(groupName)) {
                return true;
            }
        }
        return false;
    }

    public static Group createGroupObject(String domainName, String groupName, String... memberNames) {

        List<GroupMember> members = new ArrayList<>();
        for (String memberName : memberNames) {
            members.add(new GroupMember().setMemberName(memberName)
                    .setGroupName(ResourceUtils.groupResourceName(domainName, groupName)));
        }
        return createGroupObject(domainName, groupName, members);
    }

    public static Group createGroupObject(String domainName, String groupName, List<GroupMember> members) {

        Group group = new Group();
        group.setName(ResourceUtils.groupResourceName(domainName, groupName));
        group.setGroupMembers(members);
        return group;
    }

    public static SignedDomain createSignedDomain(String domainName, List<Role> roles, List<Policy> policies,
                                                  List<ServiceIdentity> services, List<Group> groups,
                                                  PrivateKey privateKey) {

        SignedDomain signedDomain = new SignedDomain();

        com.yahoo.athenz.zms.DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain(domainName);
        domainPolicies.setPolicies(policies);

        com.yahoo.athenz.zms.SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        if (privateKey != null) {
            signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));
            signedPolicies.setKeyId("0");
        }

        DomainData domain = new DomainData();
        domain.setName(domainName);
        domain.setRoles(roles);
        domain.setGroups(groups);
        domain.setServices(services);
        domain.setPolicies(signedPolicies);
        domain.setModified(Timestamp.fromCurrentTime());

        signedDomain.setDomain(domain);

        if (privateKey != null) {
            signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), privateKey));
            signedDomain.setKeyId("0");
        }

        return signedDomain;
    }

    public static void setupDomainsWithGroups(DataStore store, PrivateKey privateKey, final String domainName,
                                              List<String> skipGroups) {

        final String domainName1 = domainName + "1";
        final String domainName2 = domainName + "2";
        final String domainName3 = domainName + "3";
        final String groupName1 = "group1";
        final String groupName2 = "group2";
        final String groupName3 = "group3";
        final String groupName4 = "group4";
        final String groupName5 = "group5";
        final String groupName6 = "group6";
        final String roleName1 = "role1";
        final String roleName2 = "role2";
        final String roleName3 = "role3";
        final String roleName4 = "role4";
        final String roleName5 = "role5";
        final String policyName1 = "policy1";
        final String policyName2 = "policy2";
        final String policyName3 = "policy3";
        final String policyName4 = "policy4";

        Group group1 = null;
        if (!skipGroups.contains(ResourceUtils.groupResourceName(domainName1, groupName1))) {
            group1 = createGroupObject(domainName1, groupName1, "user.user1", "user.user2");
        }

        Group group2 = null;
        if (!skipGroups.contains(ResourceUtils.groupResourceName(domainName2, groupName2))) {
            group2 = createGroupObject(domainName2, groupName2, "user.user2", "user.user7");
        }

        // set elevated clearance so both users become expired

        Group group3 = null;
        if (!skipGroups.contains(ResourceUtils.groupResourceName(domainName3, groupName3))) {
            group3 = createGroupObject(domainName3, groupName3, "user.user4");
            group3.getGroupMembers().add(new GroupMember().setMemberName("user.user1")
                    .setGroupName(ResourceUtils.groupResourceName(domainName3, groupName3)));
            group3.getGroupMembers().add(new GroupMember().setMemberName("user.user2")
                    .setGroupName(ResourceUtils.groupResourceName(domainName3, groupName3)));
        }

        // group 4 with no members

        Group group4 = null;
        if (!skipGroups.contains(ResourceUtils.groupResourceName(domainName2, groupName4))) {
            group4 = new Group().setName(ResourceUtils.groupResourceName(domainName2, groupName4));
        }

        // group 5 with disabled and soon to be expired user

        Group group5 = null;
        if (!skipGroups.contains(ResourceUtils.groupResourceName(domainName3, groupName5))) {
            group5 = createGroupObject(domainName3, groupName5, "user.user4");
            group5.getGroupMembers().add(new GroupMember().setMemberName("user.user5")
                    .setGroupName(ResourceUtils.groupResourceName(domainName3, groupName5))
                    .setSystemDisabled(1));
            group5.getGroupMembers().add(new GroupMember().setMemberName("user.user6")
                    .setGroupName(ResourceUtils.groupResourceName(domainName3, groupName5))
                    .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 1000)));
        }

        // group 6 with users 3 and 6

        Group group6 = null;
        if (!skipGroups.contains(ResourceUtils.groupResourceName(domainName3, groupName6))) {
            group6 = createGroupObject(domainName3, groupName6, "user.user6", "user.user3");
        }

        // role1 will have user.user1 through group1

        List<Role> roles = new ArrayList<>();
        Role role1 = createRoleObject(domainName1, roleName1, "user.user2", "user.user3");
        if (group2 != null) {
            role1.getRoleMembers().add(new RoleMember()
                    .setMemberName(ResourceUtils.groupResourceName(domainName2, groupName2)));
        }
        if (group1 != null) {
            role1.getRoleMembers().add(new RoleMember()
                    .setMemberName(ResourceUtils.groupResourceName(domainName1, groupName1)));
        }
        roles.add(role1);

        // role2 has user1 as expired but ok from group1 as well

        Role role2 = createRoleObject(domainName1, roleName2, "user.user2", "user.user3");
        role2.getRoleMembers().add(new RoleMember().setMemberName("user.user1")
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() - 1000)));
        if (group2 != null) {
            role2.getRoleMembers().add(new RoleMember()
                    .setMemberName(ResourceUtils.groupResourceName(domainName2, groupName2)));
        }
        if (group1 != null) {
            role2.getRoleMembers().add(new RoleMember()
                    .setMemberName(ResourceUtils.groupResourceName(domainName1, groupName1)));
        }
        roles.add(role2);

        // role3 has user1 as expired but also group1 expired as well

        Role role3 = createRoleObject(domainName1, roleName3, "user.user2", "user.user3");
        role3.getRoleMembers().add(new RoleMember().setMemberName("user.user1")
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() - 1000)));
        if (group1 != null) {
            role3.getRoleMembers().add(new RoleMember()
                    .setMemberName(ResourceUtils.groupResourceName(domainName1, groupName1))
                    .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() - 1000)));
        }
        roles.add(role3);

        // role4 does not have user1 at all

        Role role4 = createRoleObject(domainName1, roleName4, "user.user2");
        if (group2 != null) {
            role4.getRoleMembers().add(new RoleMember()
                    .setMemberName(ResourceUtils.groupResourceName(domainName2, groupName2)));
        }
        if (group4 != null) {
            role4.getRoleMembers().add(new RoleMember()
                    .setMemberName(ResourceUtils.groupResourceName(domainName2, groupName4)));
        }
        if (group6 != null) {
            role4.getRoleMembers().add(new RoleMember()
                    .setMemberName(ResourceUtils.groupResourceName(domainName3, groupName6)));
        }
        roles.add(role4);

        List<Policy> policies = new ArrayList<>();
        Policy policy1 = createPolicyObject(domainName1, policyName1, roleName1, true,
                "update", domainName1 + ":resource1", com.yahoo.athenz.zms.AssertionEffect.ALLOW);
        policies.add(policy1);
        Policy policy2 = createPolicyObject(domainName1, policyName2, roleName2, true,
                "update", domainName1 + ":resource2", com.yahoo.athenz.zms.AssertionEffect.ALLOW);
        policies.add(policy2);
        Policy policy3 = createPolicyObject(domainName1, policyName3, roleName3, true,
                "update", domainName1 + ":resource3", com.yahoo.athenz.zms.AssertionEffect.ALLOW);
        policies.add(policy3);
        Policy policy4 = createPolicyObject(domainName1, policyName4, roleName4, true,
                "update", domainName1 + ":resource4", com.yahoo.athenz.zms.AssertionEffect.ALLOW);
        policies.add(policy4);

        // setup our signed domains and process them

        List<Group> groups = new ArrayList<>();
        if (group1 != null) {
            groups.add(group1);
        }
        SignedDomain signedDomain = ZTSTestUtils.createSignedDomain(domainName1, roles, policies, null, groups, privateKey);
        store.processSignedDomain(signedDomain, false);

        groups = new ArrayList<>();
        if (group2 != null) {
            groups.add(group2);
        }
        if (group4 != null) {
            groups.add(group4);
        }

        // just admin role for domain

        Role adminRole = createRoleObject(domainName2, "admin", "user.admin1", "user.admin2");
        roles = new ArrayList<>();
        roles.add(adminRole);

        Policy adminPolicy = createPolicyObject(domainName2, "admin", "admin", true,
                "*", domainName2 + ":*", com.yahoo.athenz.zms.AssertionEffect.ALLOW);
        policies = new ArrayList<>();
        policies.add(adminPolicy);

        signedDomain = ZTSTestUtils.createSignedDomain(domainName2, roles, policies, null, groups, privateKey);
        store.processSignedDomain(signedDomain, false);

        groups = new ArrayList<>();
        if (group3 != null) {
            groups.add(group3);
        }
        if (group5 != null) {
            groups.add(group5);
        }
        if (group6 != null) {
            groups.add(group6);
        }

        // role5 in domain 3 has group5

        Role role5 = createRoleObject(domainName3, roleName5, "user.admin");
        if (group5 != null) {
            role5.getRoleMembers().add(new RoleMember().setMemberName(domainName3 + ":group." + groupName5));
        }
        if (group6 != null) {
            role5.getRoleMembers().add(new RoleMember().setMemberName(domainName3 + ":group." + groupName6)
                    .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 1000)));
        }

        adminRole = createRoleObject(domainName3, "admin", "user.admin1", "user.admin2");
        roles = new ArrayList<>();
        roles.add(adminRole);
        roles.add(role5);

        adminPolicy = createPolicyObject(domainName3, "admin", "admin", true,
                "*", domainName3 + ":*", AssertionEffect.ALLOW);
        policies = new ArrayList<>();
        policies.add(adminPolicy);

        signedDomain = ZTSTestUtils.createSignedDomain(domainName3, roles, policies, null, groups, privateKey);
        store.processSignedDomain(signedDomain, false);
    }

    public static Role createRoleObject(final String domainName, final String roleName, String... members) {

        List<RoleMember> roleMembers = new ArrayList<>();
        for (String member : members) {
            roleMembers.add(new RoleMember().setMemberName(member));
        }
        return createRoleObject(domainName, roleName, null, roleMembers);
    }

    public static Role createRoleObject(final String domainName, final String roleName, final String trust,
                                         List<RoleMember> members) {

        Role role = new Role();
        role.setName(domainName + ":role." + roleName);
        role.setRoleMembers(members);
        role.setTrust(trust);
        return role;
    }

    public static Policy createPolicyObject(final String domainName, final String policyName,
                                            final String roleName, boolean generateRoleName, final String action,
                                            final String resource, AssertionEffect effect) {

        Policy policy = new Policy();
        policy.setName(domainName + ":policy." + policyName);

        com.yahoo.athenz.zms.Assertion assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setAction(action);
        assertion.setEffect(effect);
        assertion.setResource(resource);
        if (generateRoleName) {
            assertion.setRole(domainName + ":role." + roleName);
        } else {
            assertion.setRole(roleName);
        }

        List<Assertion> assertList = new ArrayList<>();
        assertList.add(assertion);

        policy.setAssertions(assertList);
        return policy;
    }

    public static void sleep(long millis) {
        try {
            LOGGER.info("sleeping {} milliseconds...", millis);
            Thread.sleep(millis);
        } catch (InterruptedException ex) {
            LOGGER.info("Interrupted Exception while sleeping...", ex);
        }
    }

    public static Timestamp addDays(Timestamp date, int days) {
        return Timestamp.fromMillis(date.millis() + TimeUnit.MILLISECONDS.convert(days, TimeUnit.DAYS));
    }

    public static Map<String, AttributeValue> generateAttributeValues(String service,
                                                                String instanceId,
                                                                String currentTime,
                                                                String lastNotifiedTime,
                                                                String lastNotifiedServer,
                                                                String expiryTime,
                                                                String hostName) {
        String provider = "provider";
        String primaryKey = provider + ":" + service + ":" + instanceId;
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("primaryKey", new AttributeValue(primaryKey));
        item.put("service", new AttributeValue(service));
        item.put("provider", new AttributeValue(provider));
        item.put("instanceId", new AttributeValue(instanceId));
        item.put("currentSerial", new AttributeValue("currentSerial"));

        AttributeValue currentTimeVal = new AttributeValue();
        currentTimeVal.setN(currentTime);

        if (!StringUtil.isEmpty(currentTime)) {
            item.put("currentTime", currentTimeVal);
            item.put("prevTime", currentTimeVal);
        }

        item.put("currentIP", new AttributeValue("currentIP"));
        item.put("prevSerial", new AttributeValue("prevSerial"));
        item.put("prevIP", new AttributeValue("prevIP"));

        AttributeValue clientCertVal = new AttributeValue();
        clientCertVal.setBOOL(false);
        item.put("clientCert", clientCertVal);

        if (!StringUtil.isEmpty(lastNotifiedTime)) {
            AttributeValue lastNotifiedTimeVal = new AttributeValue();
            lastNotifiedTimeVal.setN(lastNotifiedTime);
            item.put("lastNotifiedTime", lastNotifiedTimeVal);
        }

        if (!StringUtil.isEmpty(lastNotifiedServer)) {
            item.put("lastNotifiedServer", new AttributeValue(lastNotifiedServer));
        }

        if (!StringUtil.isEmpty(expiryTime)) {
            AttributeValue expiryTimeVal = new AttributeValue();
            expiryTimeVal.setN(expiryTime);
            item.put("expiryTime", expiryTimeVal);
        }

        if (!StringUtil.isEmpty(hostName)) {
            item.put("hostName", new AttributeValue(hostName));
        }

        return item;
    }

    public static Map<String, AttributeValue> generateWorkloadAttributeValues(String service,
                                                                              String instanceId,
                                                                              String provider,
                                                                              String ip,
                                                                              String hostname,
                                                                              String creationTime,
                                                                              String updateTime,
                                                                              String certExpiryTime) {
        String primaryKey = service + "#" + instanceId + "#" + ip;
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("primaryKey", new AttributeValue(primaryKey));
        item.put("service", new AttributeValue(service));
        item.put("provider", new AttributeValue(provider));
        item.put("instanceId", new AttributeValue(instanceId));
        item.put("ip", new AttributeValue(ip));
        item.put("hostname", new AttributeValue(hostname));
        AttributeValue creationTimeVal = new AttributeValue();
        creationTimeVal.setN(creationTime);
        AttributeValue updateTimeVal = new AttributeValue();
        updateTimeVal.setN(updateTime);
        AttributeValue certExpiryTimeVal = new AttributeValue();
        certExpiryTimeVal.setN(certExpiryTime);
        item.put("creationTime", creationTimeVal);
        item.put("updateTime", updateTimeVal);
        item.put("certExpiryTime", certExpiryTimeVal);

        return item;
    }

    public static WorkloadRecord createWorkloadRecord(Date creationTime,
                                                      Date updateTime,
                                                      String provider,
                                                      String instanceId,
                                                      String hostname,
                                                      String ip,
                                                      String service,
                                                      Date certExpiryTime) {
        WorkloadRecord workloadRecord = new WorkloadRecord();
        workloadRecord.setCreationTime(creationTime);
        workloadRecord.setUpdateTime(updateTime);
        workloadRecord.setService(service);
        workloadRecord.setIp(ip);
        workloadRecord.setInstanceId(instanceId);
        workloadRecord.setHostname(hostname);
        workloadRecord.setProvider(provider);
        workloadRecord.setCertExpiryTime(certExpiryTime);
        return workloadRecord;
    }

    public static String getAssumeRoleResource(final String domainName, final String roleName,
                                         boolean wildCardRole, boolean wildCardDomain) {
        if (wildCardRole && wildCardDomain) {
            return "*:role.*";
        } else if (wildCardDomain) {
            return "*:role." + roleName;
        } else if (wildCardRole) {
            return domainName + ":role.*";
        } else {
            return domainName + ":role." + roleName;
        }
    }

    public static String getDERSignature(final String protectedHeader, final String signature) {

        Map<String, String> header = Crypto.parseJWSProtectedHeader(protectedHeader);
        if (header == null) {
            return null;
        }
        final String algorithm = header.get("alg");
        if (!isESAlgorithm(algorithm)) {
            return null;
        }
        try {
            Base64.Decoder base64Decoder = Base64.getUrlDecoder();
            final byte[] signatureBytes = base64Decoder.decode(signature);
            final byte[] convertedSignature = Crypto.convertSignatureFromP1363ToDERFormat(signatureBytes,
                    Crypto.getDigestAlgorithm(algorithm));
            Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();
            return base64Encoder.encodeToString(convertedSignature);
        } catch (Exception ex) {
            return null;
        }
    }

    public static boolean isESAlgorithm(final String algorithm) {
        if (algorithm != null) {
            switch (algorithm) {
                case "ES256":
                case "ES384":
                case "ES512":
                    return true;
            }
        }
        return false;
    }

    public static SignedDomain setupDomainWithGroupMemberState(final String domainName, final String groupName,
            final String roleName, final String memberName, boolean disabledState) {

        List<GroupMember> members = new ArrayList<>();
        members.add(new GroupMember().setMemberName(memberName)
                    .setGroupName(ResourceUtils.groupResourceName(domainName, groupName))
                    .setSystemDisabled(disabledState ? 2 : 0));
        members.add(new GroupMember().setMemberName("user_domain.addl_member")
                    .setGroupName(ResourceUtils.groupResourceName(domainName, groupName)));
        Group group = createGroupObject(domainName, groupName, members);

        List<Group> groups = new ArrayList<>();
        groups.add(group);

        List<RoleMember> adminRoleMembers = new ArrayList<>();
        adminRoleMembers.add(new RoleMember().setMemberName("user_domain.admin_member"));
        Role adminRole = createRoleObject(domainName, "admin", null, adminRoleMembers);

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName(memberName)
                .setSystemDisabled(disabledState ? 2 : 0));
        Role role = createRoleObject(domainName, roleName, null, roleMembers);

        List<Role> roles = new ArrayList<>();
        roles.add(adminRole);
        roles.add(role);

        return ZTSTestUtils.createSignedDomain(domainName, roles, null, null, groups, null);
    }

    public static SignedDomain setupDomainWithRoleGroupMember(final String domainName, final String roleName,
            final String memberName, final String groupName, boolean disabledState) {

        List<RoleMember> adminRoleMembers = new ArrayList<>();
        adminRoleMembers.add(new RoleMember().setMemberName("user_domain.admin_member"));
        adminRoleMembers.add(new RoleMember().setMemberName(memberName)
                .setSystemDisabled(disabledState ? 2 : 0));
        Role adminRole = createRoleObject(domainName, "admin", null, adminRoleMembers);

        Role role = createRoleObject(domainName, roleName, groupName);

        List<Role> roles = new ArrayList<>();
        roles.add(adminRole);
        roles.add(role);

        return ZTSTestUtils.createSignedDomain(domainName, roles, null, null, null, null);
    }
}
