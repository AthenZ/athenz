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
package com.yahoo.athenz.zms;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;

public class ZMSLoadData {

    private static String AUDIT_REF = "zmsjcltloadtest";
    
    private Principal createPrincipal(String userName) {
        Authority authority = new com.yahoo.athenz.auth.impl.PrincipalAuthority();
        return SimplePrincipal.create("user", userName,
                "v=U1;d=user;n=" + userName + ";s=signature", 0, authority);
    }
    
    private ZMSClient getClient(String userName) {
        ZMSClient client = new ZMSClient(getZMSUrl());
        client.addCredentials(createPrincipal(userName));
        return client;
    }
    
    private String getZMSUrl() {

        // if we're given a config setting then use that
        
        String zmsUrl = System.getProperty("yahoo.zms_java_client.zms_url");
        
        // if the value is not available then check the env setting
        
        if (zmsUrl == null) {
            zmsUrl = System.getenv("ZMS_URL");
        }
        
        return zmsUrl;
    }
    
    private TopLevelDomain createTopLevelDomainObject(String name,
            String description, String org) {

        TopLevelDomain dom = new TopLevelDomain();
        dom.setName(name);
        dom.setDescription(description);
        dom.setOrg(org);
        dom.setEnabled(true);

        List<String> admins = new ArrayList<>();
        admins.add("sys.auth.zts");
        admins.add("sys.auth.zpu");
        admins.add("user.zms_admin");
        admins.add("user.user_admin");
        admins.add("user.hga");
        dom.setAdminUsers(admins);

        return dom;
    }
    
    private ServiceIdentity createServiceObject(ZMSClient client, String domainName, 
            String serviceName, String endPoint, String executable, String user,
            String group) {
        
        ServiceIdentity service = new ServiceIdentity();
        service.setExecutable(executable);
        if (group != null) {
            service.setGroup(group);
        }
        if (user!= null) {
            service.setUser(user);
        }
        service.setName(client.generateServiceIdentityName(domainName, serviceName));
        
        List<PublicKeyEntry> pubKeys = new ArrayList<>();
        pubKeys.add(new PublicKeyEntry().setId("0")
                .setKey("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTk"
                      + "FEQ0JpUUtCZ1FDMXRHU1ZDQTh3bDVldzVZNzZXajJySkFVRApZYW5FSmZLbUFseDVjUS84aEtFVWZTU2dwWHI"
                      + "zQ3pkaDFhMjZkbGI3bW1LMjlxbVhKWGg2dW1XOUF5ZlRPS1ZvCis2QVNsb1ZVM2F2dnVmbEdVT0VnMmpzbWRh"
                      + "a1IyNEtjTGpBdTZRclVlNDE3bEczdDhxU1BJR2pTNUMrQ3NKVXcKaDA0aEh4NWYrUEV3eFY0cmJRSURBUUFCC"
                      + "i0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-"));

        service.setPublicKeys(pubKeys);

        service.setProviderEndpoint(endPoint);
        return service;
    }
    
    private Role createRoleObject(ZMSClient client, String domainName, String roleName, 
            String trust, int memberStart, int memberEnd) {
        
        Role role = new Role();
        role.setName(client.generateRoleName(domainName, roleName));
        if (trust != null) {
            role.setTrust(trust);
        }
        
        List<String> members = new ArrayList<>();
        if (memberStart != -1) {
            for (int i = memberStart; i < memberEnd; i++) {
                members.add("user.user" + i);
            }
        } else {
            Random userRandomizer = new Random();
            for (int i = 0; i < 25; i++) {
                members.add("user.user" + Math.abs(userRandomizer.nextInt() % 1000));
            }
        }
        role.setMembers(members);
        return role;
    }
    
    private Policy createPolicyObject(ZMSClient client, String domainName, String policyName,
            String roleName, String action, String resource, AssertionEffect effect) {
        
        Policy policy = new Policy();
        policy.setName(client.generatePolicyName(domainName, policyName));
        
        Assertion assertion = new Assertion();
        assertion.setAction(action);
        assertion.setEffect(effect);
        assertion.setResource(resource);
        assertion.setRole(client.generateRoleName(domainName, roleName));
        
        List<Assertion> assertList = new ArrayList<>();
        assertList.add(assertion);
        
        policy.setAssertions(assertList);
        return policy;
    }
    
    public static void main(String [] args) {
        
        if (args.length != 3) {
            System.out.println("ZMSLoadData <admin> <domain_start_index> <domain_end_index>");
            System.exit(1);
        }
        
        String admin = args[0];
        int startIndex = Integer.parseInt(args[1]);
        int endIndex = Integer.parseInt(args[2]);
        ZMSLoadData data = new ZMSLoadData();

        for (int i = startIndex; i < endIndex; i++) {

            ZMSClient client = data.getClient(admin);
                        
            String domainName = "TestDomain" + i;
            TopLevelDomain domain = data.createTopLevelDomainObject(domainName, "Test Domain: " + domainName, "CoreTech");
            client.postTopLevelDomain(AUDIT_REF, domain);
            
            for (int j = 0; j < 10; j++) {
                
                String serviceName = "Service" + j;
                ServiceIdentity service = data.createServiceObject(client, domainName, serviceName, 
                    "http://localhost:9080/", "/usr/bin/java", null, null);

                client.putServiceIdentity(domainName, serviceName, AUDIT_REF, service);
            }

            for (int j = 0; j < 40; j++) {
                
                String roleName = "Role" + j;
                Role role = data.createRoleObject(client, domainName, roleName, null, j * 25, (j + 1) * 25);
                client.putRole(domainName, roleName, AUDIT_REF, role);
            }
            
            for (int j = 40; j < 100; j++) {
                
                String roleName = "Role" + j;
                Role role = data.createRoleObject(client, domainName, roleName, null, -1, 1000);
                client.putRole(domainName, roleName, AUDIT_REF, role);
            }
            
            for (int j = 0; j < 100; j++) {
                
                String policyName = "Policy" + j;
                String roleName = "Role" + j;
                Policy policy = data.createPolicyObject(client, domainName, policyName, roleName,
                        "*", "*", AssertionEffect.ALLOW);
                client.putPolicy(domainName, policyName, AUDIT_REF, policy);
            }
        }
    }
}
