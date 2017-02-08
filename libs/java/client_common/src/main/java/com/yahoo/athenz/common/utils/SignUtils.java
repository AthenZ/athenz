/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.common.utils;

import java.util.List;

import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.DomainPolicies;
import com.yahoo.athenz.zms.Policy;
import com.yahoo.athenz.zms.PublicKeyEntry;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zms.ServiceIdentity;
import com.yahoo.athenz.zms.SignedPolicies;
import com.yahoo.athenz.zts.PolicyData;
import com.yahoo.athenz.zts.SignedPolicyData;
import com.yahoo.rdl.Array;
import com.yahoo.rdl.Struct;

public class SignUtils {
    
    private static final String ATTR_MODIFIED = "modified";
    private static final String ATTR_POLICIES = "policies";
    private static final String ATTR_DOMAIN = "domain";
    private static final String ATTR_EXPIRES = "expires";
    private static final String ATTR_POLICY_DATA = "policyData";
    private static final String ATTR_ZMS_SIGNATURE = "zmsSignature";
    private static final String ATTR_ZMS_KEY_ID = "zmsKeyId";
    private static final String ATTR_MEMBERS = "members";
    private static final String ATTR_ROLE_MEMBERS = "roleMembers";
    private static final String ATTR_MEMBER_NAME = "memberName";
    private static final String ATTR_EXPIRATION = "expiration";
    private static final String ATTR_NAME = "name";
    private static final String ATTR_ROLE = "role";
    private static final String ATTR_SERVICES = "services";
    private static final String ATTR_ID = "id";
    private static final String ATTR_PUBLIC_KEYS = "publicKeys";
    private static final String ATTR_ACCOUNT = "account";
    private static final String ATTR_PRODUCT_ID = "ypmId";
    private static final String ATTR_EFFECT = "effect";
    private static final String ATTR_ACTION = "action";
    private static final String ATTR_RESOURCE = "resource";
    private static final String ATTR_ASSERTIONS = "assertions";
    private static final String ATTR_EXECUTABLE = "executable";
    private static final String ATTR_TRUST = "trust";
    private static final String ATTR_GROUP = "group";
    private static final String ATTR_PROVIDER_ENDPOINT = "providerEndpoint";
    private static final String ATTR_USER = "user";
    private static final String ATTR_HOSTS = "hosts";
    private static final String ATTR_KEY = "key";
    private static final String ATTR_ROLES = "roles";
    private static final String ATTR_SIGNATURE = "signature";
    private static final String ATTR_KEYID = "keyId";
    private static final String ATTR_CONTENTS = "contents";

    private static Struct asStruct(DomainPolicies domainPolicies) {
        Struct struct = new Struct();
        struct.append(ATTR_DOMAIN, domainPolicies.getDomain());
        Array policiesArray = new Array();
        for (Policy policy : domainPolicies.getPolicies()) {
            policiesArray.add(asStruct(policy));
        }
        appendArray(struct, ATTR_POLICIES, policiesArray);
        return struct;
    }
    
    private static Struct asStruct(Policy policy) {
        Struct struct = new Struct();
        struct.append(ATTR_NAME, policy.getName());
        struct.append(ATTR_MODIFIED, policy.getModified());
        List<Assertion> assertions = policy.getAssertions();
        if (assertions != null) {
            Array assertionsArray = new Array();
            for (Assertion assertion : assertions) {
                Struct structAssertion = new Struct();
                appendObject(structAssertion, ATTR_EFFECT, assertion.getEffect());
                structAssertion.append(ATTR_ACTION, assertion.getAction());
                structAssertion.append(ATTR_RESOURCE, assertion.getResource());
                structAssertion.append(ATTR_ROLE, assertion.getRole());
                assertionsArray.add(structAssertion);
            }
            appendArray(struct, ATTR_ASSERTIONS, assertionsArray);
        }
        return struct;
    }
    
    private static Struct asStruct(com.yahoo.athenz.zts.Policy policy) {
        Struct struct = new Struct();
        struct.append(ATTR_NAME, policy.getName());
        struct.append(ATTR_MODIFIED, policy.getModified());
        List<com.yahoo.athenz.zts.Assertion> assertions = policy.getAssertions();
        if (assertions != null) {
            Array assertionsArray = new Array();
            for (com.yahoo.athenz.zts.Assertion assertion : assertions) {
                Struct structAssertion = new Struct();
                appendObject(structAssertion, ATTR_EFFECT, assertion.getEffect());
                structAssertion.append(ATTR_ACTION, assertion.getAction());
                structAssertion.append(ATTR_RESOURCE, assertion.getResource());
                structAssertion.append(ATTR_ROLE, assertion.getRole());
                assertionsArray.add(structAssertion);
            }
            appendArray(struct, ATTR_ASSERTIONS, assertionsArray);
        }
        return struct;
    }
    
    private static Struct asStruct(Role role) {
        Struct struct = new Struct();
        struct.append(ATTR_NAME, role.getName());
        struct.append(ATTR_MODIFIED, role.getModified());
        appendObject(struct, ATTR_TRUST, role.getTrust());
        appendList(struct, ATTR_MEMBERS, role.getMembers());
        List<RoleMember> roleMembers = role.getRoleMembers();
        if (roleMembers != null) {
            Array roleMembersArray = new Array();
            for (RoleMember roleMember : roleMembers) {
                Struct structRoleMember = new Struct();
                structRoleMember.append(ATTR_MEMBER_NAME, roleMember.getMemberName());
                appendObject(structRoleMember, ATTR_EXPIRATION,
                        roleMember.getExpiration());
                roleMembersArray.add(structRoleMember);
            }
            appendArray(struct, ATTR_ROLE_MEMBERS, roleMembersArray);
        }
        return struct;
    }
    
    private static Struct asStruct(ServiceIdentity service) {
        Struct struct = new Struct();
        struct.append(ATTR_NAME, service.getName());
        struct.append(ATTR_MODIFIED, service.getModified());
        appendObject(struct, ATTR_EXECUTABLE, service.getExecutable());
        appendObject(struct, ATTR_GROUP, service.getGroup());
        appendObject(struct, ATTR_PROVIDER_ENDPOINT, service.getProviderEndpoint());
        appendObject(struct, ATTR_USER, service.getUser());
        appendList(struct, ATTR_HOSTS, service.getHosts());
        List<PublicKeyEntry> publicKeys = service.getPublicKeys();
        if (publicKeys != null) {
            Array publicKeysArray = new Array();
            for (PublicKeyEntry publicKey : publicKeys) {
                Struct structPublicKey = new Struct();
                structPublicKey.append(ATTR_ID, publicKey.getId());
                structPublicKey.append(ATTR_KEY, publicKey.getKey());
                publicKeysArray.add(structPublicKey);
            }
            appendArray(struct, ATTR_PUBLIC_KEYS, publicKeysArray);
        }
        return struct;
    }
    
    private static void appendList(Struct struct, String name, List<String> list) {
        if (list == null) {
            return;
        }
        Array items = new Array();
        for (String item : list) {
            items.add(item);
        }
        appendArray(struct, name, items);
    }
    
    private static void appendObject(Struct struct, String name, Object value) {
        if (value == null) {
            return;
        }
        if (value instanceof Struct) {
            struct.append(name, value);
        } else if (value instanceof String) {
            struct.append(name, value);
        } else {
            struct.append(name, value.toString());
        }
    }
    
    private static void appendArray(Struct struct, String name, Array array) {
        if (array != null && !array.isEmpty()) {
            struct.append(name, array);
        }
    }
    
    private static Object asStruct(PolicyData policyData) {
        Struct struct = new Struct();
        struct.append(ATTR_DOMAIN, policyData.getDomain());
        List<com.yahoo.athenz.zts.Policy> policies = policyData.getPolicies();
        if (policies != null) {
            Array policiesArray = new Array();
            for (com.yahoo.athenz.zts.Policy policy : policies) {
                policiesArray.add(asStruct(policy));
            }
            appendArray(struct, ATTR_POLICIES, policiesArray);
        }
        return struct;
    }
    
    private static Object asStruct(SignedPolicyData signedPolicyData) {
        Struct struct = new Struct();
        struct.append(ATTR_MODIFIED, signedPolicyData.getModified());
        struct.append(ATTR_EXPIRES, signedPolicyData.getExpires());
        struct.append(ATTR_ZMS_KEY_ID, signedPolicyData.getZmsKeyId());
        struct.append(ATTR_ZMS_SIGNATURE, signedPolicyData.getZmsSignature());
        struct.append(ATTR_POLICY_DATA, asStruct(signedPolicyData.getPolicyData()));
        return struct;
    }
    
    private static Struct asStruct(DomainData domainData) {
        Struct struct = new Struct();
        struct.append(ATTR_MODIFIED, domainData.getModified());
        appendObject(struct, ATTR_ACCOUNT, domainData.getAccount());
        appendObject(struct, ATTR_PRODUCT_ID, domainData.getYpmId());
        if (domainData.getRoles() != null) {
            Array structRoles = new Array();
            for (Role role : domainData.getRoles()) {
                structRoles.add(asStruct(role));
            }
            appendArray(struct, ATTR_ROLES, structRoles);
        }
        if (domainData.getServices() != null) {
            Array structServices = new Array();
            for (ServiceIdentity service : domainData.getServices()) {
                structServices.add(asStruct(service));
            }
            appendArray(struct, ATTR_SERVICES, structServices);
        }
        SignedPolicies signedPolicies = domainData.getPolicies();
        if (signedPolicies != null) {
            Struct structSignedPolicies = new Struct();
            appendObject(structSignedPolicies, ATTR_SIGNATURE, signedPolicies.getSignature());
            appendObject(structSignedPolicies, ATTR_KEYID, signedPolicies.getKeyId());
            appendObject(structSignedPolicies, ATTR_CONTENTS, asStruct(signedPolicies.getContents()));
            struct.append(ATTR_POLICIES, structSignedPolicies);
        }
        return struct;
    }
    
    private static void appendSeparator(StringBuilder strBuffer) {
        // if we have more than a single character
        // (which is our initial {/[ character) 
        // in our buffer then we need to separate
        // the item with a comma
        if (strBuffer.length() != 1) {
            strBuffer.append(',');
        }
    }
    
    private static String asCanonicalString(Object obj) {
        StringBuilder strBuffer = new StringBuilder();
        if (obj instanceof Struct) {
            Struct struct = (Struct) obj;
            strBuffer.append('{');
            for (String name : struct.sortedNames()) {
                appendSeparator(strBuffer);
                strBuffer.append('"');
                strBuffer.append(name);
                strBuffer.append("\":");
                strBuffer.append(asCanonicalString(struct.get(name)));
            }
            strBuffer.append('}');
        } else if (obj instanceof Array) {
            strBuffer.append('[');
            for (Object item : (Array) obj) {
                appendSeparator(strBuffer);
                strBuffer.append(asCanonicalString(item));
            }
            strBuffer.append(']');
        } else if (obj instanceof String) {
            strBuffer.append('"');
            strBuffer.append(obj);
            strBuffer.append('"');
        }
        return strBuffer.toString();
    }
    
    public static String asCanonicalString(PolicyData policyData) {
        return asCanonicalString(asStruct(policyData));
    }
    
    public static String asCanonicalString(DomainData domainData) {
        return asCanonicalString(asStruct(domainData));
    }
    
    public static String asCanonicalString(DomainPolicies domainPolicies) {
        return asCanonicalString(asStruct(domainPolicies));
    }
    
    public static String asCanonicalString(SignedPolicyData signedPolicyData) {
        return asCanonicalString(asStruct(signedPolicyData));
    }
}
