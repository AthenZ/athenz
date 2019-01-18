/*
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
    
    private static final String ATTR_ENABLED = "enabled";
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
    private static final String ATTR_YPMID = "ypmId";
    private static final String ATTR_EFFECT = "effect";
    private static final String ATTR_ACTION = "action";
    private static final String ATTR_RESOURCE = "resource";
    private static final String ATTR_ASSERTIONS = "assertions";
    private static final String ATTR_EXECUTABLE = "executable";
    private static final String ATTR_DESCRIPTION = "descrition";
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
    private static final String ATTR_CERT_DNS_DOMAIN = "certDnsDomain";

    private static Struct asStruct(DomainPolicies domainPolicies) {
        // all of our fields are in canonical order based
        // on their attribute name
        Struct struct = new Struct();
        appendObject(struct, ATTR_DOMAIN, domainPolicies.getDomain());
        Array policiesArray = new Array();
        for (Policy policy : domainPolicies.getPolicies()) {
            policiesArray.add(asStruct(policy));
        }
        appendArray(struct, ATTR_POLICIES, policiesArray);
        return struct;
    }
    
    private static Struct asStruct(Policy policy) {
        // all of our fields are in canonical order based
        // on their attribute name
        Struct struct = new Struct();
        List<Assertion> assertions = policy.getAssertions();
        if (assertions != null && !assertions.isEmpty()) {
            Array assertionsArray = new Array();
            for (Assertion assertion : assertions) {
                Struct structAssertion = new Struct();
                appendObject(structAssertion, ATTR_ACTION, assertion.getAction());
                appendObject(structAssertion, ATTR_EFFECT, assertion.getEffect());
                appendObject(structAssertion, ATTR_RESOURCE, assertion.getResource());
                appendObject(structAssertion, ATTR_ROLE, assertion.getRole());
                assertionsArray.add(structAssertion);
            }
            appendArray(struct, ATTR_ASSERTIONS, assertionsArray);
        }
        appendObject(struct, ATTR_MODIFIED, policy.getModified());
        appendObject(struct, ATTR_NAME, policy.getName());
        return struct;
    }
    
    private static Struct asStruct(com.yahoo.athenz.zts.Policy policy) {
        // all of our fields are in canonical order based
        // on their attribute name
        Struct struct = new Struct();
        List<com.yahoo.athenz.zts.Assertion> assertions = policy.getAssertions();
        if (assertions != null && !assertions.isEmpty()) {
            Array assertionsArray = new Array();
            for (com.yahoo.athenz.zts.Assertion assertion : assertions) {
                Struct structAssertion = new Struct();
                appendObject(structAssertion, ATTR_ACTION, assertion.getAction());
                appendObject(structAssertion, ATTR_EFFECT, assertion.getEffect());
                appendObject(structAssertion, ATTR_RESOURCE, assertion.getResource());
                appendObject(structAssertion, ATTR_ROLE, assertion.getRole());
                assertionsArray.add(structAssertion);
            }
            appendArray(struct, ATTR_ASSERTIONS, assertionsArray);
        }
        appendObject(struct, ATTR_MODIFIED, policy.getModified());
        appendObject(struct, ATTR_NAME, policy.getName());
        return struct;
    }
    
    private static Struct asStruct(Role role) {
        // all of our fields are in canonical order based
        // on their attribute name
        Struct struct = new Struct();
        appendList(struct, ATTR_MEMBERS, role.getMembers());
        appendObject(struct, ATTR_MODIFIED, role.getModified());
        appendObject(struct, ATTR_NAME, role.getName());
        List<RoleMember> roleMembers = role.getRoleMembers();
        if (roleMembers != null) {
            Array roleMembersArray = new Array();
            for (RoleMember roleMember : roleMembers) {
                Struct structRoleMember = new Struct();
                appendObject(structRoleMember, ATTR_EXPIRATION, roleMember.getExpiration());
                appendObject(structRoleMember, ATTR_MEMBER_NAME, roleMember.getMemberName());
                roleMembersArray.add(structRoleMember);
            }
            appendArray(struct, ATTR_ROLE_MEMBERS, roleMembersArray);
        }
        appendObject(struct, ATTR_TRUST, role.getTrust());
        return struct;
    }
    
    private static Struct asStruct(ServiceIdentity service) {
        // all of our fields are in canonical order based
        // on their attribute name
        Struct struct = new Struct();
        appendObject(struct, ATTR_DESCRIPTION, service.getDescription());
        appendObject(struct, ATTR_EXECUTABLE, service.getExecutable());
        appendObject(struct, ATTR_GROUP, service.getGroup());
        appendList(struct, ATTR_HOSTS, service.getHosts());
        appendObject(struct, ATTR_MODIFIED, service.getModified());
        appendObject(struct, ATTR_NAME, service.getName());
        appendObject(struct, ATTR_PROVIDER_ENDPOINT, service.getProviderEndpoint());
        List<PublicKeyEntry> publicKeys = service.getPublicKeys();
        Array publicKeysArray = new Array();
        if (publicKeys != null) {
            for (PublicKeyEntry publicKey : publicKeys) {
                Struct structPublicKey = new Struct();
                appendObject(structPublicKey, ATTR_ID, publicKey.getId());
                appendObject(structPublicKey, ATTR_KEY, publicKey.getKey());
                publicKeysArray.add(structPublicKey);
            }
        }
        appendArray(struct, ATTR_PUBLIC_KEYS, publicKeysArray);
        appendObject(struct, ATTR_USER, service.getUser());
        return struct;
    }
    
    private static void appendList(Struct struct, String name, List<String> list) {
        if (list == null) {
            return;
        }
        Array items = new Array();
        items.addAll(list);
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
        } else if (value instanceof Integer) {
            struct.append(name, value);
        } else if (value instanceof Boolean) {
            struct.append(name, value);
        } else {
            struct.append(name, value.toString());
        }
    }
    
    private static void appendArray(Struct struct, String name, Array array) {
        struct.append(name, array);
    }
    
    private static Object asStruct(PolicyData policyData) {
        // all of our fields are in canonical order based
        // on their attribute name
        Struct struct = new Struct();
        appendObject(struct, ATTR_DOMAIN, policyData.getDomain());
        List<com.yahoo.athenz.zts.Policy> policies = policyData.getPolicies();
        Array policiesArray = new Array();
        if (policies != null) {
            for (com.yahoo.athenz.zts.Policy policy : policies) {
                policiesArray.add(asStruct(policy));
            }
        }
        appendArray(struct, ATTR_POLICIES, policiesArray);
        return struct;
    }
    
    private static Object asStruct(SignedPolicyData signedPolicyData) {
        // all of our fields are in canonical order based
        // on their attribute name
        Struct struct = new Struct();
        appendObject(struct, ATTR_EXPIRES, signedPolicyData.getExpires());
        appendObject(struct, ATTR_MODIFIED, signedPolicyData.getModified());
        appendObject(struct, ATTR_POLICY_DATA, asStruct(signedPolicyData.getPolicyData()));
        appendObject(struct, ATTR_ZMS_KEY_ID, signedPolicyData.getZmsKeyId());
        appendObject(struct, ATTR_ZMS_SIGNATURE, signedPolicyData.getZmsSignature());
        return struct;
    }
    
    private static Struct asStruct(DomainData domainData) {
        // all of our fields are in canonical order based
        // on their attribute name
        Struct struct = new Struct();
        appendObject(struct, ATTR_ACCOUNT, domainData.getAccount());
        appendObject(struct, ATTR_CERT_DNS_DOMAIN, domainData.getCertDnsDomain());
        appendObject(struct, ATTR_ENABLED, domainData.getEnabled());
        appendObject(struct, ATTR_MODIFIED, domainData.getModified());
        appendObject(struct, ATTR_NAME, domainData.getName());
        SignedPolicies signedPolicies = domainData.getPolicies();
        if (signedPolicies != null) {
            Struct structSignedPolicies = new Struct();
            appendObject(structSignedPolicies, ATTR_CONTENTS, asStruct(signedPolicies.getContents()));
            appendObject(structSignedPolicies, ATTR_KEYID, signedPolicies.getKeyId());
            appendObject(struct, ATTR_POLICIES, structSignedPolicies);
            appendObject(structSignedPolicies, ATTR_SIGNATURE, signedPolicies.getSignature());
        }
        Array structRoles = new Array();
        if (domainData.getRoles() != null) {
            for (Role role : domainData.getRoles()) {
                structRoles.add(asStruct(role));
            }
        }
        appendArray(struct, ATTR_ROLES, structRoles);
        Array structServices = new Array();
        if (domainData.getServices() != null) {
            for (ServiceIdentity service : domainData.getServices()) {
                structServices.add(asStruct(service));
            }
        }
        appendArray(struct, ATTR_SERVICES, structServices);
        appendObject(struct, ATTR_YPMID, domainData.getYpmId());
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
    
    static String asCanonicalString(Object obj) {
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
        } else if (obj instanceof Integer) {
            strBuffer.append(obj);
        } else if (obj instanceof Long) {
            strBuffer.append(obj);
        } else if (obj instanceof Boolean) {
            strBuffer.append(obj);
        } else {
            strBuffer.append(obj.toString());
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
