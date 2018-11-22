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
package com.yahoo.athenz.zms.store.file;

import java.util.*;

import com.yahoo.athenz.zms.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.yahoo.athenz.zms.store.AthenzDomain;
import com.yahoo.athenz.zms.store.ObjectStoreConnection;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Timestamp;

public class FileConnection implements ObjectStoreConnection {

    private static final String ALL_PRINCIPALS  = "*";
    private static final Logger LOG = LoggerFactory.getLogger(FileConnection.class);

    final File rootDir;
    File quotaDir;
    public FileConnection(File rootDir, File quotaDir) {
        this.rootDir = rootDir;
        this.quotaDir = quotaDir;
    }

    @Override
    public void commitChanges() {
    }

    @Override
    public void rollbackChanges() {
    }

    @Override
    public void close() {
    }
    
    @Override
    public void setOperationTimeout(int opTimeout) {
    }

    @Override
    public Domain getDomain(String domainName) {
        
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            return null;
        }
        return getDomain(domainStruct);
    }

    private Domain getDomain(DomainStruct domainStruct) {
        Domain domain = new Domain()
                .setAccount(domainStruct.getMeta().getAccount())
                .setDescription(domainStruct.getMeta().getDescription())
                .setId(domainStruct.getId())
                .setModified(domainStruct.getModified())
                .setName(domainStruct.getName())
                .setOrg(domainStruct.getMeta().getOrg())
                .setYpmId(domainStruct.getMeta().getYpmId())
                .setApplicationId(domainStruct.getMeta().getApplicationId());
        if (domainStruct.getMeta().getAuditEnabled() != null) {
            domain.setAuditEnabled(domainStruct.getMeta().getAuditEnabled());
        } else {
            domain.setAuditEnabled(false);
        }
        if (domainStruct.getMeta().getEnabled() != null) {
            domain.setEnabled(domainStruct.getMeta().getEnabled());
        } else {
            domain.setEnabled(true);
        }
        return domain;
    }

    private String[] getDomainList() {
        String[] fnames = rootDir.list();
        if (fnames == null) {
            fnames = new String[0];
        }
        return fnames;
    }

    @Override
    public long getDomainModTimestamp(String domainName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            return 0;
        }
        return domainStruct.getModified().millis();
    }

    @Override
    public boolean insertDomain(Domain domain) {
        
        DomainStruct domainStruct = getDomainStruct(domain.getName());
        if (domainStruct != null) {
            return false;
        }

        verifyDomainProductIdUniqueness(domain.getName(), domain.getYpmId(), "insertDomain");

        domainStruct = new DomainStruct();
        domainStruct.setId(domain.getId());
        domainStruct.setName(domain.getName());
        domainStruct.setModified(Timestamp.fromCurrentTime());

        DomainMeta meta = new DomainMeta()
                .setAccount(domain.getAccount())
                .setAuditEnabled(domain.getAuditEnabled())
                .setDescription(domain.getDescription())
                .setEnabled(domain.getEnabled())
                .setOrg(domain.getOrg())
                .setYpmId(domain.getYpmId())
                .setApplicationId(domain.getApplicationId());
        domainStruct.setMeta(meta);
        
        putDomainStruct(domain.getName(), domainStruct);
        return true;
    }

    void verifyDomainProductIdUniqueness(String name, Integer productId, String caller) {

        if (productId == null || productId == 0) {
            return;
        }
        String domName = lookupDomainById(null, productId);
        if (domName != null && !domName.equals(name)) {
            throw ZMSUtils.requestError("Product Id: " + productId +
                    " is already assigned to domain: " + domName, caller);
        }
    }

    @Override
    public boolean updateDomain(Domain domain) {

        DomainStruct domainStruct = getDomainStruct(domain.getName());
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "updateDomain");
        }

        verifyDomainProductIdUniqueness(domain.getName(), domain.getYpmId(), "updateDomain");

        domainStruct.setId(domain.getId());
        domainStruct.setName(domain.getName());
        domainStruct.setModified(Timestamp.fromCurrentTime());
        DomainMeta meta = new DomainMeta()
                .setAccount(domain.getAccount())
                .setAuditEnabled(domain.getAuditEnabled())
                .setDescription(domain.getDescription())
                .setEnabled(domain.getEnabled())
                .setOrg(domain.getOrg())
                .setYpmId(domain.getYpmId())
                .setApplicationId(domain.getApplicationId());
        domainStruct.setMeta(meta);

        putDomainStruct(domain.getName(), domainStruct);
        return true;
    }

    @Override
    public boolean deleteDomain(String domainName) {
        File domainFile = new File(rootDir, domainName);
        delete(domainFile);
        return true;
    }

    @Override
    public boolean updateDomainModTimestamp(String domainName) {

        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "updateDomainModTimestamp");
        }
        domainStruct.setModified(Timestamp.fromCurrentTime());
        putDomainStruct(domainName, domainStruct);
        return true;
    }

    @Override
    public List<String> listDomains(String prefix, long modifiedSince) {

        List<String> domainList = new ArrayList<>();
        String[] fnames = getDomainList();
        List<String> slist = new ArrayList<>(java.util.Arrays.asList(fnames));
        java.util.Collections.sort(slist);
        for (String name : slist) {
            if (prefix != null) {
                if (name.startsWith(prefix)) {
                    domainList.add(name);
                }
            } else {
                domainList.add(name);
            }
        }
        return domainList;
    }

    @Override
    public List<String> lookupDomainByRole(String roleMember, String roleName) {

        boolean memberPresent = (roleMember != null && !roleMember.isEmpty());
        boolean rolePresent = (roleName != null && !roleName.isEmpty());

        // first get the list of domains

        Set<String> uniqueDomains = new HashSet<>();
        List<String> domainNames = listDomains(null, 0);
        for (String domainName : domainNames) {
            DomainStruct domainStruct = getDomainStruct(domainName);
            if (domainStruct == null) {
                continue;
            }
            if (rolePresent || memberPresent) {
                if (rolePresent) {
                    Role role = getRoleObject(domainStruct, roleName);
                    if (role == null) {
                        continue;
                    }
                    if (memberPresent) {
                        List<RoleMember> roleMembers = role.getRoleMembers();
                        if (roleMembers != null) {
                            for (RoleMember member: roleMembers) {
                                if (member.getMemberName().equalsIgnoreCase(roleMember)) {
                                    uniqueDomains.add(domainName);
                                    break;
                                }
                            }
                        }
                    } else {
                        uniqueDomains.add(domainName);
                    }
                } else {
                    HashMap<String, Role> roles = domainStruct.getRoles();
                    if (roles != null) {
                        for (Role role : roles.values()) {
                            boolean roleMemberFound = false;
                            if (role.getRoleMembers() != null) {
                                for (RoleMember member: role.getRoleMembers()) {
                                    if (member.getMemberName().equals(roleMember)) {
                                        uniqueDomains.add(domainName);
                                        roleMemberFound = true;
                                        break;
                                    }
                                }
                                if (roleMemberFound) {
                                    break;
                                }
                            }
                        }
                    }

                }
            } else {
                uniqueDomains.add(domainName);
            }
        }

        List<String> matchedDomains = new ArrayList<>(uniqueDomains);
        Collections.sort(matchedDomains);
        return matchedDomains;
    }

    @Override
    public String lookupDomainById(String account, int productId) {

        // first get the list of domains

        List<String> domainNames = listDomains(null, 0);
        for (String domainName : domainNames) {
            Domain domain = getDomain(domainName);
            if (domain == null) {
                continue;
            }
            if (account != null) {
                if (domain.getAccount() != null && account.equals(domain.getAccount())) {
                    return domainName;
                }
            } else if (productId != 0) {
                if (domain.getYpmId() != null && domain.getYpmId() == productId) {
                    return domainName;
                }
            }
        }

        return null;
    }

    @Override
    public AthenzDomain getAthenzDomain(String domainName) {

        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "getAthenzDomain");
        }
        AthenzDomain athenzDomain = new AthenzDomain(domainName);
        athenzDomain.setDomain(getDomain(domainStruct));
        if (domainStruct.getRoles() != null) {
            athenzDomain.setRoles(new ArrayList<>(domainStruct.getRoles().values()));
        }
        if (domainStruct.getPolicies() != null) {
            athenzDomain.setPolicies(new ArrayList<>(domainStruct.getPolicies().values()));
        }
        if (domainStruct.getServices() != null) {
            athenzDomain.setServices(new ArrayList<>(domainStruct.getServices().values()));
        }

        return athenzDomain;
    }

    @Override
    public DomainModifiedList listModifiedDomains(long modifiedSince) {

        DomainModifiedList domainModifiedList = new DomainModifiedList();
        List<DomainModified> nameMods = new ArrayList<>();

        List<String> domainList = listDomains(null, modifiedSince);

        // Now set the dest for the returned domain names

        for (String dname : domainList) {
            DomainStruct domainStruct = getDomainStruct(dname);
            if (domainStruct == null) {
                return null;
            }
            long ts = domainStruct.getModified().millis();
            if (ts <= modifiedSince) {
                continue;
            }
            DomainModified dm = new DomainModified().setName(dname)
                    .setModified(ts)
                    .setYpmId(domainStruct.getMeta().getYpmId())
                    .setAccount(domainStruct.getMeta().getAccount());
            nameMods.add(dm);
        }

        domainModifiedList.setNameModList(nameMods);
        return domainModifiedList;
    }

    @Override
    public boolean insertDomainTemplate(String domainName, String templateName, String params) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "insertDomainTemplate");
        }

        if (domainStruct.getTemplates() == null) {
            domainStruct.setTemplates(new ArrayList<>());
        }
        ArrayList<String> templates = domainStruct.getTemplates();
        if (!templates.contains(templateName)) {
            templates.add(templateName);
        }
        putDomainStruct(domainName, domainStruct);
        return true;
    }

    @Override
    public boolean deleteDomainTemplate(String domainName, String templateName, String params) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "deleteDomainTemplate");
        }
        ArrayList<String> templates = domainStruct.getTemplates();
        if (templates == null) {
            return true;
        }
        templates.remove(templateName);
        putDomainStruct(domainName, domainStruct);
        return true;
    }

    @Override
    public List<String> listDomainTemplates(String domainName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "listDomainTemplates");
        }
        ArrayList<String> list = new ArrayList<>();
        if (domainStruct.getTemplates() != null) {
            list.addAll(domainStruct.getTemplates());
        }
        return list;
    }

    @Override
    public List<PrincipalRole> listPrincipalRoles(String domainName, String principalName) {

        List<PrincipalRole> roles = new ArrayList<>();

        if (domainName != null) {
            DomainStruct domainStruct = getDomainStruct(domainName);
            if (domainStruct == null) {
                throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "listPrincipalRoles");
            }
            addPrincipalRoles(domainStruct, roles, domainName, principalName);
        } else {
            // we're going to go through all domains

            String[] fnames = getDomainList();
            for (String fname : fnames) {
                DomainStruct domainStruct = getDomainStruct(fname);
                if (domainStruct == null) {
                    continue;
                }
                addPrincipalRoles(domainStruct, roles, fname, principalName);
            }
        }
        return roles;
    }

    public void addPrincipalRoles(DomainStruct domainStruct, List<PrincipalRole> roles,
            String domainName, String principalName) {

        for (Role role: domainStruct.getRoles().values()) {
            List<RoleMember> roleMembers = role.getRoleMembers();
            if (roleMembers == null) {
                continue;
            }
            for (RoleMember roleMember : roleMembers) {
                final String memberName = roleMember.getMemberName();
                if (memberName.equals(principalName)) {
                    PrincipalRole pRole = new PrincipalRole();
                    pRole.setDomainName(domainName);
                    pRole.setRoleName(extractRoleName(domainName, role.getName()));
                    roles.add(pRole);
                }
            }
        }
    }

    @Override
    public List<String> listPrincipals(String domainName) {
        
        // we're going to go through all domains and extract any
        // principal that satisfies our filter domainName

        String[] fnames = getDomainList();
        Set<String> principals = new HashSet<>();
        String domainNamePrefix = domainName == null ? null : domainName + ".";
        for (String fname : fnames) {
            DomainStruct domainStruct = getDomainStruct(fname);
            if (domainStruct == null) {
                continue;
            }
            
            for (Role role: domainStruct.getRoles().values()) {
                List<RoleMember> roleMembers = role.getRoleMembers();
                if (roleMembers == null) {
                    continue;
                }
                for (RoleMember roleMember : roleMembers) {
                    
                    final String memberName = roleMember.getMemberName();
                    if (domainNamePrefix == null) {
                        principals.add(memberName);
                    } else if (memberName.startsWith(domainNamePrefix)) {
                        principals.add(memberName);
                    }
                }
            }
        }
        return new ArrayList<>(principals);
    }
    
    @SuppressWarnings("SuspiciousListRemoveInLoop")
    @Override
    public boolean deletePrincipal(String principalName, boolean subDomains) {
        
        // we're going to go through all domains and delete any
        // principal that satisfies our criteria

        String[] fnames = getDomainList();
        String domainNamePrefix = subDomains ? principalName + "." : null;
        for (String fname : fnames) {
            DomainStruct domainStruct = getDomainStruct(fname);
            if (domainStruct == null) {
                continue;
            }
            
            boolean domainChanged = false;
            for (Role role: domainStruct.getRoles().values()) {
                List<RoleMember> roleMembers = role.getRoleMembers();
                if (roleMembers == null) {
                    continue;
                }
                for (int idx = 0; idx < roleMembers.size(); idx++) {
                    final String memberName = roleMembers.get(idx).getMemberName();
                    if (memberName.equals(principalName) ||
                            (domainNamePrefix != null && memberName.startsWith(domainNamePrefix))) {
                        roleMembers.remove(idx);
                        domainChanged = true;
                    }
                }
            }
            if (domainChanged) {
                putDomainStruct(domainStruct.getName(), domainStruct);
            }
        }
        return true;
    }
    
    Role getRoleObject(DomainStruct domain, String roleName) {
        HashMap<String, Role> roles = domain.getRoles();
        if (roles == null) {
            return null;
        }
        return roles.get(roleName);
    }
    
    Policy getPolicyObject(DomainStruct domain, String policyName) {
        HashMap<String, Policy> policies = domain.getPolicies();
        if (policies == null) {
            return null;
        }
        return policies.get(policyName);
    }
    
    ServiceIdentity getServiceObject(DomainStruct domain, String serviceName) {
        HashMap<String, ServiceIdentity> services = domain.getServices();
        if (services == null) {
            return null;
        }
        return services.get(serviceName);
    }
    
    Entity getEntityObject(DomainStruct domain, String entityName) {
        HashMap<String, Entity> entities = domain.getEntities();
        if (entities == null) {
            return null;
        }
        return entities.get(entityName);
    }
    
    @Override
    public Role getRole(String domainName, String roleName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "getRole");
        }
        return getRoleObject(domainStruct, roleName);
    }

    @Override
    public boolean insertRole(String domainName, Role role) {
        updateRole(domainName, role);
        return true;
    }

    @Override
    public boolean updateRole(String domainName, Role role) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "updateRole");
        }
        if (domainStruct.getRoles() == null) {
            domainStruct.setRoles(new HashMap<>());
        }
        HashMap<String, Role> roles = domainStruct.getRoles();

        String roleName = extractRoleName(domainName, role.getName());
        if (roleName == null) {
            throw ZMSUtils.error(ResourceException.BAD_REQUEST, "invalid role name", "updateRole");
        }
        
        // here we only need to update the main attrs and not
        // the members

        Role originalRole = getRoleObject(domainStruct, roleName);
        List<RoleMember> members = role.getRoleMembers();
        if (originalRole != null) {
            role.setRoleMembers(originalRole.getRoleMembers());
        } else {
            role.setRoleMembers(null);
        }
        role.setModified(Timestamp.fromCurrentTime());
        roles.put(roleName, role);
        putDomainStruct(domainName, domainStruct);
        role.setRoleMembers(members);
        return true;
    }

    @Override
    public boolean updateRoleModTimestamp(String domainName, String roleName) {

        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "updateRoleModTimestamp");
        }
        Role role = getRoleObject(domainStruct, roleName);
        role.setModified(Timestamp.fromCurrentTime());
        putDomainStruct(domainName, domainStruct);
        return true;
    }

    @Override
    public boolean deleteRole(String domainName, String roleName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "deleteRole");
        }
        HashMap<String, Role> roles = domainStruct.getRoles();

        if (roles != null) {
            roles.remove(roleName);
            putDomainStruct(domainName, domainStruct);
        }
        return true;
    }

    @Override
    public List<String> listEntities(String domainName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "listEntities");
        }
        HashMap<String, Entity> entities = domainStruct.getEntities();
        ArrayList<String> list = new ArrayList<>();
        if (entities != null) {
            list.addAll(entities.keySet());
        }
        Collections.sort(list);
        return list;
    }

    @Override
    public List<String> listRoles(String domainName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "listRoles");
        }
        HashMap<String, Role> roles = domainStruct.getRoles();
        ArrayList<String> list = new ArrayList<>();
        if (roles != null) {
            list.addAll(roles.keySet());
        }
        Collections.sort(list);
        return list;
    }

    @Override
    public List<RoleMember> listRoleMembers(String domainName, String roleName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "listRoleMembers");
        }
        Role role = getRoleObject(domainStruct, roleName);
        if (role == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "role not found", "listRoleMembers");
        }
        return role.getRoleMembers();
    }

    @Override
    public Membership getRoleMember(String domainName, String roleName, String principal) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "getRoleMember");
        }
        Role role = getRoleObject(domainStruct, roleName);
        if (role == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "role not found", "getRoleMember");
        }
        Membership membership = new Membership()
                .setMemberName(principal)
                .setRoleName(ZMSUtils.roleResourceName(domainName, roleName))
                .setIsMember(false);
        if (role.getRoleMembers() != null) {
            Set<RoleMember> members = new HashSet<>(role.getRoleMembers());
            for (RoleMember member: members) {
                if (member.getMemberName().equalsIgnoreCase(principal)) {
                    membership.setIsMember(true);
                    membership.setExpiration(member.getExpiration());
                    break;
                }
            }
        }
        return membership;
    }

    @Override
    public boolean insertRoleMember(String domainName, String roleName, RoleMember member,
            String admin, String auditRef) {

        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "insertRoleMember");
        }
        Role role = getRoleObject(domainStruct, roleName);
        if (role == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "role not found", "insertRoleMember");
        }
        if (!validatePrincipalDomain(member.getMemberName())) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "principal domain not found", "insertRoleMember");
        }
        // make sure our existing role as the member array
        // and if it doesn't exist then create one
        if (role.getRoleMembers() == null) {
            role.setRoleMembers(new ArrayList<>());
        }
        // need to check if the member already exists
        boolean entryUpdated = false;
        for (RoleMember roleMember : role.getRoleMembers()) {
            if (roleMember.getMemberName().equals(member.getMemberName())) {
                roleMember.setExpiration(member.getExpiration());
                entryUpdated = true;
            }
        }
        if (!entryUpdated) {
            role.getRoleMembers().add(member);
        }
        putDomainStruct(domainName, domainStruct);
        return true;
    }

    boolean validatePrincipalDomain(String principal) {
        // special case for all principals
        if (ALL_PRINCIPALS.equals(principal)) {
            return true;
        }
        int idx = principal.lastIndexOf('.');
        if (idx == -1 || idx == 0 || idx == principal.length() - 1) {
            return false;
        }
        return getDomainStruct(principal.substring(0, idx)) != null;
    }

    @Override
    public boolean deleteRoleMember(String domainName, String roleName, String principal,
            String admin, String auditRef) {

        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "deleteRoleMember");
        }
        Role role = getRoleObject(domainStruct, roleName);
        if (role == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "role not found", "deleteRoleMember");
        }
        List<RoleMember> roleMembers = role.getRoleMembers();
        if (roleMembers != null) {
            for (int idx = 0; idx < roleMembers.size(); idx++) {
                if (roleMembers.get(idx).getMemberName().equalsIgnoreCase(principal)) {
                    roleMembers.remove(idx);
                    break;
                }
            }
        }
        putDomainStruct(domainName, domainStruct);
        return true;
    }

    @Override
    public Policy getPolicy(String domainName, String policyName) {
        
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "getPolicy");
        }
        return getPolicyObject(domainStruct, policyName);
    }

    @Override
    public boolean insertPolicy(String domainName, Policy policy) {
        return updatePolicy(domainName, policy);
    }

    @Override
    public boolean updatePolicy(String domainName, Policy policy) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "updatePolicy");
        }

        if (domainStruct.getPolicies() == null) {
            domainStruct.setPolicies(new HashMap<>());
        }
        HashMap<String, Policy> policies = domainStruct.getPolicies();
        
        String policyName = extractPolicyName(domainName, policy.getName());

        // here we only need to update the main attrs and not
        // the assertions

        List<Assertion> assertions = policy.getAssertions();
        Policy originalPolicy = getPolicyObject(domainStruct, policyName);
        if (originalPolicy != null) {
            policy.setAssertions(originalPolicy.getAssertions());
        } else {
            policy.setAssertions(null);
        }
        policy.setModified(Timestamp.fromCurrentTime());
        policies.put(policyName, policy);
        putDomainStruct(domainName, domainStruct);
        policy.setAssertions(assertions);
        return true;
    }

    @Override
    public boolean deletePolicy(String domainName, String policyName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "deletePolicy");
        }
        if (domainStruct.getPolicies() != null) {
            domainStruct.getPolicies().remove(policyName);
            putDomainStruct(domainName, domainStruct);
        }
        return true;
    }

    @Override
    public List<String> listPolicies(String domainName, String assertionRoleName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "listPolicies");
        }
        ArrayList<String> list = new ArrayList<>();
        if (assertionRoleName == null) {
            HashMap<String, Policy> policies = domainStruct.getPolicies();
            if (policies != null) {
                list.addAll(policies.keySet());
            }
        } else {
            List<Assertion> assertions;
            HashMap<String, Policy> policies = domainStruct.getPolicies();
            for (Policy policy : policies.values()) {
                assertions = policy.getAssertions();
                if (assertions == null) {
                    continue;
                }
                for (Assertion assertion : assertions) {
                    if (assertionRoleName.compareToIgnoreCase(assertion.getRole()) == 0) {
                        list.add(policy.getName());
                        break;
                    }
                }
            }
        }
        Collections.sort(list);
        return list;
    }

    @Override
    public boolean insertAssertion(String domainName, String policyName, Assertion assertion) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "insertAssertion");
        }
        Policy policy = getPolicyObject(domainStruct, policyName);
        if (policy == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "policy not found", "insertAssertion");
        }
        List<Assertion> assertions = policy.getAssertions();
        if (assertions == null) {
            assertions = new ArrayList<>();
            policy.setAssertions(assertions);
        }
        assertions.add(assertion);
        assertion.setId(System.nanoTime());
        putDomainStruct(domainName, domainStruct);
        return true;
    }

    boolean assertionMatch(Assertion assertion1, Assertion assertion2) {

        if (!assertion1.getAction().equals(assertion2.getAction())) {
            return false;
        }
        if (!assertion1.getResource().equals(assertion2.getResource())) {
            return false;
        }
        if (!assertion1.getRole().equals(assertion2.getRole())) {
            return false;
        }
        AssertionEffect effect1 = AssertionEffect.ALLOW;
        if (assertion1.getEffect() != null) {
            effect1 = assertion1.getEffect();
        }
        AssertionEffect effect2 = AssertionEffect.ALLOW;
        if (assertion2.getEffect() != null) {
            effect2 = assertion2.getEffect();
        }
        return effect1 == effect2;
    }

    @Override
    public boolean deleteAssertion(String domainName, String policyName, Long assertionId) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "deleteAssertion");
        }
        Policy policy = getPolicyObject(domainStruct, policyName);
        if (policy == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "policy not found", "insertAssertion");
        }
        List<Assertion> assertions = policy.getAssertions();
        boolean deleted = false;
        for (int i = 0; i < assertions.size(); i++) {
            if (assertions.get(i).getId().equals(assertionId)) {
                assertions.remove(i);
                deleted = true;
                break;
            }
        }
        putDomainStruct(domainName, domainStruct);
        return deleted;
    }

    @Override
    public List<Assertion> listAssertions(String domainName, String policyName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "listAssertions");
        }
        Policy policy = getPolicyObject(domainStruct, policyName);
        if (policy == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "policy not found", "listAssertions");
        }
        return policy.getAssertions();
    }

    @Override
    public ServiceIdentity getServiceIdentity(String domainName, String serviceName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "getServiceIdentity");
        }
        return getServiceObject(domainStruct, serviceName);
    }

    @Override
    public boolean insertServiceIdentity(String domainName, ServiceIdentity service) {
        return updateServiceIdentity(domainName, service);
    }

    @Override
    public boolean updateServiceIdentity(String domainName, ServiceIdentity service) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "updateServiceIdentity");
        }
        
        if (domainStruct.getServices() == null) {
            domainStruct.setServices(new HashMap<>());
        }
        HashMap<String, ServiceIdentity> services = domainStruct.getServices();
        
        service.setModified(Timestamp.fromCurrentTime());
        String serviceName = extractServiceName(domainName, service.getName());

        // here we only need to update the main attrs and not
        // the public keys and hosts

        List<PublicKeyEntry> publicKeys = service.getPublicKeys();
        List<String> hosts = service.getHosts();
        ServiceIdentity originalService = getServiceObject(domainStruct, serviceName);
        if (originalService != null) {
            service.setPublicKeys(originalService.getPublicKeys());
            service.setHosts(originalService.getHosts());
        } else {
            service.setPublicKeys(null);
            service.setHosts(null);
        }
        service.setModified(Timestamp.fromCurrentTime());
        services.put(serviceName, service);
        putDomainStruct(domainName, domainStruct);
        service.setPublicKeys(publicKeys);
        service.setHosts(hosts);
        return true;
    }

    @Override
    public boolean deleteServiceIdentity(String domainName, String serviceName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "deleteServiceIdentity");
        }
        HashMap<String, ServiceIdentity> services = domainStruct.getServices();
        if (services != null) {
            services.remove(serviceName);
            putDomainStruct(domainName, domainStruct);
        }
        return true;
    }

    @Override
    public List<String> listServiceIdentities(String domainName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "listServiceIdentities");
        }
        HashMap<String, ServiceIdentity> services = domainStruct.getServices();
        ArrayList<String> list = new ArrayList<>();
        if (services != null) {
            list.addAll(services.keySet());
        }
        Collections.sort(list);
        return list;
    }

    @Override
    public boolean updateServiceIdentityModTimestamp(String domainName, String serviceName) {

        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "updateServiceIdentityModTimestamp");
        }
        ServiceIdentity service = getServiceObject(domainStruct, serviceName);
        service.setModified(Timestamp.fromCurrentTime());
        putDomainStruct(domainName, domainStruct);
        return true;
    }
    
    @Override
    public PublicKeyEntry getPublicKeyEntry(String domainName, String serviceName,
            String keyId, boolean domainStateCheck) {
        
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "getPublicKeyEntry");
        }
        if (domainStateCheck && domainStruct.getMeta().getEnabled() == Boolean.FALSE) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain disabled", "getPublicKeyEntry");
        }
        ServiceIdentity service = getServiceObject(domainStruct, serviceName);
        if (service == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "service not found", "getPublicKeyEntry");
        }
        List<PublicKeyEntry> publicKeys = service.getPublicKeys();
        if (publicKeys == null) {
            return null;
        }
        for (PublicKeyEntry keyEntry : publicKeys) {
            if (keyId.equals(keyEntry.getId())) {
                return keyEntry;
            }
        }
        return null;
    }

    @Override
    public boolean insertPublicKeyEntry(String domainName, String serviceName, PublicKeyEntry publicKey) {
        return updatePublicKeyEntry(domainName, serviceName, publicKey);
    }

    boolean removePublicKeyEntry(List<PublicKeyEntry> keyList, String keyId) {

        if (keyList == null) {
            return false;
        }

        for (int idx = 0; idx < keyList.size(); idx++) {
            if (keyId.equals(keyList.get(idx).getId())) {
                keyList.remove(idx);
                return true;
            }
        }

        return false;
    }

    void updatePublicKeyEntry(ServiceIdentity service, PublicKeyEntry keyEntry) {

        // first we are going to remove the key from our array
        // if one already exists. If the keyList is null, then
        // we're going to create and set an empty list so
        // later we can add the new key entry object to that list

        if (service.getPublicKeys() == null) {
            service.setPublicKeys(new ArrayList<>());
        }
        List<PublicKeyEntry> keyList = service.getPublicKeys();
        removePublicKeyEntry(keyList, keyEntry.getId());
        
        // now let's add our new key to the list

        keyList.add(keyEntry);
    }

    @Override
    public boolean updatePublicKeyEntry(String domainName, String serviceName, PublicKeyEntry publicKey) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "updatePublicKeyEntry");
        }
        ServiceIdentity service = getServiceObject(domainStruct, serviceName);
        if (service == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "service not found", "updatePublicKeyEntry");
        }
        updatePublicKeyEntry(service, publicKey);
        putDomainStruct(domainName, domainStruct);
        return true;
    }

    @Override
    public boolean deletePublicKeyEntry(String domainName, String serviceName, String keyId) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "deletePublicKeyEntry");
        }
        ServiceIdentity service = getServiceObject(domainStruct, serviceName);
        if (service == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "service not found", "deletePublicKeyEntry");
        }
        List<PublicKeyEntry> keyList = service.getPublicKeys();
        boolean keyRemoved = removePublicKeyEntry(keyList, keyId);
        if (!keyRemoved) {
            return false;
        }
        putDomainStruct(domainName, domainStruct);
        return true;
    }

    @Override
    public List<PublicKeyEntry> listPublicKeys(String domainName, String serviceName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "listPublicKeys");
        }
        ServiceIdentity service = getServiceObject(domainStruct, serviceName);
        if (service == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "service not found", "deletePublicKeyEntry");
        }
        return service.getPublicKeys();
    }

    @Override
    public List<String> listServiceHosts(String domainName, String serviceName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "listServiceHosts");
        }
        ServiceIdentity service = getServiceObject(domainStruct, serviceName);
        if (service == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "service not found", "deletePublicKeyEntry");
        }
        return service.getHosts();
    }

    @Override
    public boolean insertServiceHost(String domainName, String serviceName, String hostName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "insertServiceHost");
        }
        ServiceIdentity service = getServiceObject(domainStruct, serviceName);
        if (service == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "service not found", "insertServiceHost");
        }
        if (service.getHosts() == null) {
            service.setHosts(new ArrayList<>());
        }
        List<String> hosts = service.getHosts();
        hosts.add(hostName);
        putDomainStruct(domainName, domainStruct);
        return true;
    }

    @Override
    public boolean deleteServiceHost(String domainName, String serviceName, String hostName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "deleteServiceHost");
        }
        ServiceIdentity service = getServiceObject(domainStruct, serviceName);
        if (service == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "service not found", "deleteServiceHost");
        }
        List<String> hosts = service.getHosts();
        if (hosts == null) {
            return false;
        }
        hosts.remove(hostName);
        putDomainStruct(domainName, domainStruct);
        return true;
    }

    @Override
    public Entity getEntity(String domainName, String entityName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "getEntity");
        }
        return getEntityObject(domainStruct, entityName);
    }

    @Override
    public boolean insertEntity(String domainName, Entity entity) {
        return updateEntity(domainName, entity);
    }

    @Override
    public boolean updateEntity(String domainName, Entity entity) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "updateEntity");
        }
        if (domainStruct.getEntities() == null) {
            domainStruct.setEntities(new HashMap<>());
        }
        HashMap<String, Entity> entities = domainStruct.getEntities();
        entities.put(entity.getName(), entity);
        putDomainStruct(domainName, domainStruct);
        return true;
    }

    @Override
    public boolean deleteEntity(String domainName, String entityName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "deleteEntity");
        }
        HashMap<String, Entity> entities = domainStruct.getEntities();
        if (entities != null) {
            entities.remove(entityName);
            putDomainStruct(domainName, domainStruct);
        }
        return true;
    }

    public synchronized DomainStruct getDomainStruct(String name) {
        File f = new File(rootDir, name);
        if (!f.exists()) {
            return null;
        }
        DomainStruct domainStruct = null;
        try {
            Path path = Paths.get(f.toURI());
            domainStruct = JSON.fromBytes(Files.readAllBytes(path), DomainStruct.class);
        } catch (IOException ignored) {
        }
        return domainStruct;
    }

    public synchronized void putDomainStruct(String name, DomainStruct data) {
        
        File f = new File(rootDir, name);
        String policydata = JSON.string(data);
        try {
            FileWriter fileWriter = new FileWriter(f);
            fileWriter.write(policydata);
            fileWriter.flush();
            fileWriter.close();
        } catch (IOException ignored) {
        }
    }
    
    private static boolean delete(File f) {
        if (f.exists()) {
            if (f.isDirectory()) {

                File[] fileList = f.listFiles();
                if (fileList != null) {
                    for (File ff : fileList) {
                        delete(ff);
                    }
                }
            }
            if (!f.delete()) {
                throw new RuntimeException("Cannot delete file: " + f);
            }
            return true;
        }
        return false;
    }

    public static void deleteDirectory(File f) {
        delete(f);
    }

    public synchronized boolean delete(String name) {
        File f = new File(rootDir, name);
        return delete(f);
    }

    String extractObjectName(String domainName, String fullName, String objType) {

        // generate prefix to compare with

        final String prefix = domainName + objType;
        if (!fullName.startsWith(prefix)) {
            return null;
        }
        return fullName.substring(prefix.length());
    }

    String extractRoleName(String domainName, String fullRoleName) {
        return extractObjectName(domainName, fullRoleName, ":role.");
    }

    String extractPolicyName(String domainName, String fullPolicyName) {
        return extractObjectName(domainName, fullPolicyName, ":policy.");
    }

    String extractServiceName(String domainName, String fullServiceName) {
        return extractObjectName(domainName, fullServiceName, ".");
    }

    @Override
    public List<RoleAuditLog> listRoleAuditLogs(String domainName, String roleName) {
        return new ArrayList<>();
    }

    @Override
    public ResourceAccessList listResourceAccess(String principal, String action, String userDomain) {
        throw ZMSUtils.error(ResourceException.INTERNAL_SERVER_ERROR, "Not Implemented", "listResourceAccess");
    }

    @Override
    public Assertion getAssertion(String domainName, String policyName, Long assertionId) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "getAssertion");
        }
        Policy policy = getPolicyObject(domainStruct, policyName);
        if (policy == null) {
            return null;
        }
        List<Assertion> assertions = policy.getAssertions();
        if (assertions == null) {
            return null;
        }
        for (Assertion assertion : assertions) {
            if (assertion.getId().equals(assertionId)) {
                return assertion;
            }
        }
        return null;
    }

    @Override
    public boolean updatePolicyModTimestamp(String domainName, String policyName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "updatePolicyModTimestamp");
        }
        Policy policy = getPolicyObject(domainStruct, policyName);
        if (policy == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "policy not found", "updatePolicyModTimestamp");
        }
        policy.setModified(Timestamp.fromCurrentTime());
        putDomainStruct(domainName, domainStruct);
        return true;
    }

    @Override
    public Quota getQuota(String domainName) {
        File f = new File(quotaDir, domainName);
        if (!f.exists()) {
            return null;
        }
        Quota quota = null;
        try {
            Path path = Paths.get(f.toURI());
            quota = JSON.fromBytes(Files.readAllBytes(path), Quota.class);
        } catch (IOException ignored) {
        }
        return quota;
    }

    boolean putQuota(String domainName, Quota quota) {
        File f = new File(quotaDir, domainName);
        String quotaData = JSON.string(quota);
        try {
            FileWriter fileWriter = new FileWriter(f);
            fileWriter.write(quotaData);
            fileWriter.flush();
            fileWriter.close();
        } catch (IOException e) {
            return false;
        }
        return true;
    }
    
    @Override
    public boolean insertQuota(String domainName, Quota quota) {
        return putQuota(domainName, quota);
    }

    @Override
    public boolean updateQuota(String domainName, Quota quota) {
        return putQuota(domainName, quota);
    }

    @Override
    public boolean deleteQuota(String domainName) {
        File quotaFile = new File(quotaDir, domainName);
        return delete(quotaFile);
    }

    @Override
    public int countRoles(String domainName) {
        final List<String> list = listRoles(domainName);
        return list == null ? 0 : list.size();
    }

    @Override
    public int countRoleMembers(String domainName, String roleName) {
        final List<RoleMember> list = listRoleMembers(domainName, roleName);
        return list == null ? 0 : list.size();
    }

    @Override
    public int countPolicies(String domainName) {
        final List<String> list =  listPolicies(domainName, null);
        return list == null ? 0 : list.size();
    }

    @Override
    public int countAssertions(String domainName, String policyName) {
        final List<Assertion> list =  listAssertions(domainName, policyName);
        return list == null ? 0 : list.size();
    }

    @Override
    public int countServiceIdentities(String domainName) {
        final List<String> list =  listServiceIdentities(domainName);
        return list == null ? 0 : list.size();
    }

    @Override
    public int countPublicKeys(String domainName, String serviceName) {
        final List<PublicKeyEntry> list =  listPublicKeys(domainName, serviceName);
        return list == null ? 0 : list.size();
    }

    @Override
    public int countEntities(String domainName) {
        final List<String> list =  listEntities(domainName);
        return list == null ? 0 : list.size();
    }

    @Override
    public DomainRoleMembers listDomainRoleMembers(String domainName) {

        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "listDomainRoleMembers");
        }

        DomainRoleMembers domainRoleMembers = new DomainRoleMembers();
        domainRoleMembers.setDomainName(domainName);
        Map<String, DomainRoleMember> memberMap = new HashMap<>();

        for (Role role: domainStruct.getRoles().values()) {
            List<RoleMember> roleMembers = role.getRoleMembers();
            if (roleMembers == null) {
                continue;
            }
            for (RoleMember roleMember : roleMembers) {

                final String memberName = roleMember.getMemberName();
                DomainRoleMember domainRoleMember = memberMap.get(memberName);
                if (domainRoleMember == null) {
                    domainRoleMember = new DomainRoleMember();
                    domainRoleMember.setMemberName(memberName);
                    memberMap.put(memberName, domainRoleMember);
                }
                List<MemberRole> memberRoles = domainRoleMember.getMemberRoles();
                if (memberRoles == null) {
                    memberRoles = new ArrayList<>();
                    domainRoleMember.setMemberRoles(memberRoles);
                }
                MemberRole memberRole = new MemberRole();
                memberRole.setRoleName(role.getName());
                memberRole.setExpiration(roleMember.getExpiration());
                memberRoles.add(memberRole);
            }
        }

        if (!memberMap.isEmpty()) {
            domainRoleMembers.setMembers(new ArrayList<>(memberMap.values()));
        }
        return domainRoleMembers;
    }
}
