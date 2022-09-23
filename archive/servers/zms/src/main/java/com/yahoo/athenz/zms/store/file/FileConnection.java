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
package com.yahoo.athenz.zms.store.file;

import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zms.store.AthenzDomain;
import com.yahoo.athenz.zms.store.ObjectStoreConnection;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Timestamp;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

/**
 * FileConnection class is primarily implemented to run unit tests and
 * allow local development without using mysql or other implemented
 * storage solution. As such, it is not designed to be run in production
 * nor it may implement all functionality in an efficient matter.
 */

///CLOVER:OFF
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
                .setAzureSubscription(domainStruct.getMeta().getAzureSubscription())
                .setDescription(domainStruct.getMeta().getDescription())
                .setId(domainStruct.getId())
                .setModified(domainStruct.getModified())
                .setName(domainStruct.getName())
                .setOrg(domainStruct.getMeta().getOrg())
                .setYpmId(domainStruct.getMeta().getYpmId())
                .setApplicationId(domainStruct.getMeta().getApplicationId())
                .setCertDnsDomain(domainStruct.getMeta().getCertDnsDomain())
                .setMemberExpiryDays(domainStruct.getMeta().getMemberExpiryDays())
                .setServiceExpiryDays(domainStruct.getMeta().getServiceExpiryDays())
                .setGroupExpiryDays(domainStruct.getMeta().getGroupExpiryDays())
                .setTokenExpiryMins(domainStruct.getMeta().getTokenExpiryMins())
                .setServiceCertExpiryMins(domainStruct.getMeta().getServiceCertExpiryMins())
                .setRoleCertExpiryMins(domainStruct.getMeta().getRoleCertExpiryMins())
                .setSignAlgorithm(domainStruct.getMeta().getSignAlgorithm())
                .setUserAuthorityFilter(domainStruct.getMeta().getUserAuthorityFilter());
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
                .setAzureSubscription(domain.getAzureSubscription())
                .setAuditEnabled(domain.getAuditEnabled())
                .setDescription(domain.getDescription())
                .setEnabled(domain.getEnabled())
                .setOrg(domain.getOrg())
                .setYpmId(domain.getYpmId())
                .setApplicationId(domain.getApplicationId())
                .setCertDnsDomain(domain.getCertDnsDomain())
                .setMemberExpiryDays(domain.getMemberExpiryDays())
                .setServiceExpiryDays(domain.getServiceExpiryDays())
                .setTokenExpiryMins(domain.getTokenExpiryMins())
                .setServiceCertExpiryMins(domain.getServiceCertExpiryMins())
                .setRoleCertExpiryMins(domain.getRoleCertExpiryMins())
                .setSignAlgorithm(domain.getSignAlgorithm())
                .setUserAuthorityFilter(domain.getUserAuthorityFilter());
        domainStruct.setMeta(meta);
        
        putDomainStruct(domain.getName(), domainStruct);
        return true;
    }

    void verifyDomainProductIdUniqueness(String name, Integer productId, String caller) {

        if (productId == null || productId == 0) {
            return;
        }
        String domName = lookupDomainById(null, null, productId);
        if (domName != null && !domName.equals(name)) {
            throw ZMSUtils.requestError("Product Id: " + productId +
                    " is already assigned to domain: " + domName, caller);
        }
    }

    @Override
    public boolean updateDomain(Domain domain) {

        final String caller = "updateDomain";
        DomainStruct domainStruct = getDomainStruct(domain.getName());
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }

        verifyDomainProductIdUniqueness(domain.getName(), domain.getYpmId(), caller);

        domainStruct.setId(domain.getId());
        domainStruct.setName(domain.getName());
        domainStruct.setModified(Timestamp.fromCurrentTime());
        DomainMeta meta = new DomainMeta()
                .setAccount(domain.getAccount())
                .setAzureSubscription(domain.getAzureSubscription())
                .setAuditEnabled(domain.getAuditEnabled())
                .setDescription(domain.getDescription())
                .setEnabled(domain.getEnabled())
                .setOrg(domain.getOrg())
                .setYpmId(domain.getYpmId())
                .setApplicationId(domain.getApplicationId())
                .setCertDnsDomain(domain.getCertDnsDomain())
                .setMemberExpiryDays(domain.getMemberExpiryDays())
                .setServiceExpiryDays(domain.getServiceExpiryDays())
                .setTokenExpiryMins(domain.getTokenExpiryMins())
                .setServiceCertExpiryMins(domain.getServiceCertExpiryMins())
                .setRoleCertExpiryMins(domain.getRoleCertExpiryMins())
                .setSignAlgorithm(domain.getSignAlgorithm());
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
    public String lookupDomainById(String account, String subscription, int productId) {

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
            } else if (subscription != null) {
                if (domain.getAzureSubscription() != null && subscription.equals(domain.getAzureSubscription())) {
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
    public DomainMetaList listModifiedDomains(long modifiedSince) {

        DomainMetaList domainModifiedList = new DomainMetaList();
        List<Domain> nameMods = new ArrayList<>();

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
            nameMods.add(getDomain(domainStruct));
        }

        domainModifiedList.setDomains(nameMods);
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
    public boolean updateDomainTemplate(String domainName, String templateName, TemplateMetaData templateMetaData) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "updateDomainTemplate");
        }
        if (domainStruct.getTemplates() == null) {
            domainStruct.setTemplates(new ArrayList<>());
        }
        ArrayList<String> templates = domainStruct.getTemplates();
        if (!templates.contains(templateName)) {
            templates.add(templateName);
        }

        if (domainStruct.getTemplateMeta() == null) {
            domainStruct.setTemplateMeta(new ArrayList<>());
        }

        TemplateMetaData domainTemplate = null;
        ArrayList<TemplateMetaData> templateMetaList = domainStruct.getTemplateMeta();

        for (TemplateMetaData meta : templateMetaList) {
            if (meta.getTemplateName().equals(templateName)) {
                domainTemplate = meta;
                break;
            }
        }

        if (domainTemplate == null) {
            domainTemplate = new TemplateMetaData();
            domainTemplate.setTemplateName(templateName);
            domainTemplate.setCurrentVersion(templateMetaData.getLatestVersion());
            templateMetaList.add(domainTemplate);
        } else {
            domainTemplate.setCurrentVersion(templateMetaData.getLatestVersion());
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
    public Map<String, List<String>> getDomainFromTemplateName(Map<String, Integer> templateNameAndLatestVersion) {

        //Input - templateNameAndLatestVersion (templateName|latestVersion) from template Meta Data
        //Output - for a given domain if domainstruct.templateMeta list has the template name and if the currentVersion is <= latestVersion..
        //...return map of domain-> List of templatenames

        Map<String, List<String>> domainNameTemplateListMap = new HashMap<>();
        List<String> domainNames = listDomains(null, 0);
        for (String domainName : domainNames) {
            DomainStruct domainStruct = getDomainStruct(domainName);
            if (domainStruct == null) {
                throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "getDomainFromTemplateName");
            }
            ArrayList<TemplateMetaData> templateMetaList = domainStruct.getTemplateMeta();

            if (templateMetaList != null) {
                for (TemplateMetaData meta : templateMetaList) {
                    for (String templateName : templateNameAndLatestVersion.keySet()) {
                        if (meta.getTemplateName().equals(templateName) && meta.getCurrentVersion() < templateNameAndLatestVersion.get(templateName)) {
                            if (domainNameTemplateListMap.get(domainName) != null) {
                                List<String> tempTemplateList = domainNameTemplateListMap.get(domainName);
                                tempTemplateList.add(meta.getTemplateName());
                            } else {
                                List<String> templateList = new ArrayList<>();
                                templateList.add(meta.getTemplateName());
                                domainNameTemplateListMap.put(domainName, templateList);
                            }
                        }
                    }
                }
            }
        }

        return domainNameTemplateListMap;
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
                    pRole.setRoleName(ZMSUtils.extractRoleName(domainName, role.getName()));
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

    Role getRoleObject(DomainStruct domain, String roleName, Boolean pending) {

        Role role = getRoleObject(domain, roleName);
        if (pending == Boolean.FALSE) {
            if (role != null && role.getRoleMembers() != null && !role.getRoleMembers().isEmpty()) {
                Iterator<RoleMember> roleit = role.getRoleMembers().iterator();
                RoleMember rm;
                while (roleit.hasNext()) {
                    rm = roleit.next();
                    if (rm != null && rm.getApproved() == Boolean.FALSE) {
                        roleit.remove();
                    }
                }
            }
        }
        return role;
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

        final String caller = "updateRole";
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }
        if (domainStruct.getRoles() == null) {
            domainStruct.setRoles(new HashMap<>());
        }
        HashMap<String, Role> roles = domainStruct.getRoles();

        String roleName = ZMSUtils.extractRoleName(domainName, role.getName());
        if (roleName == null) {
            throw ZMSUtils.error(ResourceException.BAD_REQUEST, "invalid role name", caller);
        }
        
        // here we only need to update the main attrs and not
        // the members

        Role originalRole = getRoleObject(domainStruct, roleName);
        List<RoleMember> members = role.getRoleMembers();
        if (originalRole != null) {
            role.setRoleMembers(originalRole.getRoleMembers());
            role.setAuditEnabled(role.getAuditEnabled());
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
    public List<RoleMember> listRoleMembers(String domainName, String roleName, Boolean pending) {

        final String caller = "listRoleMembers";
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }
        Role role = getRoleObject(domainStruct, roleName, pending);
        if (role == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "role not found", caller);
        }
        return role.getRoleMembers();
    }

    boolean matchExpiration(long expiration, Timestamp expiry) {
        if (expiration == 0) {
            return true;
        }
        if (expiry == null) {
            return false;
        }
        return expiry.millis() == expiration;
    }

    @Override
    public Membership getRoleMember(String domainName, String roleName, String principal,
            long expiration, boolean pending) {

        final String caller = "getRoleMember";
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }
        Role role = getRoleObject(domainStruct, roleName);
        if (role == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "role not found", caller);
        }
        Membership membership = new Membership()
                .setMemberName(principal)
                .setRoleName(ZMSUtils.roleResourceName(domainName, roleName))
                .setIsMember(false);
        if (role.getRoleMembers() != null) {
            Set<RoleMember> members = new HashSet<>(role.getRoleMembers());
            for (RoleMember member : members) {
                if (member.getMemberName().equalsIgnoreCase(principal)) {
                    if (pending && member.getApproved() != Boolean.FALSE) {
                        continue;
                    }
                    Timestamp expiry = member.getExpiration();
                    if (matchExpiration(expiration, expiry)) {
                        membership.setIsMember(true);
                        membership.setExpiration(expiry);
                        membership.setApproved(member.getApproved());
                        membership.setRequestPrincipal(member.getRequestPrincipal());
                        break;
                    }
                }
            }
        }
        return membership;
    }

    @Override
    public boolean insertRoleMember(String domainName, String roleName, RoleMember member,
            String admin, String auditRef) {

        final String caller = "insertRoleMember";
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }
        Role role = getRoleObject(domainStruct, roleName);
        if (role == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "role not found", caller);
        }
        if (!validatePrincipalDomain(member.getMemberName())) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "principal domain not found", caller);
        }
        // make sure our existing role as the member array
        // and if it doesn't exist then create one
        if (role.getRoleMembers() == null) {
            role.setRoleMembers(new ArrayList<>());
        }
        // need to check if the member already exists
        boolean entryUpdated = false;
        for (RoleMember roleMember : role.getRoleMembers()) {
            if (roleMember.getMemberName().equals(member.getMemberName()) && roleMember.getApproved() == member.getApproved()) {
                roleMember.setExpiration(member.getExpiration());
                roleMember.setRequestPrincipal(admin);
                entryUpdated = true;
            }
        }
        if (!entryUpdated) {
            member.setRequestPrincipal(admin);
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
    public boolean updateRoleMemberDisabledState(String domainName, String roleName, String principal,
            String admin, int disabledState, String auditRef) {

        final String caller = "updateRoleMemberDisabledState";
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }
        Role role = getRoleObject(domainStruct, roleName);
        if (role == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "role not found", caller);
        }
        List<RoleMember> roleMembers = role.getRoleMembers();
        if (roleMembers != null) {
            for (int idx = 0; idx < roleMembers.size(); idx++) {
                RoleMember roleMember = roleMembers.get(idx);
                if (roleMember.getMemberName().equalsIgnoreCase(principal)) {
                    roleMember.setSystemDisabled(disabledState);
                    break;
                }
            }
        }
        putDomainStruct(domainName, domainStruct);
        return true;
    }

    @Override
    public boolean deleteRoleMember(String domainName, String roleName, String principal,
            String admin, String auditRef) {

        final String caller = "deleteRoleMember";
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }
        Role role = getRoleObject(domainStruct, roleName);
        if (role == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "role not found", caller);
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
        
        String policyName = ZMSUtils.extractPolicyName(domainName, policy.getName());

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

        final String caller = "insertAssertion";
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }
        Policy policy = getPolicyObject(domainStruct, policyName);
        if (policy == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "policy not found", caller);
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

        final String caller = "deleteAssertion";
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }
        Policy policy = getPolicyObject(domainStruct, policyName);
        if (policy == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "policy not found", caller);
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

        final String caller = "listAssertions";
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }
        Policy policy = getPolicyObject(domainStruct, policyName);
        if (policy == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "policy not found", caller);
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
        String serviceName = ZMSUtils.extractServiceName(domainName, service.getName());

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

        final String caller = "getPublicKeyEntry";
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }
        if (domainStateCheck && domainStruct.getMeta().getEnabled() == Boolean.FALSE) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain disabled", caller);
        }
        ServiceIdentity service = getServiceObject(domainStruct, serviceName);
        if (service == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "service not found", caller);
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

        final String caller = "updatePublicKeyEntry";
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }
        ServiceIdentity service = getServiceObject(domainStruct, serviceName);
        if (service == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "service not found", caller);
        }
        updatePublicKeyEntry(service, publicKey);
        putDomainStruct(domainName, domainStruct);
        return true;
    }

    @Override
    public boolean deletePublicKeyEntry(String domainName, String serviceName, String keyId) {

        final String caller = "deletePublicKeyEntry";
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }
        ServiceIdentity service = getServiceObject(domainStruct, serviceName);
        if (service == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "service not found", caller);
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

        final String caller = "listPublicKeys";
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }
        ServiceIdentity service = getServiceObject(domainStruct, serviceName);
        if (service == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "service not found", caller);
        }
        return service.getPublicKeys();
    }

    @Override
    public List<String> listServiceHosts(String domainName, String serviceName) {

        final String caller = "listServiceHosts";
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }
        ServiceIdentity service = getServiceObject(domainStruct, serviceName);
        if (service == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "service not found", caller);
        }
        return service.getHosts();
    }

    @Override
    public boolean insertServiceHost(String domainName, String serviceName, String hostName) {

        final String caller = "insertServiceHost";
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }
        ServiceIdentity service = getServiceObject(domainStruct, serviceName);
        if (service == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "service not found", caller);
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

        final String caller = "deleteServiceHost";
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }
        ServiceIdentity service = getServiceObject(domainStruct, serviceName);
        if (service == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "service not found", caller);
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

        final String caller = "updatePolicyModTimestamp";
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }
        Policy policy = getPolicyObject(domainStruct, policyName);
        if (policy == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "policy not found", caller);
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
        final List<RoleMember> list = listRoleMembers(domainName, roleName, false);
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
        return listReviewRoleMembersWithFilter(domainName, (roleMember -> true), "listDomainRoleMembers");
    }

    @Override
    public DomainRoleMember getPrincipalRoles(String principal, String domainName) {
        DomainRoleMember domainRoleMember = new DomainRoleMember();
        domainRoleMember.setMemberName(principal);
        domainRoleMember.setMemberRoles(new ArrayList<>());

        if (!StringUtil.isEmpty(domainName)) {
            getDomainRolesForPrincipal(principal, domainRoleMember, domainName);
        } else {
            String[] fnames = getDomainList();
            for (String domain : fnames) {
                getDomainRolesForPrincipal(principal, domainRoleMember, domain);
            }
        }

        return domainRoleMember;
    }

    private void getDomainRolesForPrincipal(String principal, DomainRoleMember domainRoleMember, String domain) {
        DomainStruct dom = getDomainStruct(domain);
        if (dom == null) {
            return;
        }

        for (Role role: dom.getRoles().values()) {
            List<RoleMember> roleMembers = role.getRoleMembers();
            if (roleMembers == null) {
                continue;
            }
            for (RoleMember roleMember : roleMembers) {
                if (!roleMember.getMemberName().equals(principal)) {
                    continue;
                }

                MemberRole memberRole = new MemberRole();
                memberRole.setMemberName(principal);
                memberRole.setDomainName(domain);
                memberRole.setReviewReminder(roleMember.getReviewReminder());
                memberRole.setExpiration(roleMember.getExpiration());
                memberRole.setRoleName(role.getName());
                memberRole.setSystemDisabled(roleMember.getSystemDisabled());
                domainRoleMember.getMemberRoles().add(memberRole);
            }
        }
    }

    @Override
    public DomainRoleMembers listOverdueReviewRoleMembers(String domainName) {
        return listReviewRoleMembersWithFilter(domainName, (roleMember -> {
            if (roleMember.getReviewReminder() == null) {
                return false;
            }

            long reviewMillis = roleMember.getReviewReminder().millis();
            return reviewMillis - System.currentTimeMillis() < 0;
        }), "listOverdueReviewRoleMembers");
    }

    @Override
    public Map<String, List<DomainGroupMember>> getPendingDomainGroupMembers(String principal) {
        return null;
    }

    @Override
    public Map<String, List<DomainGroupMember>> getExpiredPendingDomainGroupMembers(int pendingRoleMemberLifespan) {
        return null;
    }

    @Override
    public Set<String> getPendingGroupMembershipApproverRoles(String server, long timestamp) {
        return null;
    }

    @Override
    public boolean updatePendingGroupMembersNotificationTimestamp(String server, long timestamp, int delayDays) {
        return false;
    }

    @Override
    public Map<String, DomainGroupMember> getNotifyTemporaryGroupMembers(String server, long timestamp) {
        return null;
    }

    @Override
    public boolean updateGroupMemberExpirationNotificationTimestamp(String server, long timestamp, int delayDays) {
        return false;
    }

    private DomainRoleMembers listReviewRoleMembersWithFilter(String domainName, Function<RoleMember, Boolean> filterFunc, String caller) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
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
                if (filterFunc.apply(roleMember)) {
                    addRoleMemberToMap(memberMap, roleMember, domainName, role.getName());
                }
            }
        }

        if (!memberMap.isEmpty()) {
            domainRoleMembers.setMembers(new ArrayList<>(memberMap.values()));
        }
        return domainRoleMembers;
    }


    @Override
    public boolean confirmRoleMember(String domainName, String roleName, RoleMember member,
                                    String admin, String auditRef) {

        final String caller = "confirmRoleMember";
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }
        Role role = getRoleObject(domainStruct, roleName);
        if (role == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "role not found", caller);
        }

        if (role.getRoleMembers() != null && !role.getRoleMembers().isEmpty()) {
            // need to check if the member already exists

            Iterator<RoleMember> rmIter = role.getRoleMembers().iterator();
            RoleMember roleMember;
            while (rmIter.hasNext()) {
                roleMember = rmIter.next();
                // check whether the member exists and is in inactive state
                if (roleMember.getMemberName().equals(member.getMemberName()) && roleMember.getApproved() == Boolean.FALSE) {
                    //if membership is approved, set rolemember to active
                    if (member.getApproved() == Boolean.TRUE) {
                        roleMember.setExpiration(member.getExpiration());
                        roleMember.setApproved(true);
                    } else {
                        // if membership is not approved, delete the role member from the role
                        rmIter.remove();
                    }
                }
            }
            putDomainStruct(domainName, domainStruct);
            return true;
        }
        return false;
    }

    boolean containsRoleMember(List<RoleMember> rolesMembers, String principal) {
        for (RoleMember rm : rolesMembers) {
            if (principal.equals(rm.getMemberName())) {
                return true;
            }
        }
        return false;
    }

    @Override
    public Map<String, List<DomainRoleMember>> getPendingDomainRoleMembers(String principal) {

        List<String> orgs = new ArrayList<>();
        Map<String, List<DomainRoleMember>> domainRoleMembersMap = new HashMap<>();

        DomainStruct auditDom = getDomainStruct(ZMSConsts.SYS_AUTH_AUDIT_BY_ORG);
        if (auditDom != null && auditDom.getRoles() != null && !auditDom.getRoles().isEmpty()) {
            for (Role role : auditDom.getRoles().values()) {
                if (containsRoleMember(role.getRoleMembers(), principal)) {
                    orgs.add(AthenzUtils.extractRoleName(role.getName()));
                }
            }
        }
        if (!orgs.isEmpty()) {
            domainRoleMembersMap = new HashMap<>();
            List<String> domainNames = listDomains(null, 0);
            for (String domainName : domainNames) {
                DomainStruct domain = getDomainStruct(domainName);
                if (domain == null) {
                    continue;
                }
                if (domain.getMeta() != null && orgs.contains(domain.getMeta().getOrg())) {
                    DomainRoleMembers domainRoleMembers = new DomainRoleMembers();
                    domainRoleMembers.setDomainName(domain.getName());
                    List<DomainRoleMember>  domainRoleMemberList = new ArrayList<>();
                    domainRoleMembers.setMembers(domainRoleMemberList);
                    for (Role role : domain.getRoles().values()) {
                        for (RoleMember roleMember : role.getRoleMembers()) {
                            if (roleMember.getApproved() == Boolean.FALSE) {
                                DomainRoleMember domainRoleMember = new DomainRoleMember();
                                domainRoleMember.setMemberName(roleMember.getMemberName());
                                List<MemberRole> memberRoles = new ArrayList<>();
                                MemberRole memberRole = new MemberRole();
                                memberRole.setActive(false);
                                memberRole.setRoleName(AthenzUtils.extractRoleName(role.getName()));
                                memberRole.setExpiration(roleMember.getExpiration());
                                memberRoles.add(memberRole);
                                domainRoleMember.setMemberRoles(memberRoles);
                                domainRoleMemberList.add(domainRoleMember);
                            }
                        }
                    }
                    if (!domainRoleMemberList.isEmpty()) {
                        domainRoleMembersMap.put(domain.getName(), domainRoleMemberList);
                    }
                }
            }
        }
        return domainRoleMembersMap;
    }

    @Override
    public Set<String> getPendingMembershipApproverRoles(String server, long timestamp) {

        String[] fnames = getDomainList();
        Set<String> roleNames = new HashSet<>();
        for (String name : fnames) {
            getPendingMembershipApproverRolesForDomain(name, roleNames);
        }
        return roleNames;
    }

    void getPendingMembershipApproverRolesForDomain(String domain, Set<String> roleNames) {

        DomainStruct dom = getDomainStruct(domain);
        if (dom == null) {
            return;
        }

        DomainStruct auditDomByOrg = getDomainStruct(ZMSConsts.SYS_AUTH_AUDIT_BY_ORG);
        DomainStruct auditDomByDomain = getDomainStruct(ZMSConsts.SYS_AUTH_AUDIT_BY_DOMAIN);

        for (Role role : dom.getRoles().values()) {
            if (role.getAuditEnabled() == Boolean.TRUE) {
                for (RoleMember roleMember : role.getRoleMembers()) {
                    if (roleMember.getApproved() == Boolean.FALSE) {
                        for (Role auditRole : auditDomByOrg.getRoles().values()) {
                            if (auditRole.getName().equals(ZMSConsts.SYS_AUTH_AUDIT_BY_ORG + AuthorityConsts.ROLE_SEP + dom.getMeta().getOrg())) {
                                roleNames.add(auditRole.getName());
                                break;
                            }
                        }
                        for (Role auditRole : auditDomByDomain.getRoles().values()) {
                            if (auditRole.getName().equals(ZMSConsts.SYS_AUTH_AUDIT_BY_DOMAIN + AuthorityConsts.ROLE_SEP + dom.getName())) {
                                roleNames.add(auditRole.getName());
                                break;
                            }
                        }
                    }
                }
            } else if (role.getSelfServe() == Boolean.TRUE) {
                for (RoleMember roleMember : role.getRoleMembers()) {
                    if (roleMember.getApproved() == Boolean.FALSE) {
                        roleNames.add(dom.getName() + ":role.admin");
                    }
                }
            }
        }
    }

    @Override
    public Map<String, List<DomainRoleMember>> getExpiredPendingDomainRoleMembers(int pendingRoleMemberLifespan) {

        Map<String, List<DomainRoleMember>> domainRoleMembersMap = new HashMap<>();;

        String[] fnames = getDomainList();
        for (String name : fnames) {
            DomainStruct domain = getDomainStruct(name);
            if (domain == null) {
                continue;
            }
            DomainRoleMembers domainRoleMembers = new DomainRoleMembers();
            domainRoleMembers.setDomainName(domain.getName());
            List<DomainRoleMember> domainRoleMemberList = new ArrayList<>();
            domainRoleMembers.setMembers(domainRoleMemberList);
            long now = System.currentTimeMillis();
            for (Role role : domain.getRoles().values()) {
                for (RoleMember roleMember : role.getRoleMembers()) {
                    if (roleMember.getApproved() == Boolean.FALSE &&
                            now - roleMember.getRequestTime().millis() > TimeUnit.MILLISECONDS.convert(pendingRoleMemberLifespan, TimeUnit.DAYS)) {
                        DomainRoleMember domainRoleMember = new DomainRoleMember();
                        domainRoleMember.setMemberName(roleMember.getMemberName());
                        List<MemberRole> memberRoles = new ArrayList<>();
                        MemberRole memberRole = new MemberRole();
                        memberRole.setActive(false);
                        memberRole.setRoleName(AthenzUtils.extractRoleName(role.getName()));
                        memberRole.setExpiration(roleMember.getExpiration());
                        memberRole.setRequestTime(roleMember.getRequestTime());
                        memberRole.setRequestPrincipal(roleMember.getRequestPrincipal());
                        memberRoles.add(memberRole);
                        domainRoleMember.setMemberRoles(memberRoles);
                        domainRoleMemberList.add(domainRoleMember);
                    }
                }
            }
            if (!domainRoleMemberList.isEmpty()) {
                domainRoleMembersMap.put(domain.getName(), domainRoleMemberList);
            }
        }
        return domainRoleMembersMap;
    }

    @Override
    public boolean updatePendingRoleMembersNotificationTimestamp(String server, long timestamp, int delayDays) {
        String[] fnames = getDomainList();
        boolean updated = false;
        for (String name : fnames) {
            DomainStruct dom = getDomainStruct(name);
            boolean domainChanged = false;
            if (dom == null) {
                continue;
            }
            for (Role role : dom.getRoles().values()) {
                for (RoleMember roleMember : role.getRoleMembers()) {
                    if (roleMember.getApproved() == Boolean.FALSE) {
                        roleMember.setLastNotifiedTime(Timestamp.fromCurrentTime());
                        updated = true;
                        domainChanged = true;
                    }
                }
            }
            if (domainChanged) {
                putDomainStruct(name, dom);
            }
        }
        return updated;
    }

    @Override
    public boolean deletePendingRoleMember(String domainName, String roleName, String principal,
             String admin, String auditRef) {

        final String caller = "deletePendingRoleMember";
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", caller);
        }
        Role role = getRoleObject(domainStruct, roleName);
        if (role == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "role not found", caller);
        }
        List<RoleMember> roleMembers = role.getRoleMembers();
        boolean memberDeleted = false;
        if (roleMembers != null) {
            for (int idx = 0; idx < roleMembers.size(); idx++) {
                RoleMember roleMember = roleMembers.get(idx);
                if (roleMember.getApproved() == Boolean.FALSE && roleMember.getMemberName().equalsIgnoreCase(principal)) {
                    roleMembers.remove(idx);
                    memberDeleted = true;
                    break;
                }
            }
        }
        putDomainStruct(domainName, domainStruct);
        return memberDeleted;
    }

    @Override
    public Map<String, DomainRoleMember> getNotifyTemporaryRoleMembers(String server, long timestamp) {
        return getNotifyRoleMembers(server, timestamp, true);
    }

    @Override
    public Map<String, DomainRoleMember> getNotifyReviewRoleMembers(String server, long timestamp) {
        return getNotifyRoleMembers(server, timestamp, false);
    }

    private Map<String, DomainRoleMember> getNotifyRoleMembers(String server, long timestamp, boolean isTemporaryRole) {
        Map<String, DomainRoleMember> memberMap = new HashMap<>();

        String[] fnames = getDomainList();
        for (String name : fnames) {
            DomainStruct dom = getDomainStruct(name);
            if (dom == null) {
                continue;
            }

            for (Role role: dom.getRoles().values()) {
                List<RoleMember> roleMembers = role.getRoleMembers();
                if (roleMembers == null) {
                    continue;
                }
                for (RoleMember roleMember : roleMembers) {
                    Timestamp lastNotifiedTime = isTemporaryRole ?
                            roleMember.getLastNotifiedTime() : roleMember.getReviewLastNotifiedTime();
                    if (roleMember.getApproved() == Boolean.FALSE || lastNotifiedTime == null ||
                            lastNotifiedTime.millis() != timestamp) {
                        continue;
                    }

                    addRoleMemberToMap(memberMap, roleMember, name, role.getName());
                }
            }
        }

        return memberMap;
    }

    void addRoleMemberToMap(Map<String, DomainRoleMember> memberMap, RoleMember roleMember, final String domainName,
            final String roleName) {

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
        memberRole.setMemberName(memberName);
        memberRole.setRoleName(roleName);
        memberRole.setDomainName(domainName);
        memberRole.setExpiration(roleMember.getExpiration());
        memberRoles.add(memberRole);
    }

    @Override
    public boolean updateRoleMemberExpirationNotificationTimestamp(String server, long timestamp, int delayDays) {
        return updateRoleMemberNotificationTimestamp(timestamp, true);
    }

    @Override
    public boolean updateRoleMemberReviewNotificationTimestamp(String server, long timestamp, int delayDays) {
        return updateRoleMemberNotificationTimestamp(timestamp, false);
    }

    private boolean updateRoleMemberNotificationTimestamp(long timestamp, boolean isTemporaryRole) {
        String[] fnames = getDomainList();
        boolean updated = false;
        for (String name : fnames) {
            DomainStruct dom = getDomainStruct(name);
            boolean domainChanged = false;
            if (dom == null) {
                continue;
            }
            for (Role role : dom.getRoles().values()) {
                for (RoleMember roleMember : role.getRoleMembers()) {
                    Timestamp dateChecked = isTemporaryRole ?
                            roleMember.getExpiration() : roleMember.getReviewReminder();
                    if (roleMember.getApproved() == Boolean.FALSE || dateChecked == null) {
                        continue;
                    }
                    long diffMillis = dateChecked.millis() - System.currentTimeMillis();
                    if (diffMillis < 0) {
                        continue;
                    }
                    long diffDays = TimeUnit.DAYS.convert(diffMillis, TimeUnit.MILLISECONDS);
                    if (diffDays < 29 && (diffDays == 1 || diffDays % 7 == 0)) {
                        if (isTemporaryRole) {
                            roleMember.setLastNotifiedTime(Timestamp.fromMillis(timestamp));
                        } else {
                            roleMember.setReviewLastNotifiedTime(Timestamp.fromMillis(timestamp));
                        }
                        domainChanged = true;
                        updated = true;
                    }
                }
            }
            if (domainChanged) {
                putDomainStruct(name, dom);
            }
        }
        return updated;
    }

    @Override
    public List<TemplateMetaData> getDomainTemplates(String domainName) {
        TemplateMetaData templateDomainMapping;
        List<TemplateMetaData> templateDomainMappingList = new ArrayList<>();
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "getDomainTemplates");
        }

        List<TemplateMetaData> metaDataList = domainStruct.getTemplateMeta();
        if (metaDataList != null) {
            templateDomainMapping = new TemplateMetaData();
            for (TemplateMetaData meta :metaDataList) {
                templateDomainMapping.setTemplateName(meta.getTemplateName());
                templateDomainMapping.setCurrentVersion(meta.getCurrentVersion());
                templateDomainMappingList.add(templateDomainMapping);
            }
        }
        return templateDomainMappingList;
    }

    @Override
    public boolean updateRoleReviewTimestamp(String domainName, String roleName) {
        DomainStruct domainStruct = getDomainStruct(domainName);
        if (domainStruct == null) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, "domain not found", "updateRoleReviewTimestamp");
        }
        Role role = getRoleObject(domainStruct, roleName);
        role.setLastReviewedDate(Timestamp.fromCurrentTime());
        role.setModified(Timestamp.fromCurrentTime());
        putDomainStruct(domainName, domainStruct);
        return true;
    }

    @Override
    public List<PrincipalRole> listRolesWithUserAuthorityRestrictions() {

        List<PrincipalRole> roles = new ArrayList<>();
        List<String> domainNames = listDomains(null, 0);
        for (String domainName : domainNames) {
            DomainStruct domain = getDomainStruct(domainName);
            if (domain == null) {
                continue;
            }
            final String domainUserAuthorityFilter = domain.getMeta().getUserAuthorityFilter();
            for (Role role : domain.getRoles().values()) {
                if (domainUserAuthorityFilter != null || role.getUserAuthorityExpiration() != null ||
                        role.getUserAuthorityFilter() != null) {
                    PrincipalRole prRole = new PrincipalRole();
                    prRole.setDomainName(domainName);
                    prRole.setRoleName(role.getName());
                    prRole.setDomainUserAuthorityFilter(domainUserAuthorityFilter);
                    roles.add(prRole);
                }
            }
        }
        return roles;
    }

    @Override
    public Group getGroup(String domainName, String groupName) {
        return null;
    }

    @Override
    public boolean insertGroup(String domainName, Group group) {
        return false;
    }

    @Override
    public boolean updateGroup(String domainName, Group group) {
        return false;
    }

    @Override
    public boolean deleteGroup(String domainName, String groupName) {
        return false;
    }

    @Override
    public boolean updateGroupModTimestamp(String domainName, String groupName) {
        return false;
    }

    @Override
    public int countGroups(String domainName) {
        return 0;
    }

    @Override
    public List<GroupAuditLog> listGroupAuditLogs(String domainName, String groupName) {
        return null;
    }

    @Override
    public boolean updateGroupReviewTimestamp(String domainName, String groupName) {
        return false;
    }

    @Override
    public List<GroupMember> listGroupMembers(String domainName, String groupName, Boolean pending) {
        return null;
    }

    @Override
    public int countGroupMembers(String domainName, String groupName) {
        return 0;
    }

    @Override
    public GroupMembership getGroupMember(String domainName, String groupName, String member, long expiration, boolean pending) {
        return null;
    }

    @Override
    public boolean insertGroupMember(String domainName, String groupName, GroupMember groupMember, String principal, String auditRef) {
        return false;
    }

    @Override
    public boolean deleteGroupMember(String domainName, String groupName, String member, String principal, String auditRef) {
        return false;
    }

    @Override
    public boolean updateGroupMemberDisabledState(String domainName, String groupName, String member, String principal, int disabledState, String auditRef) {
        return false;
    }

    @Override
    public boolean deletePendingGroupMember(String domainName, String groupName, String member, String principal, String auditRef) {
        return false;
    }

    @Override
    public boolean confirmGroupMember(String domainName, String groupName, GroupMember groupMember, String principal, String auditRef) {
        return false;
    }

    @Override
    public DomainGroupMember getPrincipalGroups(String principal, String domainName) {
        return null;
    }

    @Override
    public List<PrincipalGroup> listGroupsWithUserAuthorityRestrictions() {
        return null;
    }

    @Override
    public boolean updatePrincipal(String principal, int newState) {
        return false;
    }

    @Override
    public List<String> getPrincipals(int queriedState) {
        return Collections.emptyList();
    }
}
///CLOVER:ON
