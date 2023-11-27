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
import Fetchr from 'fetchr';
import 'setimmediate';
import NameUtils from './components/utils/NameUtils';
import DateUtils from './components/utils/DateUtils';
import {
    SERVICE_TYPE_STATIC,
    SERVICE_TYPE_STATIC_LABEL,
} from './components/constants/constants';

const Api = (req) => {
    let localDate = new DateUtils();
    const fetchr = new Fetchr({
        xhrPath: '/api/v1',
        xhrTimeout: 30000,
        req,
    });
    return {
        toJSON() {
            // When this object gets shipped from server to browser, don't send along
            // anything meaningful. (Components in browser will recreate.)
            return undefined;
        },

        listUserDomains(roleName) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('domain-list')
                    .params({ roleName })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        listAllDomains() {
            return new Promise((resolve, reject) => {
                fetchr.read('all-domain-list').end((err, data) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(data);
                    }
                });
            });
        },

        listAdminDomains(roleName) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('admin-domains')
                    .params({ roleName })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getDomain(domain) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('domain')
                    .params({ domain })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        createSubDomain(parent, subDomain, adminUser, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                const detail = {
                    parent,
                    name: subDomain,
                    adminUsers: [adminUser],
                };
                fetchr
                    .create('domain')
                    .params({ parent, detail })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        createUserDomain(name, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                const params = {
                    name,
                    detail: {
                        name,
                        templates: {},
                    },
                };
                fetchr
                    .create('domain')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getRoleMembers(domainName) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('role-members')
                    .params({ domainName })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data || []);
                        }
                    });
            });
        },

        getServiceDependencies(domainName) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('dependencies')
                    .params({ domainName })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            if (data) {
                                resolve(data && data.serviceAndResourceGroups);
                            } else {
                                resolve([]);
                            }
                        }
                    });
            });
        },

        getAuthHistory(domainName) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('auth-history')
                    .params({ domainName })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            if (data) {
                                resolve(data);
                            } else {
                                resolve([]);
                            }
                        }
                    });
            });
        },

        listRoles(domainName) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('role-list')
                    .params({ domainName })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve((data && data.names) || []);
                        }
                    });
            });
        },

        getRoles(domainName, members) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('roles')
                    .params({ domainName, members })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            if (data && data.list) {
                                resolve(data.list);
                            } else {
                                resolve([]);
                            }
                        }
                    });
            });
        },

        getGroups(domainName, members) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('groups')
                    .params({ domainName, members })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            if (data && data.list) {
                                resolve(data.list);
                            } else {
                                resolve([]);
                            }
                        }
                    });
            });
        },

        getServiceHost(domain, service) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('get-service-host')
                    .params({ domain, service })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            if (data) {
                                resolve(data);
                            } else {
                                resolve([]);
                            }
                        }
                    });
            });
        },

        reloadGroups(domainName, groupName) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('groups')
                    .params({ domainName, groupName })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            if (data && data.list) {
                                resolve(data.list);
                            } else {
                                resolve([]);
                            }
                        }
                    });
            });
        },

        listGroups(domainName) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('groups-list')
                    .params({ domainName })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getRole(
            domainName,
            roleName,
            auditLog = false,
            expand = true,
            pending = false
        ) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('role')
                    .params({ domainName, roleName, auditLog, expand, pending })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getCollection(
            domainName,
            collectionName,
            category,
            auditLog = true,
            expand = false,
            pending = false
        ) {
            if (category === 'group') {
                return new Promise((resolve, reject) => {
                    fetchr
                        .read('group')
                        .params({
                            domainName,
                            groupName: collectionName,
                            auditLog,
                            expand,
                            pending,
                        })
                        .end((err, data) => {
                            if (err) {
                                reject(err);
                            } else {
                                resolve(data);
                            }
                        });
                });
            } else if (category === 'role') {
                return new Promise((resolve, reject) => {
                    fetchr
                        .read('role')
                        .params({
                            domainName,
                            roleName: collectionName,
                            auditLog,
                            expand,
                            pending,
                        })
                        .end((err, data) => {
                            if (err) {
                                reject(err);
                            } else {
                                resolve(data);
                            }
                        });
                });
            } else if (category === 'domain') {
                return new Promise((resolve, reject) => {
                    fetchr
                        .read('domain')
                        .params({
                            domain: collectionName,
                        })
                        .end((err, data) => {
                            if (err) {
                                reject(err);
                            } else {
                                resolve(data);
                            }
                        });
                });
            }
        },

        getPendingDomainMembersList() {
            return new Promise((resolve, reject) => {
                fetchr.read('pending-approval').end((err, data) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(data);
                    }
                });
            });
        },

        getPendingDomainMembersListByDomain(domainName) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('pending-approval-domain')
                    .params({ domainName: domainName })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getPendingDomainMembersCountByDomain(domainName) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('pending-approval-domain-count')
                    .params({ domainName: domainName })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        processPending(
            domainName,
            roleName,
            memberName,
            auditRef,
            category,
            membership,
            _csrf
        ) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });

                fetchr
                    .create('process-pending')
                    .params({
                        domainName,
                        roleName,
                        memberName,
                        auditRef,
                        category,
                        membership,
                    })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        addRole(domainName, roleName, role, auditRef, _csrf, returnObj) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .create('role')
                    .params({ domainName, roleName, role, auditRef, returnObj })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        addGroup(domainName, groupName, group, auditRef, _csrf, returnObj) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .create('group')
                    .params({
                        domainName,
                        groupName,
                        group,
                        auditRef,
                        returnObj,
                    })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        deleteRole(domainName, roleName, auditRef, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .delete('role')
                    .params({ domainName, roleName, auditRef })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        deleteGroup(domainName, groupName, auditRef, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .delete('group')
                    .params({ domainName, groupName, auditRef })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        reviewRole(domainName, roleName, role, auditRef, _csrf, returnObj) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .update('role')
                    .params({ domainName, roleName, role, auditRef, returnObj })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        addServiceHost(
            domainName,
            serviceName,
            staticWorkload,
            auditRef,
            _csrf
        ) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                var params = {
                    domainName,
                    serviceName,
                    staticWorkload,
                    auditRef,
                };

                fetchr
                    .update('add-service-host')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            if (data) {
                                resolve(data);
                            } else {
                                resolve([]);
                            }
                        }
                    });
            });
        },

        reviewGroup(domainName, groupName, group, auditRef, _csrf, returnObj) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .update('group')
                    .params({
                        domainName,
                        groupName,
                        group,
                        auditRef,
                        returnObj,
                    })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        deleteRoleMember(domainName, memberName, auditRef, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .delete('role-members')
                    .params({ domainName, memberName, auditRef })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        addMember(
            domainName,
            collectionName,
            memberName,
            membership,
            auditRef,
            category,
            _csrf,
            returnObj
        ) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .create('member')
                    .params({
                        domainName,
                        collectionName,
                        memberName,
                        auditRef,
                        membership,
                        category,
                        returnObj,
                    })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        addMemberToRoles(
            domainName,
            roles,
            memberName,
            membership,
            auditRef,
            _csrf,
            returnObj
        ) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .create('member-multiple-roles')
                    .params({
                        domainName,
                        roles,
                        memberName,
                        auditRef,
                        membership,
                        returnObj,
                    })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        deleteMember(
            domainName,
            collectionName,
            memberName,
            auditRef,
            pending,
            category,
            _csrf
        ) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .delete('member')
                    .params({
                        domainName,
                        collectionName,
                        memberName,
                        auditRef,
                        pending,
                        category,
                    })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        deletePendingMember(domainName, roleName, memberName, auditRef, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .delete('pending-member')
                    .params({ domainName, roleName, memberName, auditRef })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getForm() {
            return new Promise((resolve, reject) => {
                fetchr.read('get-form').end((err, data) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(data);
                    }
                });
            });
        },

        // not used
        searchDomains(domainName) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('search-domain')
                    .params({ domainName })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getServices(domainName, publickeys, hosts) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('services')
                    .params({ domainName, publickeys, hosts })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            if (data) {
                                resolve(data);
                            } else {
                                resolve([]);
                            }
                        }
                    });
            });
        },

        getService(domain, service, expand = true, auditLog = true) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('service')
                    .params({ domain, service, expand, auditLog })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            if (data) {
                                resolve(data);
                            } else {
                                resolve([]);
                            }
                        }
                    });
            });
        },

        addService(
            domain,
            service,
            description,
            providerEndpoint,
            keyId,
            keyValue,
            _csrf,
            returnObj
        ) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                var params = {
                    domain,
                    service,
                    detail: {
                        name: domain + '.' + service,
                        description,
                        providerEndpoint,
                    },
                    returnObj,
                };

                if (keyId && keyValue) {
                    params.detail.publicKeys = [
                        {
                            id: keyId,
                            key: keyValue,
                        },
                    ];
                }

                fetchr
                    .create('service')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        deleteService(domain, service, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });

                var params = {
                    domain,
                    service,
                };

                fetchr
                    .delete('service')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        addKey(domain, service, keyId, keyValue, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                var params = {
                    domain,
                    service,
                    id: keyId,
                    publicKeyEntry: {
                        id: keyId,
                        key: keyValue,
                    },
                };
                fetchr
                    .create('key')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        deleteKey(domain, service, id, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });

                var params = {
                    domain,
                    service,
                    id,
                };

                fetchr
                    .delete('key')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        allowProviderTemplate(domain, service, template, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                let params = {
                    name: domain,
                    domainTemplate: {
                        templateNames: [template],
                        params: [
                            {
                                name: 'service',
                                value: service,
                            },
                        ],
                    },
                };
                fetchr
                    .create('provider')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getStatus() {
            return new Promise((resolve, reject) => {
                fetchr.read('status').end((err, data) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(data);
                    }
                });
            });
        },

        getAllUsers() {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('all-users')
                    .params()
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getPolicy(domainName, policyName) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('policy')
                    .params({ domainName, policyName })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            if (data) {
                                resolve(data);
                            } else {
                                resolve([]);
                            }
                        }
                    });
            });
        },

        getProvider(domainName, serviceName) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('provider')
                    .params({ domainName, serviceName })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getRolePrefix() {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('prefix')
                    .params()
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getPolicies(domainName, assertions, includeNonActive) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('policies')
                    .params({
                        domainName: domainName,
                        assertions: assertions,
                        includeNonActive: includeNonActive,
                    })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            if (data) {
                                resolve(data);
                            } else {
                                resolve([]);
                            }
                        }
                    });
            });
        },

        getPoliciesVersions(domainName, policyName) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('policies-versions')
                    .params({ domainName: domainName, policyName: policyName })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            if (data) {
                                resolve(data);
                            } else {
                                resolve([]);
                            }
                        }
                    });
            });
        },

        addPolicy(
            domainName,
            policyName,
            roleName,
            resource,
            action,
            effect,
            caseSensitive,
            _csrf,
            returnObj
        ) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                var params = {
                    domainName,
                    policyName,
                    policy: {
                        name: domainName + ':policy.' + policyName,
                        assertions: [
                            {
                                role: domainName + ':role.' + roleName,
                                resource: NameUtils.getResourceName(
                                    resource,
                                    domainName
                                ),
                                effect,
                                action: action.trim(),
                                caseSensitive: caseSensitive,
                            },
                        ],
                    },
                    returnObj,
                };
                fetchr
                    .create('policy')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        duplicatePolicyVersion(
            domainName,
            policyName,
            sourceVersionName,
            newVersionName,
            _csrf,
            returnObj
        ) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                var params = {
                    domainName,
                    policyName,
                    policyOptions: {
                        fromVersion: sourceVersionName,
                        version: newVersionName,
                    },
                    returnObj,
                };
                fetchr
                    .create('policy-version')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        setActivePolicyVersion(domainName, policyName, version, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                var params = {
                    domainName,
                    policyName,
                    policyOptions: {
                        version: version,
                    },
                };
                fetchr
                    .update('policy-version')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getPolicyVersion(domainName, policyName, version) {
            // escape zero version
            let versionEscaped = version;
            if (versionEscaped === '0') {
                versionEscaped = '"0"';
            }
            return new Promise((resolve, reject) => {
                fetchr
                    .read('policy-version')
                    .params({
                        domainName: domainName,
                        policyName: policyName,
                        version: versionEscaped,
                    })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            if (data) {
                                resolve(data);
                            } else {
                                resolve([]);
                            }
                        }
                    });
            });
        },

        deletePolicy(domainName, policyName, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });

                var params = {
                    domainName,
                    policyName,
                };

                fetchr
                    .delete('policy')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        deletePolicyVersion(domainName, policyName, version, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });

                var params = {
                    domainName,
                    policyName,
                    version,
                };

                fetchr
                    .delete('policy-version')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getHistory(domainName, roleName, startDate, endDate, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .read('domain-history')
                    .params({ domainName, roleName, startDate, endDate })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            if (data) {
                                resolve(data);
                            } else {
                                resolve([]);
                            }
                        }
                    });
            });
        },

        addAssertion(
            domainName,
            policyName,
            roleName,
            resource,
            action,
            effect,
            caseSensitive,
            _csrf
        ) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                var params = {
                    domainName,
                    policyName,
                    assertion: {
                        role: NameUtils.getRoleAssertionName(
                            roleName,
                            domainName
                        ),
                        resource: NameUtils.getResourceName(
                            resource,
                            domainName
                        ),
                        effect,
                        action: action.trim(),
                        caseSensitive: caseSensitive,
                    },
                };
                fetchr
                    .create('assertion')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        addAssertionPolicyVersion(
            domainName,
            policyName,
            version,
            roleName,
            resource,
            action,
            effect,
            caseSensitive,
            _csrf
        ) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                var params = {
                    domainName,
                    policyName,
                    version,
                    assertion: {
                        role: domainName + ':role.' + roleName,
                        resource: NameUtils.getResourceName(
                            resource,
                            domainName
                        ),
                        effect,
                        action: action.trim(),
                        caseSensitive: caseSensitive,
                    },
                };
                fetchr
                    .create('assertion-version')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        addAssertionConditions(
            domainName,
            policyName,
            assertionId,
            assertionConditions,
            auditRef,
            _csrf
        ) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                var params = {
                    domainName,
                    assertionId,
                    assertionConditions,
                    policyName,
                    auditRef,
                };
                fetchr
                    .create('assertionConditions')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        deleteAssertionConditions(
            domainName,
            policyName,
            assertionId,
            auditRef,
            _csrf
        ) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });

                let params = {
                    domainName,
                    policyName,
                    assertionId,
                    auditRef,
                };

                fetchr
                    .delete('assertionConditions')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        deleteAssertionCondition(
            domainName,
            policyName,
            assertionId,
            conditionId,
            auditRef,
            _csrf
        ) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });

                let params = {
                    domainName,
                    policyName,
                    assertionId,
                    conditionId,
                    auditRef,
                };

                fetchr
                    .delete('assertionCondition')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        deleteAssertion(domainName, policyName, assertionId, auditRef, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });

                let params = {
                    domainName,
                    policyName,
                    assertionId,
                    auditRef,
                };

                fetchr
                    .delete('assertion')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        deleteAssertionPolicyVersion(
            domainName,
            policyName,
            version,
            assertionId,
            auditRef,
            _csrf
        ) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });

                let params = {
                    domainName,
                    policyName,
                    version,
                    assertionId,
                    auditRef,
                };

                fetchr
                    .delete('assertion-version')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },
        deleteSubDomain(parent, name, auditRef, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .delete('domain')
                    .params({ parent, name, auditRef })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        putMeta(domainName, collectionName, detail, auditRef, _csrf, category) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .create('meta')
                    .params({
                        domainName,
                        collectionName,
                        detail,
                        auditRef,
                        category,
                    })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getMeta(params) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('meta')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        isAWSTemplateApplied(domainName) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('domain-templates')
                    .params({ name: domainName })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            if (
                                data &&
                                data.templateNames.indexOf('aws') > -1
                            ) {
                                resolve(true);
                            }
                            resolve(false);
                        }
                    });
            });
        },

        applyAWSTemplates(domainName, auditRef, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .create('domain-templates')
                    .params({ domainName, auditRef })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getDomainTemplateDetailsList(name) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('templates')
                    .params({ name })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getServerTemplateDetailsList() {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('templates')
                    .params()
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getAuthOptions() {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('auth-options')
                    .params()
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getHeaderDetails() {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('header-details')
                    .params()
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getServiceHeaderDetails() {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('service-header-details')
                    .params()
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getServicePageConfig() {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('service-page-config')
                    .params()
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        updateTemplate(params, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .create('provider')
                    .params(params)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getGroup(domainName, groupName, auditLog = true, pending = true) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('group')
                    .params({
                        domainName,
                        groupName,
                        auditLog,
                        pending,
                    })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getCollectionMembers(domainName, collectionName, category, trust) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('collection-members')
                    .params({ domainName, collectionName, category, trust })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getDomainRoleMembers(principal) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('domain-role-member')
                    .params({ principal })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getTimeZone() {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('time-zone')
                    .params()
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getFeatureFlag() {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('feature-flag')
                    .params()
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getPageFeatureFlag(pageName) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('page-feature-flag')
                    .params({ pageName })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getInstances(domainName, serviceName, category) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('instances')
                    .params({ domainName, serviceName, category })
                    .end((err, workloadList) => {
                        if (err) {
                            reject(err);
                        } else {
                            let result = {
                                workLoadData: [],
                            };
                            let workLoadMeta = {
                                totalDynamic: 0,
                                totalStatic: 0,
                                totalRecords: 0,
                                totalHealthyDynamic: 0,
                            };
                            let totalHealthyDynamicCount = 0;
                            if (
                                workloadList != null &&
                                Object.keys(workloadList).length > 0
                            ) {
                                workLoadMeta.totalRecords = workloadList.length;
                                if (category === SERVICE_TYPE_STATIC) {
                                    workloadList.forEach((workload) => {
                                        result.workLoadData.push(workload);
                                    });
                                    workLoadMeta.totalStatic =
                                        result.workLoadData.length;
                                    result.workLoadMeta = workLoadMeta;
                                    resolve(result);
                                } else {
                                    workloadList.forEach((workload) => {
                                        result.workLoadData.push(workload);
                                        if (
                                            workload.hostname !== 'NA' &&
                                            localDate.isRefreshedinLastSevenDays(
                                                workload.updateTime,
                                                'UTC'
                                            )
                                        ) {
                                            totalHealthyDynamicCount++;
                                        }
                                    });
                                    workLoadMeta.totalHealthyDynamic =
                                        totalHealthyDynamicCount;
                                    workLoadMeta.totalDynamic =
                                        result.workLoadData.length;
                                    result.workLoadMeta = workLoadMeta;
                                    resolve(result);
                                }
                            } else {
                                workLoadMeta.totalRecords = 0;
                                workLoadMeta.totalStatic = 0;
                                workLoadMeta.totalRecords = 0;
                                workLoadMeta.totalHealthyDynamic = 0;
                                result.workLoadMeta = workLoadMeta;
                                resolve(result);
                            }
                        }
                    });
            });
        },

        deleteInstance(
            provider,
            domainName,
            service,
            instanceId,
            category,
            auditRef,
            _csrf
        ) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .delete('instances')
                    .params({
                        provider,
                        domainName,
                        service,
                        instanceId,
                        category,
                        auditRef,
                    })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getInboundOutbound(domainName) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('microsegmentation')
                    .params({ domainName: domainName })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getAuthorityAttributes() {
            return new Promise((resolve, reject) => {
                fetchr.read('authority').end((err, data) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(data);
                    }
                });
            });
        },

        editMicrosegmentation(
            domainName,
            roleChanged,
            assertionChanged,
            assertionConditionChanged,
            data,
            _csrf
        ) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .update('microsegmentation')
                    .params({
                        domainName,
                        roleChanged,
                        assertionChanged,
                        assertionConditionChanged,
                        data,
                    })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        validateMicrosegmentationPolicy(
            category,
            roleMembers,
            inboundDestinationService,
            outboundSourceService,
            sourcePort,
            destinationPort,
            protocol,
            domainName,
            assertionId,
            _csrf
        ) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .update('validateMicrosegmentation')
                    .params({
                        category,
                        roleMembers,
                        inboundDestinationService,
                        outboundSourceService,
                        sourcePort,
                        destinationPort,
                        protocol,
                        domainName,
                        assertionId,
                    })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        updateGraphLayout(elements, style, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .update('graph-layout')
                    .params({ elements, style })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        deleteTransportRule(
            domainName,
            policyName,
            assertionId,
            roleName,
            auditRef,
            _csrf
        ) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .delete('transport-rule')
                    .params({
                        domainName,
                        policyName,
                        assertionId,
                        roleName,
                        auditRef,
                    })
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },
        getResourceAccessList(action) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('resource-access')
                    .params(action)
                    .end((err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data);
                        }
                    });
            });
        },

        getReviewRoles() {
            return new Promise((resolve, reject) => {
                fetchr.read('roles-review').end((err, data) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(data);
                    }
                });
            });
        },

        getReviewGroups() {
            return new Promise((resolve, reject) => {
                fetchr.read('groups-review').end((err, data) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(data);
                    }
                });
            });
        },
    };
};

export default Api;
