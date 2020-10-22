/*
 * Copyright 2020 Verizon Media
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

export default (req) => {
    const fetchr = new Fetchr({
        xhrPath: '/api/v1',
        xhrTimeout: 10000,
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
                        templates: {
                            templateNames: ['openhouse'],
                        },
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

        getRoles(domainName) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('roles')
                    .params({ domainName })
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

        getPendingDomainRoleMembersList() {
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

        processPending(
            domainName,
            roleName,
            memberName,
            auditRef,
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

        addRole(domainName, roleName, role, auditRef, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .create('role')
                    .params({ domainName, roleName, role, auditRef })
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

        reviewRole(domainName, roleName, role, auditRef, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .update('role')
                    .params({ domainName, roleName, role, auditRef })
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
            roleName,
            memberName,
            membership,
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
                    .create('member')
                    .params({
                        domainName,
                        roleName,
                        memberName,
                        auditRef,
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

        addMemberToRoles(
            domainName,
            roles,
            memberName,
            membership,
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
                    .create('member-multiple-roles')
                    .params({
                        domainName,
                        roles,
                        memberName,
                        auditRef,
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

        deleteMember(domainName, roleName, memberName, auditRef, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .delete('member')
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

        getServices(domainName) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('services')
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
            _csrf
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

        getPolicies(domainName, assertions) {
            return new Promise((resolve, reject) => {
                fetchr
                    .read('policies')
                    .params({ domainName: domainName, assertions: assertions })
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
                                action,
                            },
                        ],
                    },
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
                        role: domainName + ':role.' + roleName,
                        resource: NameUtils.getResourceName(
                            resource,
                            domainName
                        ),
                        effect,
                        action,
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

        deleteAssertion(domainName, policyName, assertionId, _csrf) {
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

        putRoleMeta(domainName, roleName, detail, auditRef, _csrf) {
            return new Promise((resolve, reject) => {
                fetchr.updateOptions({
                    context: {
                        _csrf: _csrf,
                    },
                });
                fetchr
                    .create('role-meta')
                    .params({ domainName, roleName, detail, auditRef })
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
    };
};
