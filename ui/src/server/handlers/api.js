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
const Fetchr = require('fetchr');
let CLIENTS = require('../clients');
const errorHandler = require('../utils/errorHandler');
const userService = require('../services/userService');
const debug = require('debug')('AthenzUI:server:handlers:api');
let appConfig = {};
let domainHistoryApi = undefined;
try {
    domainHistoryApi = require('./domain-history');
} catch (err) {
    if (err.code !== 'ENOENT') {
        debug(
            '[Startup] extended api domain-history does not exist. Moving on.. '
        );
    }
}

const responseHandler = function(err, data) {
    if (err) {
        debug(
            `principal: ${this.req.session.shortId} rid: ${
                this.req.headers.rid
            } Error from ZMS while calling ${this.caller} API: ${JSON.stringify(
                err
            )}`
        );
        return this.callback(errorHandler.fetcherError(err));
    } else {
        this.callback(null, data);
    }
};

Fetchr.registerService({
    name: 'assertion',
    create(req, resource, params, body, config, callback) {
        req.clients.zms.putAssertion(
            params,
            responseHandler.bind({ caller: 'putAssertion', callback, req })
        );
    },
    delete(req, resource, params, config, callback) {
        req.clients.zms.deleteAssertion(
            params,
            responseHandler.bind({ caller: 'deleteAssertion', callback, req })
        );
    },
});

Fetchr.registerService({
    name: 'domain',
    read(req, resource, params, config, callback) {
        req.clients.zms.getDomain(
            params,
            responseHandler.bind({ caller: 'getDomain', callback, req })
        );
    },
    // we will be reusing this api for creating sub domains as well as user domains
    // the params.parent decides if it is a sub domain
    create(req, resource, params, body, config, callback) {
        if (params.parent) {
            req.clients.zms.postSubDomain(
                params,
                responseHandler.bind({ caller: 'postSubDomain', callback, req })
            );
        } else {
            req.clients.zms.postUserDomain(
                params,
                responseHandler.bind({
                    caller: 'postUserDomain',
                    callback,
                    req,
                })
            );
        }
    },
    delete(req, resource, params, config, callback) {
        req.clients.zms.deleteSubDomain(
            params,
            responseHandler.bind({ caller: 'deleteSubDomain', callback, req })
        );
    },
});

Fetchr.registerService({
    name: 'domain-templates',
    read(req, resource, params, config, callback) {
        req.clients.zms.getDomainTemplateList(
            params,
            responseHandler.bind({
                caller: 'getDomainTemplates',
                callback,
                req,
            })
        );
    },
    create(req, resource, params, body, config, callback) {
        let paramsAWS = {
            name: params.domainName,
            domainTemplate: {
                templateNames: ['aws'],
            },
            auditRef: params.auditRef,
        };

        let paramsBastionService = {
            name: params.domainName,
            domainTemplate: {
                templateNames: ['aws_instance_launch_provider'],
                params: [
                    {
                        name: 'service',
                        value: 'bastion',
                    },
                ],
            },
            auditRef: params.auditRef,
        };

        Promise.all([
            new Promise((resolve, reject) => {
                req.clients.zms.putDomainTemplate(paramsAWS, (err, json) => {
                    if (err) {
                        return reject(err);
                    }
                    return resolve(json);
                });
            }),
            new Promise((resolve, reject) => {
                req.clients.zms.putDomainTemplate(
                    paramsBastionService,
                    (err, json) => {
                        if (err) {
                            return reject(err);
                        }
                        return resolve(json);
                    }
                );
            }),
        ])
            .then((data) => {
                return callback(null, data);
            })
            .catch((err) => {
                debug(
                    `principal: ${req.session.shortId} rid: ${
                        req.headers.rid
                    } Error from ZMS while calling putDomainTemplate API for applying AWS templates : ${JSON.stringify(
                        err
                    )}`
                );
                return callback(errorHandler.fetcherError(err));
            });
    },
});

Fetchr.registerService({
    name: 'templates',
    read(req, resource, params, config, callback) {
        new Promise((resolve, reject) => {
            req.clients.zms.getDomainTemplateDetailsList(params, function(
                err,
                json
            ) {
                if (err) {
                    return reject(err);
                }
                if (!err && Array.isArray(json.metaData)) {
                    return resolve(json.metaData);
                }
                return resolve([]);
            });
        })
            .then((data) => {
                return callback(null, data);
            })
            .catch((err) => {
                if (err.status !== 404) {
                    debug(
                        `principal: ${req.session.shortId} rid: ${
                            req.headers.rid
                        } Error from ZMS getDomainTemplateDetailsList API: ${JSON.stringify(
                            err
                        )}`
                    );
                    callback(errorHandler.fetcherError(err));
                } else {
                    callback(null, []);
                }
            });
    },
});

Fetchr.registerService({
    name: 'admin-domains',
    read(req, resource, params, config, callback) {
        let username = 'user.' + req.session.shortId;
        // this will allow non-human functional test identity to see domains
        if (req.session.shortId.indexOf('.') !== -1) {
            username = req.session.shortId;
        }
        const adminReqParams = { roleMember: username, roleName: 'admin' };
        Promise.all([
            new Promise((resolve, reject) => {
                req.clients.zms.getDomainList(adminReqParams, function(
                    err,
                    json
                ) {
                    if (err) {
                        return reject(err);
                    }
                    if (!err && Array.isArray(json.names)) {
                        return resolve(json.names);
                    }
                    return resolve([]);
                });
            }),
            new Promise((resolve, reject) => {
                req.clients.zms.getSignedDomains(
                    { metaOnly: 'true', metaAttr: 'all' },
                    function(err, json) {
                        if (err) {
                            return reject(err);
                        }
                        return resolve(json);
                    }
                );
            }),
        ])
            .then((values) => {
                let adminDomains = values[0] ? values[0] : [];
                let allDomains = values[1].domains ? values[1].domains : [];
                let newAdminDomains = allDomains
                    .filter((domain) => {
                        return adminDomains.includes(domain.domain.name);
                    })
                    .sort((a, b) => {
                        return a.domain.name > b.domain.name ? 1 : -1;
                    });
                callback(null, newAdminDomains);
            })
            .catch((err) => {
                debug(
                    `principal: ${req.session.shortId} rid: ${
                        req.headers.rid
                    } Error from ZMS while calling getSignedDomains API for managedDomains : ${JSON.stringify(
                        err
                    )}`
                );
                return callback(errorHandler.fetcherError(err));
            });
    },
});

Fetchr.registerService({
    name: 'domain-list',
    read(req, resource, params, config, callback) {
        let username = 'user.' + req.session.shortId;
        // this will allow non-human functional test identity to see domains
        if (req.session.shortId.indexOf('.') !== -1) {
            username = req.session.shortId;
        }
        const userReqParams = { roleMember: username };

        let promises = [];
        promises.push(
            new Promise((resolve, reject) => {
                req.clients.zms.getDomainList(userReqParams, function(
                    err,
                    json
                ) {
                    if (err) {
                        return reject(err);
                    }
                    if (Array.isArray(json.names)) {
                        return resolve(json.names);
                    }
                    return resolve([]);
                });
            })
        );

        const adminReqParams = { ...userReqParams };
        adminReqParams.roleName = 'admin';

        promises.push(
            new Promise((resolve, reject) => {
                req.clients.zms.getDomainList(adminReqParams, function(
                    err,
                    json
                ) {
                    if (err) {
                        return reject(err);
                    }
                    if (Array.isArray(json.names)) {
                        return resolve(json.names);
                    }
                    return resolve([]);
                });
            })
        );

        let memberDomains = [];
        let adminDomains = [];
        let searchResults = [];

        Promise.all(promises)
            .then((values) => {
                memberDomains = values[0];
                adminDomains = values[1];
                adminDomains.forEach((domainName) => {
                    let searchData = { name: domainName };
                    searchData.adminDomain = true;
                    searchResults.push(searchData);
                });

                memberDomains.forEach((domainName) => {
                    let searchData = { name: domainName };
                    let searchDomain = adminDomains.includes(domainName);
                    if (!searchDomain) {
                        searchData.userDomain = true;
                        searchResults.push(searchData);
                    }
                });

                searchResults.sort((a, b) => {
                    return a.name > b.name ? 1 : -1;
                });

                return callback(null, searchResults);
            })
            .catch((err) => {
                debug(
                    `principal: ${req.session.shortId} rid: ${
                        req.headers.rid
                    } Error from ZMS while calling getDomainList API for UserDomainList: ${JSON.stringify(
                        err
                    )}`
                );
                callback(errorHandler.fetcherError(err));
            });
    },
});

Fetchr.registerService({
    name: 'get-form',
    read(req, resource, params, config, callback) {
        callback(null, req.csrfToken());
    },
});

Fetchr.registerService({
    name: 'member',
    create(req, resource, params, body, config, callback) {
        req.clients.zms.putMembership(
            params,
            responseHandler.bind({ caller: 'putMembership', callback, req })
        );
    },
    delete(req, resource, params, config, callback) {
        req.clients.zms.deleteMembership(
            params,
            responseHandler.bind({ caller: 'deleteMembership', callback, req })
        );
    },
});

Fetchr.registerService({
    name: 'pending-member',
    delete(req, resource, params, config, callback) {
        req.clients.zms.deletePendingMembership(
            params,
            responseHandler.bind({
                caller: 'deletePendingMembership',
                callback,
                req,
            })
        );
    },
});

Fetchr.registerService({
    name: 'member-multiple-roles',
    create(req, resource, params, body, config, callback) {
        let promises = [];
        params.roles.forEach((role) => {
            let reqParams = {
                domainName: params.domainName,
                roleName: role,
                memberName: params.memberName,
                membership: params.membership,
                auditRef: params.auditRef,
            };
            promises.push(
                new Promise((resolve, reject) => {
                    req.clients.zms.putMembership(reqParams, function(
                        err,
                        json
                    ) {
                        if (err) {
                            return reject(err);
                        }
                        return resolve(json);
                    });
                })
            );
        });

        Promise.all(promises)
            .then((values) => {
                return callback(null, values);
            })
            .catch((err) => {
                debug(
                    `principal: ${req.session.shortId} rid: ${
                        req.headers.rid
                    } Error from ZMS while calling putMembership API for multiple roles: ${JSON.stringify(
                        err
                    )}`
                );
                return callback(errorHandler.fetcherError(err));
            });
    },
});

Fetchr.registerService({
    name: 'role-members',
    read(req, resource, params, config, callback) {
        req.clients.zms.getDomainRoleMembers(params, function(err, data) {
            if (err) {
                debug(
                    `principal: ${req.session.shortId} rid: ${
                        req.headers.rid
                    } Error from ZMS while calling getDomainRoleMembers API: ${JSON.stringify(
                        err
                    )}`
                );
                callback(errorHandler.fetcherError(err));
            }

            if (data && data.members) {
                data.members.forEach((member) => {
                    member.memberFullName = userService.getUserFullName(
                        member.memberName
                    );
                });
            }
            callback(null, data);
        });
    },
    delete(req, resource, params, config, callback) {
        req.clients.zms.deleteDomainRoleMember(
            params,
            responseHandler.bind({
                caller: 'deleteDomainRoleMember',
                callback,
                req,
            })
        );
    },
});

Fetchr.registerService({
    name: 'policies',
    read(req, resource, params, config, callback) {
        req.clients.zms.getPolicies(params, function(err, data) {
            if (!err && Array.isArray(data.list)) {
                return callback(
                    null,
                    data.list.sort((a, b) => {
                        return a.name > b.name ? 1 : -1;
                    })
                );
            }
            debug(
                `principal: ${req.session.shortId} rid: ${
                    req.headers.rid
                } Error from ZMS while calling getPolicies API: ${JSON.stringify(
                    err
                )}`
            );
            return callback(errorHandler.fetcherError(err));
        });
    },
});

Fetchr.registerService({
    name: 'policy',
    read(req, resource, params, config, callback) {
        req.clients.zms.getPolicy(
            params,
            responseHandler.bind({ caller: 'getPolicy', callback, req })
        );
    },
    create(req, resource, params, body, config, callback) {
        req.clients.zms.getPolicy(params, (err) => {
            if (err) {
                if (err.status === 404) {
                    return req.clients.zms.putPolicy(
                        params,
                        responseHandler.bind({
                            caller: 'putPolicy',
                            callback,
                            req,
                        })
                    );
                } else {
                    return callback(errorHandler.fetcherError(err));
                }
            }
            let customError = {
                status: '500',
                message: {
                    message: `Policy ${params.policyName} exists in domain ${params.domainName}.`,
                },
            };
            debug(
                `principal: ${req.session.shortId} rid: ${
                    req.headers.rid
                } Error from ZMS while calling getPolicy API: ${JSON.stringify(
                    customError
                )}`
            );
            return callback(errorHandler.fetcherError(customError));
        });
    },
    delete(req, resource, params, config, callback) {
        req.clients.zms.deletePolicy(params, function(err, data) {
            if (err) {
                return callback(errorHandler.fetcherError(err));
            } else {
                callback(null, data);
            }
        });
    },
});

Fetchr.registerService({
    name: 'process-pending',
    create(req, resource, params, body, config, callback) {
        req.clients.zms.putMembershipDecision(
            params,
            responseHandler.bind({
                caller: 'putMembershipDecision',
                callback,
                req,
            })
        );
    },
});

Fetchr.registerService({
    name: 'provider',
    read(req, resource, params, config, callback) {
        let res = {
            provider: {},
            allProviders: appConfig.allProviders,
        };
        let promises = [];
        const service = `${params.domainName}:service.${params.serviceName}`;
        appConfig.allProviders.forEach((provider) => {
            let param = {
                domainName: params.domainName,
                policyName: provider.id,
            };
            promises.push(
                new Promise((resolve, reject) => {
                    req.clients.zms.getPolicy(param, (err, data) => {
                        res.provider[provider.id] = 'not';
                        if (err) {
                            if (err.status !== 404) {
                                reject(err);
                            }
                        }
                        if (
                            data &&
                            data.assertions &&
                            data.assertions.some(
                                (a) =>
                                    a.resource &&
                                    a.resource === service &&
                                    a.action &&
                                    a.action === 'launch'
                            )
                        ) {
                            res.provider[provider.id] = 'allow';
                        }
                        resolve();
                    });
                })
            );
        });
        Promise.all(promises)
            .then((data) => {
                callback(null, res);
            })
            .catch((err) => {
                debug(
                    `principal: ${req.session.shortId} rid: ${
                        req.headers.rid
                    } Error from ZMS while calling getPolicy API for providers: ${JSON.stringify(
                        err
                    )}`
                );
                callback(errorHandler.fetcherError(err));
            });
    },
    create(req, resource, params, body, config, callback) {
        req.clients.zms.putDomainTemplate(
            params,
            responseHandler.bind({ caller: 'putDomainTemplate', callback, req })
        );
    },
});

Fetchr.registerService({
    name: 'auth-options',
    read(req, resource, params, config, callback) {
        callback(null, {
            zms: appConfig.zms,
            athenzDomainService: appConfig.athenzDomainService,
        });
    },
});

Fetchr.registerService({
    name: 'prefix',
    read(req, resource, params, config, callback) {
        callback(null, {
            allPrefixes: appConfig.allPrefixes,
        });
    },
});

Fetchr.registerService({
    name: 'role',
    read(req, resource, params, config, callback) {
        req.clients.zms.getRole(params, function(err, data) {
            if (err) {
                debug(
                    `principal: ${req.session.shortId} rid: ${
                        req.headers.rid
                    } Error from ZMS while calling getRole API: ${JSON.stringify(
                        err
                    )}`
                );
                callback(errorHandler.fetcherError(err));
            }
            if (data) {
                if (data.roleMembers) {
                    let roleMembers = data.roleMembers;
                    roleMembers.forEach((member) => {
                        member.memberFullName = userService.getUserFullName(
                            member.memberName
                        );
                    });
                }
                if (data.auditLog) {
                    data.auditLog.forEach((m) => {
                        m.memberFullName = userService.getUserFullName(
                            m.member
                        );
                        m.adminFullName = userService.getUserFullName(m.admin);
                    });
                }
            }
            callback(null, data);
        });
    },
    create(req, resource, params, body, config, callback) {
        req.clients.zms.putRole(
            params,
            responseHandler.bind({ caller: 'putRole', callback, req })
        );
    },
    delete(req, resource, params, config, callback) {
        req.clients.zms.deleteRole(
            params,
            responseHandler.bind({ caller: 'deleteRole', callback, req })
        );
    },
    update(req, resource, params, body, config, callback) {
        req.clients.zms.putRoleReview(
            params,
            responseHandler.bind({ caller: 'putRoleReview', callback, req })
        );
    },
});

Fetchr.registerService({
    name: 'role-meta',
    create(req, resource, params, body, config, callback) {
        req.clients.zms.putRoleMeta(
            params,
            responseHandler.bind({ caller: 'putRoleMeta', callback, req })
        );
    },
});

Fetchr.registerService({
    name: 'roles',
    read(req, resource, params, config, callback) {
        req.clients.zms.getRoles(
            params,
            responseHandler.bind({ caller: 'getRoles', callback, req })
        );
    },
});

Fetchr.registerService({
    name: 'role-list',
    read(req, resource, params, config, callback) {
        req.clients.zms.getRoleList(
            params,
            responseHandler.bind({ caller: 'getRoleList', callback, req })
        );
    },
});

Fetchr.registerService({
    name: 'pending-approval',
    read(req, resource, params, config, callback) {
        let username = 'user.' + req.session.shortId;
        // this will allow non-human functional test identity to see domains
        if (req.session.shortId.indexOf('.') !== -1) {
            username = req.session.shortId;
        }
        params.principal = username;
        new Promise((resolve, reject) => {
            req.clients.zms.getPendingDomainRoleMembersList(
                params,
                (err, data) => {
                    if (err) {
                        reject(err);
                    }
                    if (data) {
                        resolve(data);
                    }
                }
            );
        })
            .then((data) => {
                let pendingMap = {};
                data.domainRoleMembersList.forEach((domain) => {
                    const domainName = domain.domainName;
                    domain.members.forEach((member) => {
                        const memberName = member.memberName;
                        member.memberRoles.forEach((role) => {
                            const roleName = role.roleName;
                            const expiryDate = role.expiration;
                            const userComment = role.auditRef;
                            const key = domainName + memberName + roleName;
                            pendingMap[key] = {
                                domainName: domainName,
                                memberName: memberName,
                                memberNameFull: userService.getUserFullName(
                                    memberName
                                ),
                                roleName: roleName,
                                userComment: userComment,
                                auditRef: '',
                                requestPrincipal: role.requestPrincipal,
                                requestPrincipalFull: userService.getUserFullName(
                                    role.requestPrincipal
                                ),
                                requestTime: role.requestTime,
                                expiryDate: expiryDate,
                            };
                        });
                    });
                });
                return callback(null, pendingMap);
            })
            .catch((err) => {
                if (err.status !== 404) {
                    debug(
                        `principal: ${req.session.shortId} rid: ${
                            req.headers.rid
                        } Error from ZMS while calling domainRoleMemberList API: ${JSON.stringify(
                            err
                        )}`
                    );
                    callback(errorHandler.fetcherError(err));
                } else {
                    // 404 from domainRoleMemberList is ok, no pending approvals.
                    callback(null, []);
                }
            });
    },
});

Fetchr.registerService({
    name: 'services',
    read(req, resource, params, config, callback) {
        req.clients.zms.getServiceIdentities(params, function(err, data) {
            if (!err && Array.isArray(data.list)) {
                return callback(
                    null,
                    data.list.sort((a, b) => {
                        return a.name > b.name ? 1 : -1;
                    })
                );
            }
            debug(
                `principal: ${req.session.shortId} rid: ${
                    req.headers.rid
                } Error from ZMS while calling getServiceIdentities API: ${JSON.stringify(
                    err
                )}`
            );
            return callback(errorHandler.fetcherError(err));
        });
    },
});

Fetchr.registerService({
    name: 'search-domain',
    read(req, resource, params, config, callback) {
        let allDomains = [];
        let adminDomains = [];
        let memberDomains = [];
        let searchResults = [];
        let username = 'user.' + req.session.shortId;
        // this will allow non-human functional test identity to see domains
        if (req.session.shortId.indexOf('.') !== -1) {
            username = req.session.shortId;
        }
        Promise.all([
            new Promise((resolve, reject) => {
                req.clients.zms.getDomainList({}, function(err, json) {
                    if (err) {
                        return reject(err);
                    }
                    if (!err && Array.isArray(json.names)) {
                        return resolve(json.names);
                    }
                    return resolve([]);
                });
            }),
            new Promise((resolve, reject) => {
                req.clients.zms.getDomainList(
                    {
                        roleMember: username,
                    },
                    function(err, json) {
                        if (err) {
                            return reject(err);
                        }
                        if (Array.isArray(json.names)) {
                            return resolve(json.names);
                        }
                        return resolve([]);
                    }
                );
            }),
            new Promise((resolve, reject) => {
                req.clients.zms.getDomainList(
                    {
                        roleName: 'admin',
                        roleMember: username,
                    },
                    function(err, json) {
                        if (err) {
                            return reject(err);
                        }
                        if (Array.isArray(json.names)) {
                            return resolve(json.names);
                        }
                        return resolve([]);
                    }
                );
            }),
        ])
            .then(function(values) {
                allDomains = values[0];
                memberDomains = values[1];
                adminDomains = values[2];
                allDomains.forEach(function(domainName) {
                    if (domainName.includes(params.domainName)) {
                        let searchData = { name: domainName };
                        let userDomain = memberDomains.find(
                            (domain) => domain === domainName
                        );
                        let adminDomain = adminDomains.find(
                            (domain) => domain === domainName
                        );
                        if (userDomain) {
                            searchData.userDomain = true;
                        }
                        if (adminDomain) {
                            searchData.adminDomain = true;
                        }
                        searchResults.push(searchData);
                    }
                });
                return callback(null, searchResults);
            })
            .catch((err) => {
                debug(
                    `principal: ${req.session.shortId} rid: ${
                        req.headers.rid
                    } Error from ZMS while calling getDomainList API for search: ${JSON.stringify(
                        err
                    )}`
                );
                callback(errorHandler.fetcherError(err));
            });
    },
});

Fetchr.registerService({
    name: 'service',
    read(req, resource, params, config, callback) {
        req.clients.zms.getServiceIdentity(
            params,
            responseHandler.bind({
                caller: 'getServiceIdentity',
                callback,
                req,
            })
        );
    },
    create(req, resource, params, body, config, callback) {
        req.clients.zms.putServiceIdentity(
            params,
            responseHandler.bind({
                caller: 'putServiceIdentity',
                callback,
                req,
            })
        );
    },
    delete(req, resource, params, config, callback) {
        req.clients.zms.deleteServiceIdentity(
            params,
            responseHandler.bind({
                caller: 'deleteServiceIdentity',
                callback,
                req,
            })
        );
    },
});

Fetchr.registerService({
    name: 'key',
    create(req, resource, params, body, config, callback) {
        req.clients.zms.putPublicKeyEntry(
            params,
            responseHandler.bind({ caller: 'putPublicKeyEntry', callback, req })
        );
    },
    delete(req, resource, params, config, callback) {
        req.clients.zms.deletePublicKeyEntry(
            params,
            responseHandler.bind({
                caller: 'deletePublicKeyEntry',
                callback,
                req,
            })
        );
    },
});

Fetchr.registerService({
    name: 'status',
    read(req, resource, params, config, callback) {
        callback(null, 'ok');
    },
});

Fetchr.registerService({
    name: 'user',
    read(req, resource, params, config, callback) {
        callback(null, {
            userId: req.session.shortId,
        });
    },
});

Fetchr.registerService({
    name: 'auth-options',
    read(req, resource, params, config, callback) {
        callback(null, {
            zms: appConfig.zms,
            athenzDomainService: appConfig.athenzDomainService,
        });
    },
});

Fetchr.registerService({
    name: 'domain-history',
    read(req, resource, params, config, callback) {
        if (typeof domainHistoryApi === 'function') {
            domainHistoryApi(
                req,
                resource,
                params,
                config,
                callback,
                userService,
                errorHandler
            );
        } else {
            debug('domain-history API is not defined. ');
            callback(null, []);
        }
    },
});

Fetchr.registerService({
    name: 'header-details',
    read(req, resource, params, config, callback) {
        callback(null, {
            userData: appConfig.userData(req.session.shortId),
            headerLinks: appConfig.headerLinks,
            userId: req.session.shortId,
            createDomainMessage: appConfig.createDomainMessage,
            productMasterLink: appConfig.productMasterLink,
        });
    },
});

Fetchr.registerService({
    name: 'service-page-config',
    read(req, resource, params, config, callback) {
        callback(null, {
            servicePageConfig: appConfig.servicePageConfig,
        });
    },
});

module.exports.load = function(config, secrets) {
    appConfig = {
        zms: config.zms,
        athenzDomainService: config.athenzDomainService,
        userData: config.userData,
        headerLinks: config.headerLinks,
        allProviders: config.allProviders,
        createDomainMessage: config.createDomainMessage,
        servicePageConfig: config.servicePageConfig,
        productMasterLink: config.productMasterLink,
        allPrefixes: config.allPrefixes,
    };
    return CLIENTS.load(config, secrets);
};

module.exports.route = function(expressApp) {
    // TODO fetchr statsCollector
    expressApp.use(CLIENTS.middleware());
    expressApp.use('/api/v1', Fetchr.middleware());
};
