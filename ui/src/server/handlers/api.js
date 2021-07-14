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

const responseHandler = function (err, data) {
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
    name: 'assertionConditions',
    create(req, resource, params, body, config, callback) {
        let assertionConditions = [];
        let assertionConditionData = {
            operator: 'EQUALS',
            value: '',
        };

        var assertionCondition;

        for (var i = 0; i < params.assertionConditions.length; i++) {
            let condition = {};
            assertionCondition = {
                conditionsMap: {},
            };
            Object.keys(params.assertionConditions[i]).forEach((key) => {
                let copyAssertionConditionData = JSON.parse(
                    JSON.stringify(assertionConditionData)
                );
                copyAssertionConditionData['value'] =
                    params.assertionConditions[i][key];
                if (copyAssertionConditionData['value'] === '') {
                    copyAssertionConditionData['value'] = '*';
                }
                condition[key] = copyAssertionConditionData;
            });
            assertionCondition['conditionsMap'] = condition;
            assertionConditions.push(assertionCondition);
        }
        let finalData = {
            conditionsList: assertionConditions,
        };
        params.assertionConditions = finalData;

        req.clients.zms.putAssertionConditions(
            params,
            responseHandler.bind({
                caller: 'putAssertionConditions',
                callback,
                req,
            })
        );
    },
});

Fetchr.registerService({
    name: 'assertionCondition',

    delete(req, resource, params, config, callback) {
        req.clients.zms.deleteAssertionCondition(
            params,
            responseHandler.bind({
                caller: 'deleteAssertionCondition',
                callback,
                req,
            })
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
            params.detail.templates.templateNames = appConfig.templates;
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
            if (params) {
                req.clients.zms.getDomainTemplateDetailsList(
                    params,
                    function (err, json) {
                        if (err) {
                            return reject(err);
                        }
                        if (!err && Array.isArray(json.metaData)) {
                            return resolve(json.metaData);
                        }
                        return resolve([]);
                    }
                );
            } else {
                req.clients.zms.getServerTemplateDetailsList(function (
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
            }
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
                req.clients.zms.getDomainList(
                    adminReqParams,
                    function (err, json) {
                        if (err) {
                            return reject(err);
                        }
                        if (!err && Array.isArray(json.names)) {
                            return resolve(json.names);
                        }
                        return resolve([]);
                    }
                );
            }),
            new Promise((resolve, reject) => {
                req.clients.zms.getSignedDomains(
                    { metaOnly: 'true', metaAttr: 'all' },
                    function (err, json) {
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
                req.clients.zms.getDomainList(
                    userReqParams,
                    function (err, json) {
                        if (err) {
                            return reject(err);
                        }
                        if (Array.isArray(json.names)) {
                            return resolve(json.names);
                        }
                        return resolve([]);
                    }
                );
            })
        );

        const adminReqParams = { ...userReqParams };
        adminReqParams.roleName = 'admin';

        promises.push(
            new Promise((resolve, reject) => {
                req.clients.zms.getDomainList(
                    adminReqParams,
                    function (err, json) {
                        if (err) {
                            return reject(err);
                        }
                        if (Array.isArray(json.names)) {
                            return resolve(json.names);
                        }
                        return resolve([]);
                    }
                );
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
    name: 'get-service-host',
    read(req, resource, params, config, callback) {
        req.clients.zms.getServiceIdentity(
            params,
            responseHandler.bind({ caller: 'get-service-host', callback, req })
        );
    },
});

Fetchr.registerService({
    name: 'member',
    create(req, resource, params, body, config, callback) {
        if (params.category === 'group') {
            req.clients.zms.putGroupMembership(
                {
                    domainName: params.domainName,
                    groupName: params.collectionName,
                    memberName: params.memberName,
                    auditRef: params.auditRef,
                    membership: params.membership,
                    category: params.category,
                },
                responseHandler.bind({
                    caller: 'putGroupMembership',
                    callback,
                    req,
                })
            );
        } else if (params.category === 'role') {
            req.clients.zms.putMembership(
                {
                    domainName: params.domainName,
                    roleName: params.collectionName,
                    memberName: params.memberName,
                    auditRef: params.auditRef,
                    membership: params.membership,
                },
                responseHandler.bind({ caller: 'putMembership', callback, req })
            );
        }
    },
    delete(req, resource, params, config, callback) {
        if (params.category === 'group') {
            if (params.pending) {
                req.clients.zms.deletePendingGroupMembership(
                    {
                        domainName: params.domainName,
                        groupName: params.collectionName,
                        memberName: params.memberName,
                        auditRef: params.auditRef,
                    },
                    responseHandler.bind({
                        caller: 'deletePendingGroupMembership',
                        callback,
                        req,
                    })
                );
            } else {
                req.clients.zms.deleteGroupMembership(
                    {
                        domainName: params.domainName,
                        groupName: params.collectionName,
                        memberName: params.memberName,
                        auditRef: params.auditRef,
                    },
                    responseHandler.bind({
                        caller: 'deleteGroupMembership',
                        callback,
                        req,
                    })
                );
            }
        } else if (params.category === 'role') {
            if (params.pending) {
                req.clients.zms.deletePendingMembership(
                    {
                        domainName: params.domainName,
                        roleName: params.collectionName,
                        memberName: params.memberName,
                        auditRef: params.auditRef,
                    },
                    responseHandler.bind({
                        caller: 'deleteMembership',
                        callback,
                        req,
                    })
                );
            } else {
                req.clients.zms.deleteMembership(
                    {
                        domainName: params.domainName,
                        roleName: params.collectionName,
                        memberName: params.memberName,
                        auditRef: params.auditRef,
                    },
                    responseHandler.bind({
                        caller: 'deleteMembership',
                        callback,
                        req,
                    })
                );
            }
        }
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
                    req.clients.zms.putMembership(
                        reqParams,
                        function (err, json) {
                            if (err) {
                                return reject(err);
                            }
                            return resolve(json);
                        }
                    );
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
        req.clients.zms.getDomainRoleMembers(params, function (err, data) {
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
        req.clients.zms.getPolicies(params, function (err, data) {
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
        req.clients.zms.deletePolicy(params, function (err, data) {
            if (err) {
                return callback(errorHandler.fetcherError(err));
            } else {
                callback(null, data);
            }
        });
    },
});

Fetchr.registerService({
    name: 'assertionId',
    read(req, resource, params, config, callback) {
        new Promise((resolve, reject) => {
            req.clients.zms.getPolicy(
                {
                    policyName: params.policyName,
                    domainName: params.domainName,
                },
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
            .then((policyData) => {
                let flag = 0;
                policyData.assertions.forEach((assertion) => {
                    if (
                        assertion.role ===
                            params.domainName + ':role.' + params.roleName &&
                        assertion.resource ===
                            params.domainName + ':' + params.resource &&
                        assertion.action === params.action &&
                        assertion.effect === params.effect
                    ) {
                        flag = 1;
                        callback(null, assertion.id);
                    }
                });

                if (!flag) {
                    let error = {
                        status: 404,
                        message: {
                            message:
                                'Failed to get assertion for policy' +
                                params.policyName +
                                '.',
                        },
                    };
                    callback(errorHandler.fetcherError(error));
                }
            })
            .catch((err) => {
                debug(
                    `principal: ${req.session.shortId} rid: ${
                        req.headers.rid
                    } Error from ZMS while calling getPolicy API for microsegmentation: ${JSON.stringify(
                        err
                    )}`
                );
                callback(errorHandler.fetcherError(err));
            });
    },
});

Fetchr.registerService({
    name: 'process-pending',
    create(req, resource, params, body, config, callback) {
        if (params.category === 'group') {
            req.clients.zms.putGroupMembershipDecision(
                {
                    domainName: params.domainName,
                    groupName: params.roleName,
                    memberName: params.memberName,
                    auditRef: params.auditRef,
                    membership: params.membership,
                },
                responseHandler.bind({
                    caller: 'putGroupMembershipDecision',
                    callback,
                    req,
                })
            );
        } else if (params.category === 'role') {
            req.clients.zms.putMembershipDecision(
                {
                    domainName: params.domainName,
                    roleName: params.roleName,
                    memberName: params.memberName,
                    auditRef: params.auditRef,
                    membership: params.membership,
                },
                responseHandler.bind({
                    caller: 'putMembershipDecision',
                    callback,
                    req,
                })
            );
        }
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
            zmsLoginUrl: appConfig.zmsLoginUrl,
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
        let promises = [];

        const getGroupMembers = (domainName, groupName, roleMember) => {
            return new Promise((resolve, reject) => {
                req.clients.zms.getGroup(
                    { domainName, groupName },
                    (err, data) => {
                        if (err) {
                            reject(err);
                        }
                        if (data && data.groupMembers) {
                            roleMember.groupMembers = data.groupMembers;
                            roleMember.groupMembers.forEach((member) => {
                                member.memberFullName =
                                    userService.getUserFullName(
                                        member.memberName
                                    );
                            });
                        }
                        resolve();
                    }
                );
            });
        };

        req.clients.zms.getRole(params, function (err, data) {
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
            if (data && data.trust) {
                req.clients.zms.getRole(
                    {
                        domainName: params.domainName,
                        roleName: params.roleName,
                        auditLog: false,
                        expand: true,
                        pending: false,
                    },
                    function (err, data) {
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
                            if (data.auditLog) {
                                data.auditLog.forEach((m) => {
                                    m.memberFullName =
                                        userService.getUserFullName(m.member);
                                    m.adminFullName =
                                        userService.getUserFullName(m.admin);
                                });
                            }
                            if (data.roleMembers) {
                                let roleMembers = data.roleMembers;
                                roleMembers.forEach((member) => {
                                    member.memberFullName =
                                        userService.getUserFullName(
                                            member.memberName
                                        );
                                });

                                roleMembers.forEach((member) => {
                                    if (member.memberName.includes(':group.')) {
                                        promises.push(
                                            getGroupMembers(
                                                member.memberName.split(
                                                    ':group.'
                                                )[0],
                                                member.memberName.split(
                                                    ':group.'
                                                )[1],
                                                member
                                            )
                                        );
                                    }
                                });
                                Promise.all(promises)
                                    .then(() => {
                                        callback(null, data);
                                    })
                                    .catch((err) => {
                                        callback(
                                            errorHandler.fetcherError(err)
                                        );
                                    });
                            } else {
                                callback(null, data);
                            }
                        }
                    }
                );
            } else if (data) {
                if (data.auditLog) {
                    data.auditLog.forEach((m) => {
                        m.memberFullName = userService.getUserFullName(
                            m.member
                        );
                        m.adminFullName = userService.getUserFullName(m.admin);
                    });
                }
                if (data.roleMembers) {
                    let roleMembers = data.roleMembers;
                    roleMembers.forEach((member) => {
                        member.memberFullName = userService.getUserFullName(
                            member.memberName
                        );
                    });
                    roleMembers.forEach((member) => {
                        if (member.memberName.includes(':group.')) {
                            promises.push(
                                getGroupMembers(
                                    member.memberName.split(':group.')[0],
                                    member.memberName.split(':group.')[1],
                                    member
                                )
                            );
                        }
                    });
                    Promise.all(promises)
                        .then(() => {
                            callback(null, data);
                        })
                        .catch((err) => {
                            callback(errorHandler.fetcherError(err));
                        });
                } else {
                    callback(null, data);
                }
            }
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
    name: 'meta',
    create(req, resource, params, body, config, callback) {
        if (params.category === 'group') {
            req.clients.zms.putGroupMeta(
                {
                    domainName: params.domainName,
                    groupName: params.collectionName,
                    auditRef: params.auditRef,
                    detail: params.detail,
                },
                responseHandler.bind({ caller: 'putGroupMeta', callback, req })
            );
        } else if (params.category === 'role') {
            req.clients.zms.putRoleMeta(
                {
                    domainName: params.domainName,
                    roleName: params.collectionName,
                    auditRef: params.auditRef,
                    detail: params.detail,
                },
                responseHandler.bind({ caller: 'putRoleMeta', callback, req })
            );
        } else if (params.category === 'domain') {
            req.clients.zms.putDomainMeta(
                {
                    name: params.domainName,
                    auditRef: params.auditRef,
                    detail: params.detail,
                },
                responseHandler.bind({ caller: 'putDomainMeta', callback, req })
            );
        }
    },
    read(req, resource, params, config, callback) {
        if (params.category === 'domain') {
            req.clients.zms.getDomainMetaStoreValidValuesList(
                params,
                responseHandler.bind({
                    caller: 'getDomainMetaStoreValidValuesList',
                    callback,
                    req,
                })
            );
        }
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
    name: 'groups',
    read(req, resource, params, config, callback) {
        req.clients.zms.getGroups(params, function (err, data) {
            if (err) {
                debug(
                    `principal: ${req.session.shortId} rid: ${
                        req.headers.rid
                    } Error from ZMS while calling getGroups API: ${JSON.stringify(
                        err
                    )}`
                );
                callback(errorHandler.fetcherError(err));
            }
            if (params.groupName) {
                let groupName =
                    params.domainName + ':group.' + params.groupName;
                let found = false;
                if (data && data.list) {
                    for (let item of data.list) {
                        if (item.name === groupName) {
                            found = true;
                            break;
                        }
                    }
                    if (found) {
                        callback(null, data);
                    } else {
                        setTimeout(() => {
                            req.clients.zms.getGroups(
                                params,
                                responseHandler.bind({
                                    caller: 'getGroups',
                                    callback,
                                    req,
                                })
                            );
                        }, 500);
                    }
                }
            } else {
                callback(null, data);
            }
        });
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
    name: 'groups-list',
    read(req, resource, params, config, callback) {
        req.clients.zms.getGroups(params, function (err, data) {
            if (err) {
                debug(
                    `principal: ${req.session.shortId} rid: ${
                        req.headers.rid
                    } Error from ZMS while calling getGroups API: ${JSON.stringify(
                        err
                    )}`
                );
                callback(errorHandler.fetcherError(err));
            }
            let newData = [];
            if (data && data.list) {
                data.list.forEach((item) => {
                    newData.push(item.name);
                });
            }
            callback(null, newData);
        });
    },
});

Fetchr.registerService({
    name: 'add-service-host',
    update(req, resource, params, body, config, callback) {
        req.clients.zms.putServiceIdentity(
            params,
            responseHandler.bind({ caller: 'add-service-host', callback, req })
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
        Promise.all([
            new Promise((resolve, reject) => {
                req.clients.zms.getPendingDomainGroupMembersList(
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
            }),
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
            }),
        ])
            .then((values) => {
                let data = values[1];
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
                                category: 'role',
                                domainName: domainName,
                                memberName: memberName,
                                memberNameFull:
                                    userService.getUserFullName(memberName),
                                roleName: roleName,
                                userComment: userComment,
                                auditRef: '',
                                requestPrincipal: role.requestPrincipal,
                                requestPrincipalFull:
                                    userService.getUserFullName(
                                        role.requestPrincipal
                                    ),
                                requestTime: role.requestTime,
                                expiryDate: expiryDate,
                            };
                        });
                    });
                });
                values[0].domainGroupMembersList.forEach((domain) => {
                    const domainName = domain.domainName;
                    domain.members.forEach((member) => {
                        const memberName = member.memberName;
                        member.memberGroups.forEach((group) => {
                            const groupName = group.groupName;
                            const expiryDate = group.expiration;
                            const userComment = group.auditRef;
                            const key = domainName + memberName + groupName;
                            pendingMap[key] = {
                                category: 'group',
                                domainName: domainName,
                                memberName: memberName,
                                memberNameFull:
                                    userService.getUserFullName(memberName),
                                roleName: groupName,
                                userComment: userComment,
                                auditRef: '',
                                requestPrincipal: group.requestPrincipal,
                                requestPrincipalFull:
                                    userService.getUserFullName(
                                        group.requestPrincipal
                                    ),
                                requestTime: group.requestTime,
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
        req.clients.zms.getServiceIdentities(params, function (err, data) {
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
                req.clients.zms.getDomainList({}, function (err, json) {
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
                    function (err, json) {
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
                    function (err, json) {
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
            .then(function (values) {
                allDomains = values[0];
                memberDomains = values[1];
                adminDomains = values[2];
                allDomains.forEach(function (domainName) {
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
    name: 'group',
    read(req, resource, params, config, callback) {
        req.clients.zms.getGroup(params, function (err, data) {
            if (err) {
                if (err.status !== 404) {
                    debug(
                        `principal: ${req.session.shortId} rid: ${
                            req.headers.rid
                        } Error from ZMS while calling getGroup API: ${JSON.stringify(
                            err
                        )}`
                    );
                    callback(errorHandler.fetcherError(err));
                } else {
                    callback(null, []);
                }
            }
            if (data && data.groupMembers) {
                data.groupMembers.forEach((member) => {
                    member.memberFullName = userService.getUserFullName(
                        member.memberName
                    );
                });
            }
            if (data.auditLog) {
                data.auditLog.forEach((m) => {
                    m.memberFullName = userService.getUserFullName(m.member);
                    m.adminFullName = userService.getUserFullName(m.admin);
                });
            }
            callback(null, data);
        });
    },

    create(req, resource, params, body, config, callback) {
        req.clients.zms.putGroup(
            params,
            responseHandler.bind({ caller: 'putGroup', callback, req })
        );
    },

    delete(req, resource, params, config, callback) {
        req.clients.zms.deleteGroup(
            params,
            responseHandler.bind({ caller: 'deleteGroup', callback, req })
        );
    },

    update(req, resource, params, body, config, callback) {
        req.clients.zms.putGroupReview(
            params,
            responseHandler.bind({ caller: 'putGroupReview', callback, req })
        );
    },
});

Fetchr.registerService({
    name: 'collection-members',
    read(req, resource, params, config, callback) {
        if (params.category === 'group') {
            req.clients.zms.getGroup(
                {
                    domainName: params.domainName,
                    groupName: params.collectionName,
                    auditLog: false,
                    pending: true,
                },
                function (err, data) {
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
                        if (data.groupMembers) {
                            let groupMembers = data.groupMembers;
                            groupMembers.forEach((member) => {
                                member.memberFullName =
                                    userService.getUserFullName(
                                        member.memberName
                                    );
                            });
                        }
                    }
                    callback(null, data.groupMembers);
                }
            );
        } else if (params.category === 'role') {
            if (params.trust) {
                let promises = [];

                const getGroupMembers = (domainName, groupName, roleMember) => {
                    return new Promise((resolve, reject) => {
                        req.clients.zms.getGroup(
                            { domainName, groupName },
                            (err, data) => {
                                if (err) {
                                    reject(err);
                                }
                                if (data && data.groupMembers) {
                                    roleMember.groupMembers = data.groupMembers;
                                    roleMember.groupMembers.forEach(
                                        (member) => {
                                            member.memberFullName =
                                                userService.getUserFullName(
                                                    member.memberName
                                                );
                                        }
                                    );
                                }
                                resolve();
                            }
                        );
                    });
                };

                req.clients.zms.getRole(
                    {
                        domainName: params.domainName,
                        roleName: params.collectionName,
                        auditLog: false,
                        pending: true,
                        expand: true,
                    },
                    function (err, data) {
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
                            if (data.auditLog) {
                                data.auditLog.forEach((m) => {
                                    m.memberFullName =
                                        userService.getUserFullName(m.member);
                                    m.adminFullName =
                                        userService.getUserFullName(m.admin);
                                });
                            }
                            if (data.roleMembers) {
                                let roleMembers = data.roleMembers;
                                roleMembers.forEach((member) => {
                                    member.memberFullName =
                                        userService.getUserFullName(
                                            member.memberName
                                        );
                                });

                                roleMembers.forEach((member) => {
                                    if (member.memberName.includes(':group.')) {
                                        promises.push(
                                            getGroupMembers(
                                                member.memberName.split(
                                                    ':group.'
                                                )[0],
                                                member.memberName.split(
                                                    ':group.'
                                                )[1],
                                                member
                                            )
                                        );
                                    }
                                });
                                Promise.all(promises)
                                    .then(() => {
                                        callback(null, data.roleMembers);
                                    })
                                    .catch((err) => {
                                        callback(
                                            errorHandler.fetcherError(err)
                                        );
                                    });
                            } else {
                                callback(null, []);
                            }
                        }
                    }
                );
            } else {
                let promises = [];

                const getGroupMembers = (domainName, groupName, roleMember) => {
                    return new Promise((resolve, reject) => {
                        req.clients.zms.getGroup(
                            { domainName, groupName },
                            (err, data) => {
                                if (err) {
                                    reject(err);
                                }
                                if (data && data.groupMembers) {
                                    roleMember.groupMembers = data.groupMembers;
                                    roleMember.groupMembers.forEach(
                                        (member) => {
                                            member.memberFullName =
                                                userService.getUserFullName(
                                                    member.memberName
                                                );
                                        }
                                    );
                                }
                                resolve();
                            }
                        );
                    });
                };

                req.clients.zms.getRole(
                    {
                        domainName: params.domainName,
                        roleName: params.collectionName,
                        auditLog: false,
                        pending: true,
                        expand: false,
                    },
                    function (err, data) {
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
                            if (data.auditLog) {
                                data.auditLog.forEach((m) => {
                                    m.memberFullName =
                                        userService.getUserFullName(m.member);
                                    m.adminFullName =
                                        userService.getUserFullName(m.admin);
                                });
                            }
                            if (data.roleMembers) {
                                let roleMembers = data.roleMembers;
                                roleMembers.forEach((member) => {
                                    member.memberFullName =
                                        userService.getUserFullName(
                                            member.memberName
                                        );
                                });

                                roleMembers.forEach((member) => {
                                    if (member.memberName.includes(':group.')) {
                                        promises.push(
                                            getGroupMembers(
                                                member.memberName.split(
                                                    ':group.'
                                                )[0],
                                                member.memberName.split(
                                                    ':group.'
                                                )[1],
                                                member
                                            )
                                        );
                                    }
                                });
                                Promise.all(promises)
                                    .then(() => {
                                        callback(null, data.roleMembers);
                                    })
                                    .catch((err) => {
                                        callback(
                                            errorHandler.fetcherError(err)
                                        );
                                    });
                            } else {
                                callback(null, []);
                            }
                        }
                    }
                );
            }
        }
    },
});

Fetchr.registerService({
    name: 'domain-role-member',
    read(req, resource, params, config, callback) {
        req.clients.zms.getPrincipalRoles(params, function (err, data) {
            debug(
                `principal: ${req.session.shortId} rid: ${
                    req.headers.rid
                } Error from ZMS while calling getDomainRoleMember API: ${JSON.stringify(
                    err
                )}`
            );

            if (data) {
                let prefix = new Set();
                if (data.memberRoles) {
                    data.memberRoles.forEach((roleMember) => {
                        prefix.add(roleMember.domainName);
                    });
                }
                data.prefix = [...prefix];
                return callback(null, data);
            }

            return callback(errorHandler.fetcherError(err));
        });
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
    name: 'service-header-details',
    read(req, resource, params, config, callback) {
        callback(null, {
            static: appConfig.serviceHeaderLinks[0],
            dynamic: appConfig.serviceHeaderLinks[1],
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

Fetchr.registerService({
    name: 'feature-flag',
    read(req, resource, params, config, callback) {
        callback(null, appConfig.featureFlag);
    },
});

Fetchr.registerService({
    name: 'microsegmentation',
    read(req, resource, params, config, callback) {
        let jsonData = {
            inbound: [],
            outbound: [],
        };

        let promises = [];

        req.clients.zms.getPolicies(
            { domainName: params.domainName, assertions: true },
            (err, data) => {
                if (!err && Array.isArray(data.list)) {
                    data.list.forEach((item, index) => {
                        if (
                            item.name.startsWith(
                                params.domainName + ':policy.' + 'acl.'
                            )
                        ) {
                            let temp = item.name.split('.');
                            //sample policy name - ACL.<service-name>.[inbound/outbound]
                            let serviceName = temp[temp.length - 2];
                            let category = '';

                            item.assertions &&
                                item.assertions.forEach(
                                    (assertionItem, assertionIdx) => {
                                        let tempData = {};
                                        let tempProtocol =
                                            assertionItem.action.split('-');
                                        tempData['layer'] = tempProtocol[0];
                                        let tempPort =
                                            assertionItem.action.split(':');
                                        tempData['source_port'] = tempPort[1];
                                        tempData['destination_port'] =
                                            tempPort[2];
                                        if (assertionItem.conditions) {
                                            tempData['conditionsList'] = [];

                                            assertionItem.conditions[
                                                'conditionsList'
                                            ].forEach((condition) => {
                                                let tempCondition = {};
                                                Object.keys(
                                                    condition['conditionsMap']
                                                ).forEach((key) => {
                                                    tempCondition[key] =
                                                        condition[
                                                            'conditionsMap'
                                                        ][key]['value'];
                                                });
                                                tempCondition['id'] =
                                                    condition['id'];
                                                tempCondition['assertionId'] =
                                                    assertionItem['id'];
                                                tempCondition['policyName'] =
                                                    item.name;
                                                tempData['conditionsList'].push(
                                                    tempCondition
                                                );
                                            });
                                        }
                                        let index = 0;
                                        if (item.name.includes('inbound')) {
                                            category = 'inbound';
                                            tempData['destination_service'] =
                                                serviceName;
                                            tempData['source_services'] = [];
                                            tempData['assertionIdx'] =
                                                assertionItem.id;
                                            jsonData['inbound'].push(tempData);
                                            index = jsonData['inbound'].length;
                                        } else if (
                                            item.name.includes('outbound')
                                        ) {
                                            category = 'outbound';
                                            tempData['source_service'] =
                                                serviceName;
                                            tempData['destination_services'] =
                                                [];
                                            tempData['assertionIdx'] =
                                                assertionItem.id;
                                            jsonData['outbound'].push(tempData);
                                            index = jsonData['outbound'].length;
                                        }
                                        //assertion convention for micro-segmentation:
                                        //GRANT [Action: <transport layer>-IN / <transport layer>-OUT]:[Source Port]:[Destination Port] [Resource:<service-name>] ON <role-name>
                                        // role name will be of the form : <domain>:role.<roleName>
                                        let roleName =
                                            assertionItem.role.substring(
                                                params.domainName.length + 6
                                            );
                                        promises.push(
                                            getRole(
                                                roleName,
                                                params.domainName,
                                                category,
                                                index
                                            )
                                        );

                                        promises.push(
                                            getIdentifier(
                                                roleName,
                                                category,
                                                index
                                            )
                                        );
                                    }
                                );
                        }
                    });
                } else if (err) {
                    return this.callback(errorHandler.fetcherError(err));
                }
                Promise.all(promises)
                    .then(() => {
                        return callback(null, jsonData);
                    })
                    .catch((err) => {
                        return this.callback(errorHandler.fetcherError(err));
                    });
            }
        );

        function getIdentifier(roleName, category, jsonIndex) {
            return new Promise((resolve, reject) => {
                let substringPrefix = '.' + category + '-';
                let identifier = roleName.substring(
                    roleName.indexOf(substringPrefix) + substringPrefix.length
                );
                jsonData[category][jsonIndex - 1]['identifier'] = identifier;
                resolve();
            });
        }

        function getRole(roleName, domainName, category, jsonIndex) {
            return new Promise((resolve, reject) => {
                req.clients.zms.getRole(
                    {
                        domainName: params.domainName,
                        roleName: roleName,
                        auditLog: false,
                        pending: false,
                        expand: false,
                    },
                    (err, data) => {
                        if (data) {
                            if (data.roleMembers) {
                                data.roleMembers.forEach((roleMember, idx) => {
                                    if (category === 'inbound') {
                                        jsonData[category][jsonIndex - 1][
                                            'source_services'
                                        ].push(roleMember.memberName);
                                    } else if (category === 'outbound') {
                                        jsonData[category][jsonIndex - 1][
                                            'destination_services'
                                        ].push(roleMember.memberName);
                                    }
                                });
                                resolve();
                            } else {
                                resolve();
                            }
                        } else if (err) {
                            reject(err);
                        }
                    }
                );
            });
        }
    },

    update(req, resource, params, body, config, callback) {
        let roleName = '';
        let policyName = '';
        let resourceName = '';
        let action = '';
        let promises = [];
        let tempMembers = [];
        let finalData;
        let auditRef = 'Updated using MicroSegmentation UI';

        if (params.data['category'] === 'inbound') {
            roleName =
                'acl.' +
                params.data['destination_service'] +
                '.inbound-' +
                params.data['identifier'];
            policyName =
                'acl.' + params.data['destination_service'] + '.inbound';
            resourceName =
                params.domainName + ':' + params.data['destination_service'];
            tempMembers = params.data['source_services'];
            action =
                params.data['layer'] +
                '-IN:' +
                params.data['source_port'] +
                ':' +
                params.data['destination_port'];
        } else {
            roleName =
                'acl.' +
                params.data['source_service'] +
                '.outbound-' +
                params.data['identifier'];
            policyName = 'acl.' + params.data['source_service'] + '.outbound';
            resourceName =
                params.domainName + ':' + params.data['source_service'];
            tempMembers = params.data['destination_services'];
            action =
                params.data['layer'] +
                '-OUT:' +
                params.data['source_port'] +
                ':' +
                params.data['destination_port'];
        }

        if (params.assertionChanged || params.assertionConditionChanged) {
            let assertionConditions = [];
            let assertionConditionData = {
                operator: 'EQUALS',
                value: '',
            };

            var assertionCondition;

            for (var i = 0; i < params.data['conditionsList'].length; i++) {
                let condition = {};
                assertionCondition = {
                    conditionsMap: {},
                };
                Object.keys(params.data['conditionsList'][i]).forEach((key) => {
                    if (key === 'enforcementstate' || key === 'instances') {
                        let copyAssertionConditionData = JSON.parse(
                            JSON.stringify(assertionConditionData)
                        );
                        copyAssertionConditionData['value'] =
                            params.data['conditionsList'][i][key];
                        if (copyAssertionConditionData['value'] === '') {
                            copyAssertionConditionData['value'] = '*';
                        }
                        condition[key] = copyAssertionConditionData;
                    }
                });
                assertionCondition['conditionsMap'] = condition;
                assertionConditions.push(assertionCondition);
            }
            finalData = {
                conditionsList: assertionConditions,
            };
        }

        if (params.roleChanged) {
            let role = {
                name: roleName,
                members: tempMembers,
            };

            promises.push(
                new Promise((resolve, reject) => {
                    req.clients.zms.putRole(
                        {
                            domainName: params.domainName,
                            roleName,
                            role,
                            auditRef,
                        },
                        (err, json) => {
                            if (err) {
                                return reject(err);
                            } else {
                                return resolve();
                            }
                        }
                    );
                })
            );
        }

        if (params.assertionChanged) {
            let assertion = {
                role: params.domainName + ':role.' + roleName,
                resource: resourceName,
                effect: 'ALLOW',
                action: action,
                caseSensitive: true,
            };
            promises.push(
                new Promise((resolve, reject) => {
                    req.clients.zms.getPolicy(
                        {
                            domainName: params.domainName,
                            policyName,
                        },
                        (err, data) => {
                            if (err) {
                                reject(err);
                            } else {
                                let foundAssertionMatch = false;
                                data.assertions.forEach((element) => {
                                    if (
                                        element.action.localeCompare(action) ===
                                        0
                                    ) {
                                        foundAssertionMatch = true;
                                    }
                                });
                                if (foundAssertionMatch) {
                                    let err = {
                                        status: '500',
                                        message: {
                                            message:
                                                'Policy with the assertion already exists',
                                        },
                                    };
                                    return reject(err);
                                }
                                return resolve(data);
                            }
                        }
                    );
                })
                    .then((data) => {
                        return new Promise((resolve, reject) => {
                            req.clients.zms.putAssertion(
                                {
                                    domainName: params.domainName,
                                    policyName,
                                    assertion,
                                },
                                (err, data) => {
                                    if (err) {
                                        reject(err);
                                    } else {
                                        return resolve(data);
                                    }
                                }
                            );
                        });
                    })
                    .then((data) => {
                        return new Promise((resolve, reject) => {
                            req.clients.zms.putAssertionConditions(
                                {
                                    domainName: params.domainName,
                                    policyName,
                                    assertionId: data.id,
                                    assertionConditions: finalData,
                                },
                                (err, data) => {
                                    if (err) {
                                        reject(err);
                                    } else {
                                        resolve(data);
                                    }
                                }
                            );
                        });
                    })
                    .then((assertionConditionData) => {
                        return new Promise((resolve, reject) => {
                            req.clients.zms.deleteAssertion(
                                {
                                    domainName: params.domainName,
                                    policyName,
                                    assertionId: params.data['assertionIdx'],
                                },
                                (err, data) => {
                                    if (err) {
                                        reject(err);
                                    } else {
                                        resolve(data);
                                    }
                                }
                            );
                        });
                    })
            );
        } else if (params.assertionConditionChanged) {
            promises.push(
                new Promise((resolve, reject) => {
                    req.clients.zms.deleteAssertionConditions(
                        {
                            domainName: params.domainName,
                            policyName,
                            assertionId: params.data['assertionIdx'],
                        },
                        (err, data) => {
                            if (err) {
                                reject(err);
                            } else {
                                return resolve(data);
                            }
                        }
                    );
                }).then(() => {
                    return new Promise((resolve, reject) => {
                        req.clients.zms.putAssertionConditions(
                            {
                                domainName: params.domainName,
                                policyName,
                                assertionId: params.data['assertionIdx'],
                                assertionConditions: finalData,
                            },
                            (err, data) => {
                                if (err) {
                                    reject(err);
                                } else {
                                    resolve(data);
                                }
                            }
                        );
                    });
                })
            );
        }

        Promise.all(promises)
            .then((data) => {
                return callback(null, data);
            })
            .catch((err) => {
                return callback(errorHandler.fetcherError(err));
            });
    },
});

Fetchr.registerService({
    name: 'instances',
    read(req, resource, params, config, callback) {
        req.clients.zts.getWorkloadsByService(
            { domainName: params.domainName, serviceName: params.serviceName },
            (err, data) => {
                if (data && data.workloadList != null) {
                    return callback(null, data);
                } else {
                    return callback(errorHandler.fetcherError(err));
                }
            }
        );
    },
});

Fetchr.registerService({
    name: 'authority',
    read(req, resource, params, config, callback) {
        req.clients.zms.getUserAuthorityAttributeMap(
            responseHandler.bind({
                caller: 'getUserAuthorityAttributeMap',
                callback,
                req,
            })
        );
    },
});

module.exports.load = function (config, secrets) {
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
        zmsLoginUrl: config.zmsLoginUrl,
        featureFlag: config.featureFlag,
        serviceHeaderLinks: config.serviceHeaderLinks,
        templates: config.templates,
    };
    return CLIENTS.load(config, secrets);
};

module.exports.route = function (expressApp) {
    // TODO fetchr statsCollector
    expressApp.use(CLIENTS.middleware());
    expressApp.use('/api/v1', Fetchr.middleware());
};
