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
'use strict';

const {
    toSelfServeSearchResponse,
    toZmsSearchParams,
} = require('./selfServeContract');

const ROLE_SEARCH_METHOD = 'getSelfServeRoles';
const GROUP_SEARCH_METHOD = 'getSelfServeGroups';

const firstMethod = (client, names) =>
    names.find((name) => client && typeof client[name] === 'function');

const invoke = (client, method, params) =>
    new Promise((resolve, reject) => {
        client[method](params, (err, data) => {
            if (err) {
                reject(err);
            } else {
                resolve(data);
            }
        });
    });

const invokeNamed = (client, names, params) => {
    const method = firstMethod(client, names);
    if (!method) {
        return Promise.reject({
            status: 501,
            message: {
                message: `ZMS client is missing ${names[0]}`,
            },
        });
    }
    return invoke(client, method, params);
};

const applyDomainFilter = (response, domain) =>
    domain
        ? {
              ...response,
              list: response.list.filter((item) => item.domainName === domain),
          }
        : response;

const searchZms = async (zms, params) => {
    const searchParams = toZmsSearchParams(params);
    if (
        !firstMethod(zms, [ROLE_SEARCH_METHOD]) ||
        !firstMethod(zms, [GROUP_SEARCH_METHOD])
    ) {
        return Promise.reject({
            status: 501,
            message: {
                message: 'ZMS client is missing a self-serve search method',
            },
        });
    }
    const pages = await Promise.all([
        invoke(zms, ROLE_SEARCH_METHOD, searchParams).then((data) =>
            toSelfServeSearchResponse(data, {
                member: searchParams.member,
                type: 'role',
            })
        ),
        invoke(zms, GROUP_SEARCH_METHOD, searchParams).then((data) =>
            toSelfServeSearchResponse(data, {
                member: searchParams.member,
                type: 'group',
            })
        ),
    ]);
    const list = pages.flatMap((page) => page.list);
    const domains = [
        ...new Set(pages.flatMap((page) => page.domains || [])),
    ].sort();
    const counts = pages
        .map((page) => page.membershipCount)
        .filter((count) => count !== undefined);
    const membershipCount = counts.length
        ? counts.reduce((sum, count) => sum + count, 0)
        : undefined;
    const response = { list, domains };
    if (membershipCount !== undefined) {
        response.membershipCount = membershipCount;
    } else if (searchParams.member) {
        response.membershipCount = list.filter(
            (item) => item.memberStatus === 'member'
        ).length;
    }
    return applyDomainFilter(response, params.domain);
};

const search = (zms, params) => {
    if (
        !firstMethod(zms, [ROLE_SEARCH_METHOD]) ||
        !firstMethod(zms, [GROUP_SEARCH_METHOD])
    ) {
        return Promise.reject({
            status: 501,
            message: {
                message: 'ZMS client has no self-serve search method',
            },
        });
    }
    return searchZms(zms, params);
};

const membershipBody = (params, memberName, { isGroup } = {}) => {
    const body = { memberName };
    if (params.expiration) {
        body.expiration = params.expiration;
    }
    if (!isGroup && params.reviewReminder) {
        body.reviewReminder = params.reviewReminder;
    }
    return body;
};

const extendExpiration = (params) => {
    return params.expiration || '';
};

const applyAction = (zms, params, memberName) => {
    const isGroup = params.type === 'group';
    const auditRef =
        params.auditRef || params.justification || 'self-service request';
    const collectionName = params.name;
    const domainName = params.domainName;

    if (params.action === 'request' || params.action === 'extend') {
        const membership = membershipBody(
            {
                ...params,
                expiration:
                    params.action === 'extend'
                        ? extendExpiration(params)
                        : params.expiration,
            },
            memberName,
            { isGroup }
        );
        if (isGroup) {
            return invokeNamed(zms, ['putGroupMembership'], {
                domainName,
                groupName: collectionName,
                memberName,
                auditRef,
                membership,
                returnObj: true,
            });
        }
        return invokeNamed(zms, ['putMembership'], {
            domainName,
            roleName: collectionName,
            memberName,
            auditRef,
            membership,
            returnObj: true,
        });
    }

    if (params.action === 'cancel') {
        if (isGroup) {
            return invokeNamed(zms, ['deletePendingGroupMembership'], {
                domainName,
                groupName: collectionName,
                memberName,
                auditRef,
            });
        }
        return invokeNamed(zms, ['deletePendingMembership'], {
            domainName,
            roleName: collectionName,
            memberName,
            auditRef,
        });
    }

    if (params.action === 'leave') {
        if (isGroup) {
            return invokeNamed(zms, ['deleteGroupMembership'], {
                domainName,
                groupName: collectionName,
                memberName,
                auditRef,
            });
        }
        return invokeNamed(zms, ['deleteMembership'], {
            domainName,
            roleName: collectionName,
            memberName,
            auditRef,
        });
    }

    return Promise.reject({
        status: 400,
        message: { message: `Unknown self-service action: ${params.action}` },
    });
};

module.exports = {
    search,
    applyAction,
};
