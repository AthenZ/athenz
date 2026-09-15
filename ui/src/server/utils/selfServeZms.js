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

// rdl-rest names a PUT Membership method putMembership. This UI's existing
// member service already calls putMembership, so try that first and fall back.
const COMBINED_SEARCH_METHODS = [
    'getSelfServeResources',
    'searchSelfServe',
    'getSelfServe',
];
const ROLE_SEARCH_METHODS = [
    'getSelfServeRoles',
    'getSelfServeRoleList',
    'getSelfserveRoles',
];
const GROUP_SEARCH_METHODS = [
    'getSelfServeGroups',
    'getSelfServeGroupList',
    'getSelfserveGroups',
];
const SEARCH_METHODS = [
    ...COMBINED_SEARCH_METHODS,
    ...ROLE_SEARCH_METHODS,
    ...GROUP_SEARCH_METHODS,
];

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

const searchPages = async (zms, method, params, type) => {
    const list = [];
    const domains = new Set();
    let membershipCount;
    let skip;
    for (let page = 0; page < 20; page++) {
        const raw = await invoke(zms, method, {
            ...params,
            ...(skip ? { skip, next: skip } : {}),
        });
        const mapped = toSelfServeSearchResponse(raw, {
            member: params.member,
            type,
        });
        list.push(...mapped.list);
        (mapped.domains || []).forEach((domain) => domains.add(domain));
        if (mapped.membershipCount !== undefined) {
            membershipCount = mapped.membershipCount;
        }
        skip = mapped.next;
        if (!skip) {
            break;
        }
    }
    const response = {
        list,
        domains: [...domains].sort(),
    };
    if (membershipCount !== undefined) {
        response.membershipCount = membershipCount;
    } else if (params.member) {
        response.membershipCount = list.filter(
            (item) => item.memberStatus === 'member'
        ).length;
    }
    return response;
};

// The ZMS self-serve endpoints return every matching object across all
// domains; they do not filter by domain server-side. The domain dropdown is
// populated from the full result set, so filter the displayed list here while
// leaving domains/membershipCount computed over the complete response.
const applyDomainFilter = (response, domain) =>
    domain
        ? {
              ...response,
              list: response.list.filter((item) => item.domainName === domain),
          }
        : response;

const searchZms = async (zms, params) => {
    const searchParams = toZmsSearchParams(params);
    const combined = firstMethod(zms, COMBINED_SEARCH_METHODS);
    if (combined) {
        const response = await searchPages(zms, combined, searchParams);
        return applyDomainFilter(response, searchParams.domain);
    }
    const roleMethod = firstMethod(zms, ROLE_SEARCH_METHODS);
    const groupMethod = firstMethod(zms, GROUP_SEARCH_METHODS);
    if (!roleMethod && !groupMethod) {
        return Promise.reject({
            status: 501,
            message: {
                message: 'ZMS client is missing a self-serve search method',
            },
        });
    }
    // Each endpoint is dedicated to a single object kind, so stamp every item
    // with the type derived from which endpoint produced it. This is what lets
    // the UI split results into the separate Roles and Groups sections.
    const tasks = [];
    if (roleMethod) {
        tasks.push(searchPages(zms, roleMethod, searchParams, 'role'));
    }
    if (groupMethod) {
        tasks.push(searchPages(zms, groupMethod, searchParams, 'group'));
    }
    const pages = await Promise.all(tasks);
    const list = pages.flatMap((page) => page.list);
    const domains = [
        ...new Set(pages.flatMap((page) => page.domains || [])),
    ].sort();
    // sum the per-endpoint counts so the "my roles & groups" header reflects
    // memberships across both roles and groups, not just the first endpoint
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
    return applyDomainFilter(response, searchParams.domain);
};

const search = (zms, params) => {
    if (!firstMethod(zms, SEARCH_METHODS)) {
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
    // both roles and groups support member expiration; the request flow simply
    // omits it for groups, while the extend flow supplies a chosen date
    if (params.expiration) {
        body.expiration = params.expiration;
    }
    // review reminders apply to roles only
    if (!isGroup && params.reviewReminder) {
        body.reviewReminder = params.reviewReminder;
    }
    return body;
};

const extendExpiration = (params) => {
    if (params.expiration) {
        return params.expiration;
    }
    const mins = Number(params.selfRenewMins) || 20160;
    return new Date(Date.now() + mins * 60 * 1000).toISOString();
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
