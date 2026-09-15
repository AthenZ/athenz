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

const toNumber = (value, fallback = 0) => {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
};

// ZMS returns the role/group and domain member-expiry caps as-is; the effective
// cap is the lower of the two, with 0 meaning "no limit". Returns 0 when neither
// side sets a limit.
const effectiveExpiryDays = (collectionDays, domainDays) => {
    const limits = [collectionDays, domainDays].filter((days) => days > 0);
    return limits.length ? Math.min(...limits) : 0;
};

const MEMBER_STATUSES = new Set(['member', 'pending', 'none']);

const memberStatusFrom = (value) => {
    const status = String(value ?? '').toLowerCase();
    return MEMBER_STATUSES.has(status) ? status : 'none';
};

const toSelfServeItem = (item = {}, fallbackType) => ({
    type: item.type ?? fallbackType ?? 'role',
    domainName: item.domainName ?? '',
    name: item.name ?? '',
    description: item.description ?? '',
    memberStatus: memberStatusFrom(item.memberStatus),
    expiration: item.expiration ?? '',
    selfRenew: Boolean(item.selfRenew),
    selfRenewMins: toNumber(item.selfRenewMins, 0),
    reviewEnabled: Boolean(item.reviewEnabled),
    auditEnabled: Boolean(item.auditEnabled),
    deleteProtection: Boolean(item.deleteProtection),
    inheritedFrom: item.inheritedFrom || undefined,
    maxExpiryDays: effectiveExpiryDays(
        toNumber(item.memberExpiryDays, 0),
        toNumber(item.domainMemberExpiryDays, 0)
    ),
});

const uniqueDomains = (list) =>
    [...new Set(list.map((item) => item.domainName).filter(Boolean))].sort();

const membershipCountFromList = (list) =>
    list.filter((item) => item.memberStatus === 'member').length;

const toSelfServeSearchResponse = (data = {}, options = {}) => {
    const list = (data.list ?? []).map((item) =>
        toSelfServeItem(item, options.type)
    );
    const response = {
        list,
        domains: uniqueDomains(list),
        next: data.next ?? undefined,
    };
    if (options.member) {
        response.membershipCount = membershipCountFromList(list);
    }
    return response;
};

const toZmsSearchParams = (params = {}) => {
    const matchString = params.matchString ?? '';
    const domain = params.domain ?? '';
    const member =
        params.member === true ||
        params.member === 'true' ||
        params.member === '1';
    const payload = {
        matchString,
        domain,
        member,
        memberOnly: member,
    };
    if (params.limit) {
        payload.limit = Number(params.limit);
    }
    if (params.skip || params.next) {
        const cursor = params.skip || params.next;
        payload.skip = cursor;
        payload.next = cursor;
    }
    return payload;
};

module.exports = {
    toSelfServeItem,
    toSelfServeSearchResponse,
    toZmsSearchParams,
};
