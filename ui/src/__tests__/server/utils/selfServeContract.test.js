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
const {
    toSelfServeItem,
    toSelfServeSearchResponse,
    toZmsSearchParams,
} = require('../../../server/utils/selfServeContract');

describe('selfServeContract', () => {
    it('maps SelfServeObject role fields into UI items', () => {
        const mapped = toSelfServeSearchResponse(
            {
                list: [
                    {
                        domainName: 'paranoids.tools',
                        name: 'security-platform-users',
                        description: 'Day to day access',
                        memberStatus: 'NONE',
                        selfRenew: true,
                        selfRenewMins: 43200,
                        reviewEnabled: true,
                        auditEnabled: false,
                        deleteProtection: true,
                        memberExpiryDays: 90,
                        domainMemberExpiryDays: 30,
                    },
                    {
                        domainName: 'athenz.prod',
                        name: 'security-platform-auditors',
                        description: 'Audit coverage',
                        memberStatus: 'pending',
                        expiration: '2026-09-12T00:00:00.000Z',
                    },
                ],
            },
            { type: 'role' }
        );

        expect(mapped.list).toHaveLength(2);
        expect(mapped.list[0]).toEqual(
            expect.objectContaining({
                type: 'role',
                domainName: 'paranoids.tools',
                name: 'security-platform-users',
                memberStatus: 'none',
                selfRenew: true,
                selfRenewMins: 43200,
                reviewEnabled: true,
                deleteProtection: true,
                // effective cap is the lower of role (90) and domain (30)
                maxExpiryDays: 30,
            })
        );
        expect(mapped.list[1]).toEqual(
            expect.objectContaining({
                type: 'role',
                domainName: 'athenz.prod',
                name: 'security-platform-auditors',
                memberStatus: 'pending',
                expiration: '2026-09-12T00:00:00.000Z',
            })
        );
        expect(mapped.domains).toEqual(['athenz.prod', 'paranoids.tools']);
        expect(mapped.membershipCount).toBeUndefined();
    });

    it('stamps the type from the endpoint option', () => {
        const mapped = toSelfServeSearchResponse(
            {
                list: [
                    {
                        domainName: 'paranoids.tools',
                        name: 'security-champions',
                        memberStatus: 'member',
                    },
                ],
            },
            { type: 'group' }
        );
        expect(mapped.list[0]).toEqual(
            expect.objectContaining({
                type: 'group',
                name: 'security-champions',
                memberStatus: 'member',
            })
        );
    });

    it('reads memberStatus and inheritedFrom directly from the contract', () => {
        const item = toSelfServeItem(
            {
                domainName: 'paranoids.tools',
                name: 'scanner-users',
                memberStatus: 'member',
                inheritedFrom: 'paranoids.tools:group.security-champions',
            },
            'role'
        );
        expect(item.inheritedFrom).toBe(
            'paranoids.tools:group.security-champions'
        );
        expect(item.memberStatus).toBe('member');
    });

    it('counts memberships only for member=true searches without a backend total', () => {
        const mapped = toSelfServeSearchResponse(
            {
                list: [
                    {
                        type: 'role',
                        domainName: 'a',
                        name: 'r1',
                        memberStatus: 'member',
                    },
                    {
                        type: 'role',
                        domainName: 'a',
                        name: 'r2',
                        memberStatus: 'pending',
                    },
                ],
            },
            { member: true }
        );
        expect(mapped.membershipCount).toBe(1);
    });

    it('maps the search term to the ZMS matchString query param', () => {
        expect(
            toZmsSearchParams({
                matchString: 'security-platform',
                domain: 'paranoids.tools',
                member: 'true',
                skip: 'abc',
            })
        ).toEqual(
            expect.objectContaining({
                matchString: 'security-platform',
                domain: 'paranoids.tools',
                member: true,
                memberOnly: true,
                skip: 'abc',
                next: 'abc',
            })
        );
    });
});
