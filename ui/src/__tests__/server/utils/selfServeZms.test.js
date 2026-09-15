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
const selfServeZms = require('../../../server/utils/selfServeZms');

const mockClient = (methods) => {
    const client = {};
    Object.keys(methods).forEach((name) => {
        client[name] = (params, callback) => {
            try {
                callback(null, methods[name](params));
            } catch (err) {
                callback(err);
            }
        };
    });
    return client;
};

describe('selfServeZms', () => {
    it('rejects when the ZMS client has no self-serve search method', async () => {
        await expect(
            selfServeZms.search({}, { matchString: 'x' })
        ).rejects.toMatchObject({ status: 501 });
    });

    it('maps getSelfServeRoles plus getSelfServeGroups in parallel', async () => {
        const zms = mockClient({
            getSelfServeRoles: () => ({
                list: [
                    { domainName: 'd1', name: 'role-a', memberStatus: 'none' },
                ],
            }),
            getSelfServeGroups: () => ({
                list: [
                    {
                        domainName: 'd1',
                        name: 'group-a',
                        memberStatus: 'member',
                    },
                ],
            }),
        });
        const data = await selfServeZms.search(zms, { matchString: 'a' });
        expect(data.list.map((item) => item.name).sort()).toEqual([
            'group-a',
            'role-a',
        ]);
        expect(data.list.find((item) => item.name === 'group-a').type).toBe(
            'group'
        );
    });

    it('stamps type from the endpoint when the API returns an untyped list', async () => {
        // Mirrors the real ZMS contract: each endpoint returns { list: [...] }
        // with short names and no type field. The adapter must tag items based
        // on which endpoint produced them so the UI can split the sections.
        const zms = mockClient({
            getSelfServeRoles: () => ({
                list: [{ domainName: 'd1', name: 'sredb-readers' }],
            }),
            getSelfServeGroups: () => ({
                list: [{ domainName: 'd1', name: 'platform-team' }],
            }),
        });
        const data = await selfServeZms.search(zms, { matchString: 'a' });
        expect(
            data.list.find((item) => item.name === 'sredb-readers').type
        ).toBe('role');
        expect(
            data.list.find((item) => item.name === 'platform-team').type
        ).toBe('group');
    });

    it('filters the list by domain while keeping the full domain dropdown', async () => {
        const zms = mockClient({
            getSelfServeRoles: () => ({
                list: [
                    { domainName: 'd1', name: 'role-a' },
                    { domainName: 'd2', name: 'role-b' },
                ],
            }),
            getSelfServeGroups: () => ({ list: [] }),
        });
        const data = await selfServeZms.search(zms, {
            matchString: 'role',
            domain: 'd1',
        });
        expect(data.list.map((item) => item.name)).toEqual(['role-a']);
        expect(data.domains).toEqual(['d1', 'd2']);
    });

    it('forwards memberOnly and surfaces the membership overlay for the my-roles view', async () => {
        const captured = {};
        const zms = mockClient({
            getSelfServeRoles: (params) => {
                captured.roles = params;
                return {
                    list: [
                        {
                            domainName: 'd1',
                            name: 'role-a',
                            memberStatus: 'member',
                            expiration: '2026-09-12T00:00:00.000Z',
                        },
                        {
                            domainName: 'd1',
                            name: 'role-b',
                            memberStatus: 'member',
                            inheritedFrom: 'eng:group.platform',
                        },
                    ],
                };
            },
            getSelfServeGroups: (params) => {
                captured.groups = params;
                return {
                    list: [
                        {
                            domainName: 'd2',
                            name: 'group-a',
                            memberStatus: 'member',
                        },
                    ],
                };
            },
        });
        const data = await selfServeZms.search(zms, {
            matchString: '',
            member: true,
        });

        // the my-roles view drives the server-side membership filter
        expect(captured.roles.memberOnly).toBe(true);
        expect(captured.groups.memberOnly).toBe(true);

        // the per-principal overlay fields flow through to the UI item shape
        const direct = data.list.find((item) => item.name === 'role-a');
        expect(direct.memberStatus).toBe('member');
        expect(direct.expiration).toBe('2026-09-12T00:00:00.000Z');
        const inherited = data.list.find((item) => item.name === 'role-b');
        expect(inherited.inheritedFrom).toBe('eng:group.platform');

        // the header count spans both roles and groups
        expect(data.membershipCount).toBe(3);
    });

    it('follows next-page tokens until search results are exhausted', async () => {
        const calls = [];
        const zms = mockClient({
            getSelfServeResources: (params) => {
                calls.push(params);
                if (!params.skip) {
                    return {
                        list: [{ domainName: 'd', name: 'one', type: 'role' }],
                        next: 'page-2',
                    };
                }
                return {
                    list: [{ domainName: 'd', name: 'two', type: 'role' }],
                };
            },
        });
        const data = await selfServeZms.search(zms, { matchString: 'x' });
        expect(data.list.map((item) => item.name)).toEqual(['one', 'two']);
        expect(calls[1].skip).toBe('page-2');
    });

    it('requests role membership through the same ZMS method as Add Member', async () => {
        let captured;
        const zms = mockClient({
            getSelfServeRoles: () => ({ roles: [] }),
            putMembership: (params) => {
                captured = params;
                return { memberName: params.memberName };
            },
        });
        await selfServeZms.applyAction(
            zms,
            {
                action: 'request',
                type: 'role',
                domainName: 'paranoids.tools',
                name: 'security-platform-users',
                auditRef: 'need console access',
                expiration: '2026-09-12T00:00:00.000Z',
                reviewReminder: '2026-08-12T00:00:00.000Z',
            },
            'user.jdoe'
        );
        expect(captured).toEqual(
            expect.objectContaining({
                domainName: 'paranoids.tools',
                roleName: 'security-platform-users',
                memberName: 'user.jdoe',
                auditRef: 'need console access',
                returnObj: true,
                membership: expect.objectContaining({
                    memberName: 'user.jdoe',
                    expiration: '2026-09-12T00:00:00.000Z',
                    reviewReminder: '2026-08-12T00:00:00.000Z',
                }),
            })
        );
    });

    it('keeps a group expiration but drops the role-only review reminder', async () => {
        let captured;
        const zms = mockClient({
            getSelfServeRoles: () => ({ roles: [] }),
            putGroupMembership: (params) => {
                captured = params;
                return {};
            },
        });
        await selfServeZms.applyAction(
            zms,
            {
                action: 'extend',
                type: 'group',
                domainName: 'paranoids.tools',
                name: 'security-champions',
                expiration: '2026-09-12T00:00:00.000Z',
                reviewReminder: '2026-08-12T00:00:00.000Z',
                justification: 'extend champions',
            },
            'user.jdoe'
        );
        // groups support member expiration, so the chosen date is preserved
        expect(captured.membership.expiration).toBe('2026-09-12T00:00:00.000Z');
        // review reminders are a role-only concept and stay off group bodies
        expect(captured.membership.reviewReminder).toBeUndefined();
        expect(captured.auditRef).toBe('extend champions');
        expect(captured.groupName).toBe('security-champions');
    });

    it('cancels pending membership and leaves with the existing delete APIs', async () => {
        const calls = [];
        const zms = mockClient({
            getSelfServeRoles: () => ({ roles: [] }),
            deletePendingMembership: (params) => {
                calls.push(['pending', params]);
                return {};
            },
            deleteMembership: (params) => {
                calls.push(['leave', params]);
                return {};
            },
        });
        await selfServeZms.applyAction(
            zms,
            {
                action: 'cancel',
                type: 'role',
                domainName: 'd',
                name: 'r',
                auditRef: 'changed mind',
            },
            'user.jdoe'
        );
        await selfServeZms.applyAction(
            zms,
            {
                action: 'leave',
                type: 'role',
                domainName: 'd',
                name: 'r',
                auditRef: 'no longer needed',
            },
            'user.jdoe'
        );
        expect(calls[0][0]).toBe('pending');
        expect(calls[1][0]).toBe('leave');
        expect(calls[1][1].roleName).toBe('r');
    });
});
