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
 * See the License for the specific language governing permissions and limitations
 * under the License.
 */
import {
    hasResourceOwner,
    isRoleResourceListManaged,
    isRoleResourceMetaManaged,
    isRoleResourceMembersManaged,
    errorMessageSuggestsResourceOwnership,
    resolveResourceOwnershipCliOnError,
    resolveRoleDeleteResourceOwnershipCli,
} from '../../../components/utils/resourceOwnership';

describe('resourceOwnership', () => {
    it('treats any non-blank SimpleName as an owner', () => {
        expect(hasResourceOwner('terraform')).toBe(true);
        expect(hasResourceOwner('TF')).toBe(true);
        expect(hasResourceOwner('user.terraform')).toBe(true);
        expect(hasResourceOwner('other')).toBe(true);
        expect(hasResourceOwner('  principal  ')).toBe(true);
        expect(hasResourceOwner('')).toBe(false);
        expect(hasResourceOwner('   ')).toBe(false);
        expect(hasResourceOwner(null)).toBe(false);
        expect(hasResourceOwner(undefined)).toBe(false);
    });

    it('detects role meta managed when any relevant owner is set', () => {
        expect(
            isRoleResourceMetaManaged({
                objectOwner: 'terraform',
                metaOwner: null,
            })
        ).toBe(true);
        expect(
            isRoleResourceMetaManaged({
                objectOwner: 'human',
                metaOwner: null,
            })
        ).toBe(true);
        expect(
            isRoleResourceMetaManaged({
                objectOwner: null,
                metaOwner: null,
            })
        ).toBe(false);
        expect(
            isRoleResourceMetaManaged({
                objectOwner: '',
                metaOwner: '  ',
            })
        ).toBe(false);
    });

    it('detects role list managed for members-only ownership', () => {
        expect(
            isRoleResourceListManaged({
                objectOwner: null,
                metaOwner: null,
                membersOwner: 'terraform',
            })
        ).toBe(true);
        expect(
            isRoleResourceMembersManaged({ membersOwner: 'terraform' })
        ).toBe(true);
        expect(
            isRoleResourceListManaged({
                objectOwner: null,
                metaOwner: null,
                membersOwner: null,
            })
        ).toBe(false);
    });

    it('resolveResourceOwnershipCliOnError returns deferred builder when managed or error matches', () => {
        const builder = resolveResourceOwnershipCliOnError(
            true,
            { body: { message: 'other' } },
            (zmsUrl) => `zms-cli -z ${zmsUrl} -d dom`
        );
        expect(typeof builder).toBe('function');
        expect(builder('https://zms.example.com:4443/zms/v1')).toBe(
            'zms-cli -z https://zms.example.com:4443/zms/v1 -d dom'
        );
        expect(
            resolveResourceOwnershipCliOnError(
                false,
                { body: { message: 'other' } },
                () => 'x'
            )
        ).toBeNull();
        expect(
            resolveResourceOwnershipCliOnError(
                false,
                { body: { message: 'Role has a resource owner: TF' } },
                () => 'y'
            )('https://zms.example.com:4443/zms/v1')
        ).toBe('y');
        expect(
            resolveResourceOwnershipCliOnError(true, {}, () => 'z', {
                when: false,
            })
        ).toBeNull();
    });

    it('resolveRoleDeleteResourceOwnershipCli builds delete-role command via builder', () => {
        const builder = resolveRoleDeleteResourceOwnershipCli(
            { objectOwner: 'terraform' },
            { body: { message: 'Role has a resource owner: terraform' } },
            'my.domain',
            'readers',
            'audit-ref'
        );
        const cmd = builder('https://zms.example.com:4443/zms/v1');
        expect(cmd).toContain('delete-role');
        expect(cmd).toContain('readers');
        expect(cmd).toContain('-r ignore');
        expect(cmd).toContain("-z 'https://zms.example.com:4443/zms/v1'");
    });

    it('errorMessageSuggestsResourceOwnership matches ZMS ownership phrases', () => {
        expect(
            errorMessageSuggestsResourceOwnership({
                body: { message: 'Role has a resource owner: TF' },
            })
        ).toBe(true);
        expect(
            errorMessageSuggestsResourceOwnership({
                body: {
                    message:
                        'Invalid resource owner for object: TF vs. unittest',
                },
            })
        ).toBe(true);
        expect(
            errorMessageSuggestsResourceOwnership({
                body: { message: 'Policy has a resource owner: TF' },
            })
        ).toBe(true);
        expect(
            errorMessageSuggestsResourceOwnership({
                body: { message: 'Invalid members owner for role: readers' },
            })
        ).toBe(true);
        expect(
            errorMessageSuggestsResourceOwnership({
                body: { message: 'Unknown owner domain for principal' },
            })
        ).toBe(false);
        expect(
            errorMessageSuggestsResourceOwnership({
                body: { message: 'Something else' },
            })
        ).toBe(false);
    });
});
