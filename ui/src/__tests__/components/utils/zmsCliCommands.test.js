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
    cliAddAssertion,
    cliDeleteRole,
    cliRoleMetaDiff,
    formatAssertionWords,
    shellQuote,
    ZMS_CLI_RESOURCE_OWNER_FLAG,
} from '../../../components/utils/zmsCliCommands';

const DOMAIN = 'my.domain';
const ROLE = 'my-role';
const RUNTIME_ZMS = 'https://zms.example.com:4443/zms/v1';

describe('shellQuote', () => {
    it('returns empty string for null and undefined', () => {
        expect(shellQuote(null)).toBe('');
        expect(shellQuote(undefined)).toBe('');
    });

    it('leaves simple tokens unquoted', () => {
        expect(shellQuote('my.domain')).toBe('my.domain');
        expect(shellQuote('my-role')).toBe('my-role');
        expect(shellQuote('user.john')).toBe('user.john');
    });

    it('single-quotes values with spaces or special characters', () => {
        expect(shellQuote('audit ref')).toBe("'audit ref'");
        expect(shellQuote('https://zms.example.com:4443/zms/v1')).toBe(
            "'https://zms.example.com:4443/zms/v1'"
        );
        expect(shellQuote('contains "quotes"')).toBe('\'contains "quotes"\'');
        expect(shellQuote("it's fine")).toBe("'it'\\''s fine'");
        expect(shellQuote('$(touch /tmp/poc)')).toBe("'$(touch /tmp/poc)'");
    });
});

describe('zmsCliCommands', () => {
    it('includes -z when runtime ZMS URL is passed', () => {
        const cmd = cliDeleteRole(
            'my.domain',
            'my-role',
            'audit-ref',
            RUNTIME_ZMS
        );
        expect(cmd).toContain(`-z '${RUNTIME_ZMS}'`);
        expect(cmd).toContain('-d my.domain');
        expect(cmd).toContain(`-r ${ZMS_CLI_RESOURCE_OWNER_FLAG}`);
        expect(cmd).toContain('delete-role my-role');
        expect(cmd).toContain('-a audit-ref');
    });

    it('omits -z when ZMS URL is not passed', () => {
        const cmd = cliDeleteRole('my.domain', 'my-role', null);
        expect(cmd).not.toContain(' -z ');
        expect(cmd).toMatch(/^zms-cli -d my\.domain/);
    });

    it('quotes assertion fields with shell metacharacters', () => {
        const words = formatAssertionWords(DOMAIN, {
            effect: 'ALLOW',
            action: 'read',
            role: `${DOMAIN}:role.writers`,
            resource: `${DOMAIN}:articles.*`,
        });
        expect(words).toBe("grant read to writers on 'articles.*'");
    });

    it('includes quoted assertion words in add-assertion command', () => {
        const words = formatAssertionWords(DOMAIN, {
            effect: 'ALLOW',
            action: 'read',
            role: `${DOMAIN}:role.writers`,
            resource: `${DOMAIN}:articles.*`,
        });
        const cmd = cliAddAssertion(
            DOMAIN,
            'writers_policy',
            words,
            null,
            false
        );
        expect(cmd).toContain(
            "add-assertion writers_policy grant read to writers on 'articles.*'"
        );
    });

    it('quotes role descriptions in set-role-description commands', () => {
        const cmd = cliRoleMetaDiff(
            DOMAIN,
            ROLE,
            { description: 'old' },
            { description: 'contains spaces' },
            'audit-ref'
        );
        expect(cmd).toContain("set-role-description my-role 'contains spaces'");
    });
});
