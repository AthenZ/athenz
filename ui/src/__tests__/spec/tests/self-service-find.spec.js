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

/*
 * Functional coverage for the Self Service feature: page load, Find search,
 * result sections and the domain filter (tests 1-9).
 *
 * See libs/self-service-helpers.js for the shared fixtures/helpers and the
 * reason the self-service coverage is split across several spec files.
 */

const {
    authenticateAndWait,
    waitAndSetValue,
    waitAndClick,
    waitForElement,
    waitForElementExist,
    waitForTabToOpenAndSwitch,
    beforeEachTest,
} = require('../libs/helpers');
const {
    TEST_DOMAIN,
    SECOND_DOMAIN,
    DESC_ROLE_TOKEN,
    DESC_GROUP_TOKEN,
    rowLink,
    rowElementFor,
    gotoSelfService,
    searchSelfServe,
    createSelfServiceHarness,
} = require('../libs/self-service-helpers');

// Fixture names (kept distinct so the cross-domain self-serve search is
// deterministic and cleanup is unambiguous).
const NAME_ROLE = 'ss-func-name-role';
const DESC_ROLE = 'ss-func-desc-role';
const DESC_GROUP = 'ss-func-desc-group';
const SPLIT_ROLE = 'ss-func-split-role';
const SPLIT_GROUP = 'ss-func-split-group';
const CLEAR_ROLE = 'ss-func-clear-role';
const DOMFILTER_ROLE = 'ss-func-domfilter-role';

describe('self service screen tests - find', () => {
    const { createSelfServeRole, createSelfServeGroup, cleanup } =
        createSelfServiceHarness();

    beforeEach(async () => {
        await beforeEachTest();
    });

    // Page & tabs
    // =====================================================================

    it('1: page loads with Find tab, search prompt and a My Roles tab count', async () => {
        await authenticateAndWait();
        await gotoSelfService();

        await waitForElementExist('[data-testid="self-service-search-bar"]');
        await waitForElementExist('div*=Find Roles & Groups');
        await waitForElementExist('div*=My Roles & Groups');
        // initial Find empty-state prompt
        await waitForElementExist(
            'div*=Search by name or description to find self-service'
        );
    });

    // =====================================================================
    // Find / search
    // =====================================================================

    it('2: search by name returns the role with domain and link (new tab)', async () => {
        await authenticateAndWait();
        await createSelfServeRole(NAME_ROLE, {
            description: 'self service functional name role',
        });
        await gotoSelfService();

        await searchSelfServe(NAME_ROLE);

        const link = await waitForElementExist(rowLink('role', NAME_ROLE));
        expect(await link.getAttribute('href')).toBe(
            `/domain/${TEST_DOMAIN}/role/${NAME_ROLE}/members`
        );
        expect(await link.getAttribute('target')).toBe('_blank');
        expect(await link.getAttribute('rel')).toBe('noopener noreferrer');

        // domain shown directly under the name (scoped to our row)
        const row = await rowElementFor('role', NAME_ROLE);
        const domain = await row.$('[data-testid="self-service-row-domain"]');
        await expect(domain).toHaveText(expect.stringContaining(TEST_DOMAIN));

        // clicking opens the members page in a new tab
        const original = await browser.getWindowHandle();
        await waitAndClick(rowLink('role', NAME_ROLE));
        await waitForTabToOpenAndSwitch();
        await expect(browser).toHaveUrl(
            expect.stringContaining(`/role/${NAME_ROLE}/members`)
        );
        await browser.closeWindow();
        await browser.switchToWindow(original);
    });

    it('3: search matches a role by its description', async () => {
        await authenticateAndWait();
        await createSelfServeRole(DESC_ROLE, {
            description: `functional ${DESC_ROLE_TOKEN} description`,
        });
        await gotoSelfService();

        await searchSelfServe(DESC_ROLE_TOKEN);
        await waitForElementExist(rowLink('role', DESC_ROLE));
    });

    it('4: groups are matched by name (name-only search)', async () => {
        // Groups have no description in the UI, so group search is name-only.
        // (Proving the description negative would require seeding a group
        // description via the ZMS API, which is out of scope for a UI test.)
        await authenticateAndWait();
        await createSelfServeGroup(DESC_GROUP, {});
        await gotoSelfService();

        // a token that is not part of the group name must not match
        await searchSelfServe(DESC_GROUP_TOKEN);
        await waitForElementExist(rowLink('group', DESC_GROUP), {
            reverse: true,
        });

        // searching by (part of) the name returns it
        await searchSelfServe('ss-func-desc-group');
        await waitForElementExist(rowLink('group', DESC_GROUP));
    });

    it('5: results split into Roles and Groups sections by type', async () => {
        await authenticateAndWait();
        await createSelfServeRole(SPLIT_ROLE, {});
        await createSelfServeGroup(SPLIT_GROUP, {});
        await gotoSelfService();

        await searchSelfServe('ss-func-split');

        const role = await waitForElementExist(rowLink('role', SPLIT_ROLE));
        const group = await waitForElementExist(rowLink('group', SPLIT_GROUP));
        expect(await role.getAttribute('href')).toBe(
            `/domain/${TEST_DOMAIN}/role/${SPLIT_ROLE}/members`
        );
        expect(await group.getAttribute('href')).toBe(
            `/domain/${TEST_DOMAIN}/group/${SPLIT_GROUP}/members`
        );
    });

    it('6: shows the empty state when nothing matches', async () => {
        await authenticateAndWait();
        await gotoSelfService();

        await searchSelfServe('ss-func-nonexistent-zzz-nomatch');
        await waitForElementExist('div*=No self-service roles or groups match');
    });

    // =====================================================================
    // Domain filter
    // =====================================================================

    it('7: domain filter defaults to All domains before searching', async () => {
        await authenticateAndWait();
        await gotoSelfService();

        const dropdown = await $('input[name="self-service-domain"]');
        await waitForElement(dropdown);
        expect(await dropdown.getValue()).toBe('All domains');
    });

    it('8: selecting a domain narrows results across domains', async () => {
        await authenticateAndWait();
        await createSelfServeRole(DOMFILTER_ROLE, { domain: TEST_DOMAIN });
        await createSelfServeRole(DOMFILTER_ROLE, {
            domain: SECOND_DOMAIN,
            justification: 'functional test domain filter',
        });
        await gotoSelfService();

        await searchSelfServe(DOMFILTER_ROLE);
        // both domains present
        await waitForElementExist(rowLink('role', DOMFILTER_ROLE, TEST_DOMAIN));
        await waitForElementExist(
            rowLink('role', DOMFILTER_ROLE, SECOND_DOMAIN)
        );

        // choose the functional-test domain in the dropdown. Scope to the
        // dropdown option (.dropdown-item) so we don't accidentally click the
        // identical domain text rendered under a result row.
        await waitAndClick('input[name="self-service-domain"]');
        await waitAndClick(`.dropdown-item*=${TEST_DOMAIN}`);
        await browser.pause(500);

        // only the functional-test row remains
        await waitForElementExist(rowLink('role', DOMFILTER_ROLE, TEST_DOMAIN));
        await waitForElementExist(
            rowLink('role', DOMFILTER_ROLE, SECOND_DOMAIN),
            { reverse: true }
        );
    });

    it('9: clearing the query resets results and the domain filter', async () => {
        await authenticateAndWait();
        await createSelfServeRole(CLEAR_ROLE, {});
        await gotoSelfService();

        await searchSelfServe(CLEAR_ROLE);
        await waitForElementExist(rowLink('role', CLEAR_ROLE));

        // Empty the query. setValue('') does not reliably fire React's onChange
        // on a controlled input, so type a character and delete it to guarantee
        // state.query is emptied before submitting.
        const searchInput = await $('#self-service-search');
        await waitAndSetValue(searchInput, 'x');
        await searchInput.click();
        await browser.keys('Backspace');
        await waitAndClick('[data-testid="self-service-search-button"]');
        await browser.pause(500);

        await waitForElementExist('[data-testid="self-service-result-row"]', {
            reverse: true,
        });
        await waitForElementExist(
            'div*=Search by name or description to find self-service'
        );
        const dropdown = await $('input[name="self-service-domain"]');
        expect(await dropdown.getValue()).toBe('All domains');
    });

    afterEach(async () => {
        await cleanup();
    });
});
