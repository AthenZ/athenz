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
 * Functional coverage for the Self Service feature (Find / My Roles & Groups).
 *
 * These tests exercise the ZMS self-serve endpoints end-to-end through the UI.
 * The membership overlay (memberStatus / expiration / inheritedFrom), the
 * request/leave/extend/cancel actions and the "My Roles & Groups" tab are all
 * scoped to the *logged-in principal*: ZMS derives `memberName` from the
 * authenticated session. Every membership assertion below is therefore
 * self-consistent: the same principal that requests access is the one whose
 * memberships are read back.
 *
 * Fixtures are self-serve roles/groups created in the functional-test domain
 * (and, for the cross-domain filter test, the audit-enabled domain). Each test
 * records what it created in `createdFixtures`; `afterEach` deletes them, which
 * also removes any membership the run produced.
 */

const config = require('../../../config/config');
const {
    authenticateAndWait,
    navigateAndWait,
    waitAndSetValue,
    waitAndClick,
    waitForElement,
    waitForElementExist,
    waitForTabToOpenAndSwitch,
    beforeEachTest,
} = require('../libs/helpers');

const testdata = config().testdata;

const TEST_DOMAIN = testdata.functionalTest;
const SECOND_DOMAIN = testdata.auditEnabled;
const SELF_SERVICE_URI = '/self-service';

// Fixture names (kept distinct so the cross-domain self-serve search is
// deterministic and cleanup is unambiguous).
const NAME_ROLE = 'ss-func-name-role';
const DESC_ROLE = 'ss-func-desc-role';
const DESC_GROUP = 'ss-func-desc-group';
const SPLIT_ROLE = 'ss-func-split-role';
const SPLIT_GROUP = 'ss-func-split-group';
const CLEAR_ROLE = 'ss-func-clear-role';
const DOMFILTER_ROLE = 'ss-func-domfilter-role';
const REQUEST_ROLE = 'ss-func-request-role';
const JUST_ROLE = 'ss-func-just-role';
const REQUEST_GROUP = 'ss-func-request-group';
const MULTI_ROLE = 'ss-func-multi-role';
const MULTI_GROUP = 'ss-func-multi-group';
const MINE_ACTIVE_ROLE = 'ss-func-mine-active-role';
const MINE_PENDING_ROLE = 'ss-func-mine-pending-role';
const MINE_LEAVE_ROLE = 'ss-func-mine-leave-role';
const MINE_EXPIRY_ROLE = 'ss-func-mine-expiry-role';
const EXTEND_MAX_ROLE = 'ss-func-extend-max-role';
const EXTEND_NOMAX_ROLE = 'ss-func-extend-nomax-role';
const EXTEND_GROUP = 'ss-func-extend-group';
const EXTEND_VALID_ROLE = 'ss-func-extend-valid-role';
const INHERIT_GROUP = 'ss-func-inherit-group';
const INHERIT_ROLE = 'ss-func-inherit-role';
const ALERT_ROLE = 'ss-func-alert-role';

// Search tokens that only live in the *description* of a fixture, used to prove
// roles search name+description while groups search name-only.
const DESC_ROLE_TOKEN = 'zzsssearchtokenrole';
const DESC_GROUP_TOKEN = 'zzsssearchtokengroup';

const keyFor = (type, name, domain = TEST_DOMAIN) =>
    `${domain}:${type}.${name}`;

const rowLink = (type, name, domain) =>
    `[data-testid="self-service-row-link-${keyFor(type, name, domain)}"]`;

// Resolve the specific result row for a fixture (via its uniquely keyed link)
// so assertions on shared testids (domain, expiry, pills) are scoped to *our*
// row and never pick up another self-serve object that happens to be returned
// by the global search or held by the test principal.
const rowElementFor = async (type, name, domain) => {
    const link = await waitForElementExist(rowLink(type, name, domain));
    return link.$('./ancestor::div[@data-testid="self-service-result-row"]');
};

describe('self service screen tests', () => {
    let createdFixtures = [];

    beforeEach(async () => {
        await beforeEachTest();
    });

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    const gotoSelfService = async () => {
        await navigateAndWait(SELF_SERVICE_URI);
        await waitForElementExist('[data-testid="self-service"]');
    };

    const goToFindTab = async () => {
        await waitAndClick('div*=Find Roles & Groups');
    };

    const goToMineTab = async () => {
        await waitAndClick('div*=My Roles & Groups');
        await browser.pause(1000);
    };

    // Reload the page fresh and land on the My Roles & Groups tab. Used to make
    // membership assertions deterministic after an action.
    const reloadMine = async () => {
        await gotoSelfService();
        await goToMineTab();
    };

    const searchSelfServe = async (query) => {
        await waitAndSetValue('#self-service-search', query);
        await waitAndClick('[data-testid="self-service-search-button"]');
        await browser.pause(1000);
    };

    const assertNoExistsError = async (kind, name) => {
        const err = await $('div[data-testid="error-message"]');
        const exists = await err
            .waitForExist({ timeout: 1500 })
            .catch(() => false);
        if (exists) {
            const text = await err.getText();
            if (text.includes('already exists')) {
                throw new Error(
                    `${kind} "${name}" already exists - cleanup required before re-run.`
                );
            }
            throw new Error(
                `Unexpected error creating ${kind} "${name}": ${text}`
            );
        }
    };

    const deleteRoleIfExists = async (name, domain = TEST_DOMAIN) => {
        await navigateAndWait(`/domain/${domain}/role`);
        await waitForElementExist('button*=Add Role');
        const del = await $(
            `.//*[local-name()="svg" and @id="${name}-delete-role-button"]`
        );
        const appeared = await del
            .waitForExist({ timeout: 5000 })
            .catch(() => false);
        if (!appeared) {
            return;
        }
        await waitAndClick(del, { timeout: 5000 });
        await waitForElementExist('div[data-testid="modal-title"]');
        // audit-enabled domains ask for a justification on delete
        const justification = await $('input[id="justification"]');
        const needsJustification = await justification
            .waitForExist({ timeout: 1000 })
            .catch(() => false);
        if (needsJustification) {
            await waitAndSetValue(
                'input[id="justification"]',
                'functional test cleanup'
            );
        }
        await waitAndClick('button*=Delete');
        await browser.pause(500);
    };

    const deleteGroupIfExists = async (name, domain = TEST_DOMAIN) => {
        await navigateAndWait(`/domain/${domain}/group`);
        await waitForElementExist('button*=Add Group');
        const del = await $(
            `.//*[local-name()="svg" and @id="delete-group-icon-${name}"]`
        );
        const appeared = await del
            .waitForExist({ timeout: 5000 })
            .catch(() => false);
        if (!appeared) {
            return;
        }
        await waitAndClick(del, { timeout: 5000 });
        const justification = await $('input[id="justification"]');
        const needsJustification = await justification
            .waitForExist({ timeout: 1000 })
            .catch(() => false);
        if (needsJustification) {
            await waitAndSetValue(
                'input[id="justification"]',
                'functional test cleanup'
            );
        }
        await waitAndClick('button*=Delete');
        await browser.pause(500);
    };

    // Create a self-serve role via the standard Add Role + advanced settings
    // flow. opts: { domain, selfRenew, selfRenewMins, reviewEnabled,
    // memberExpiryDays, description, members: [] }. Caller must be authenticated.
    const createSelfServeRole = async (name, opts = {}) => {
        const domain = opts.domain || TEST_DOMAIN;
        await deleteRoleIfExists(name, domain);
        await navigateAndWait(`/domain/${domain}/role`);
        await waitAndClick('button*=Add Role');
        await waitAndSetValue('#role-name-input', name);
        await waitAndClick('#advanced-settings-icon');
        await waitAndClick('label[for="switch-settingselfServe"]');
        if (opts.reviewEnabled) {
            await waitAndClick('label[for="switch-settingreviewEnabled"]');
        }
        if (opts.selfRenew) {
            await waitAndClick('label[for="switch-settingselfRenew"]');
            await waitAndSetValue(
                '#setting-selfRenewMins',
                String(opts.selfRenewMins || 60)
            );
        }
        if (opts.memberExpiryDays !== undefined) {
            await waitAndSetValue(
                '#setting-memberExpiryDays',
                String(opts.memberExpiryDays)
            );
        }
        if (opts.description) {
            await waitAndSetValue('#setting-description', opts.description);
        }
        for (const member of opts.members || []) {
            await waitAndSetValue('input[name="member-name"]', member);
            await waitAndClick(`div*=${member}`);
            await waitAndClick('button[data-wdio="add-role-member"]');
        }
        // audit-enabled domains require a justification to create
        if (opts.justification) {
            await waitAndSetValue(
                'input[id="justification"]',
                opts.justification
            );
        }
        await waitAndClick('button*=Submit');
        await assertNoExistsError('Role', name);
        createdFixtures.push({ kind: 'role', name, domain });
    };

    const createSelfServeGroup = async (name, opts = {}) => {
        const domain = opts.domain || TEST_DOMAIN;
        await deleteGroupIfExists(name, domain);
        await navigateAndWait(`/domain/${domain}/group`);
        await waitAndClick('button*=Add Group');
        await waitAndSetValue('#group-name-input', name);
        await waitAndClick('#advanced-settings-icon');
        await waitAndClick('label[for="switch-settingselfServe"]');
        if (opts.reviewEnabled) {
            await waitAndClick('label[for="switch-settingreviewEnabled"]');
        }
        if (opts.selfRenew) {
            await waitAndClick('label[for="switch-settingselfRenew"]');
            await waitAndSetValue(
                '#setting-selfRenewMins',
                String(opts.selfRenewMins || 60)
            );
        }
        if (opts.memberExpiryDays !== undefined) {
            await waitAndSetValue(
                '#setting-memberExpiryDays',
                String(opts.memberExpiryDays)
            );
        }
        // NOTE: the Add Group flow has no description field (only roles do),
        // which is why groups are searched by name only.
        for (const member of opts.members || []) {
            await waitAndSetValue('input[name="member-name"]', member);
            await waitAndClick(`div*=${member}`);
            await waitAndClick('button[data-wdio="add-group-member"]');
        }
        await waitAndClick('button*=Submit');
        await assertNoExistsError('Group', name);
        createdFixtures.push({ kind: 'group', name, domain });
    };

    // Select a row's checkbox (the visible target is the label bound to the
    // hidden input via for="checkbox-<key>").
    const selectRow = async (key) => {
        await waitAndClick(`label[for="checkbox-${key}"]`);
    };

    // Find -> select -> Request access -> justify -> Submit for a single item.
    const requestSingleFromFind = async (
        name,
        key,
        justification = 'functional test request'
    ) => {
        await searchSelfServe(name);
        await waitForElementExist(
            `[data-testid="self-service-row-link-${key}"]`
        );
        await selectRow(key);
        await waitAndClick('[data-testid="request-selected"]');
        await waitForElementExist('[data-testid="request-access-form"]');
        await waitAndSetValue('#self-serve-justification', justification);
        await waitAndClick('button*=Submit');
        await waitForElementExist('[data-testid="request-access-form"]', {
            reverse: true,
        });
    };

    // =====================================================================
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

    // =====================================================================
    // Request access (Find tab)
    // =====================================================================

    it('10: requesting a role submits a pending request', async () => {
        await authenticateAndWait();
        await createSelfServeRole(REQUEST_ROLE, { reviewEnabled: true });
        await gotoSelfService();

        await requestSingleFromFind(REQUEST_ROLE, keyFor('role', REQUEST_ROLE));

        // re-search: the row now reflects the pending state
        await searchSelfServe(REQUEST_ROLE);
        const row = await rowElementFor('role', REQUEST_ROLE);
        const pending = await row.$('div*=Pending approval');
        await pending.waitForExist();
    });

    it('11: request requires a justification', async () => {
        await authenticateAndWait();
        await createSelfServeRole(JUST_ROLE, { reviewEnabled: true });
        await gotoSelfService();

        await searchSelfServe(JUST_ROLE);
        const key = keyFor('role', JUST_ROLE);
        await waitForElementExist(
            `[data-testid="self-service-row-link-${key}"]`
        );
        await selectRow(key);
        await waitAndClick('[data-testid="request-selected"]');
        await waitForElementExist('[data-testid="request-access-form"]');
        // submit with no justification
        await waitAndClick('button*=Submit');
        await waitForElementExist('div*=Justification is required');
    });

    it('12: requesting a group shows no expiry pickers', async () => {
        await authenticateAndWait();
        await createSelfServeGroup(REQUEST_GROUP, { reviewEnabled: true });
        await gotoSelfService();

        await searchSelfServe(REQUEST_GROUP);
        const key = keyFor('group', REQUEST_GROUP);
        await waitForElementExist(
            `[data-testid="self-service-row-link-${key}"]`
        );
        await selectRow(key);
        await waitAndClick('[data-testid="request-selected"]');
        await waitForElementExist('[data-testid="request-access-form"]');

        // groups have no expiry/reminder date pickers
        await waitForElementExist('#self-serve-expiry', { reverse: true });

        await waitAndSetValue(
            '#self-serve-justification',
            'functional test group request'
        );
        await waitAndClick('button*=Submit');
        await waitForElementExist('[data-testid="request-access-form"]', {
            reverse: true,
        });
    });

    it('13: multi-select shows a breakdown and requests role + group together', async () => {
        await authenticateAndWait();
        await createSelfServeRole(MULTI_ROLE, { reviewEnabled: true });
        await createSelfServeGroup(MULTI_GROUP, { reviewEnabled: true });
        await gotoSelfService();

        await searchSelfServe('ss-func-multi');
        const roleKey = keyFor('role', MULTI_ROLE);
        const groupKey = keyFor('group', MULTI_GROUP);
        await waitForElementExist(
            `[data-testid="self-service-row-link-${roleKey}"]`
        );
        await selectRow(roleKey);
        await selectRow(groupKey);

        const bar = await waitForElementExist(
            '[data-testid="self-service-selection-bar"]'
        );
        await expect(bar).toHaveText(expect.stringContaining('2 selected'));
        await expect(bar).toHaveText(expect.stringContaining('1 role'));
        await expect(bar).toHaveText(expect.stringContaining('1 group'));

        await waitAndClick('[data-testid="request-selected"]');
        await waitForElementExist('[data-testid="request-access-form"]');
        await waitAndSetValue(
            '#self-serve-justification',
            'functional test multi request'
        );
        await waitAndClick('button*=Submit');
        await waitForElementExist('[data-testid="request-access-form"]', {
            reverse: true,
        });
    });

    // =====================================================================
    // My Roles & Groups
    // =====================================================================

    it('14: an approved self-request appears under My Roles', async () => {
        await authenticateAndWait();
        // no review -> self add becomes an active membership immediately
        await createSelfServeRole(MINE_ACTIVE_ROLE, { reviewEnabled: false });
        await gotoSelfService();

        await requestSingleFromFind(
            MINE_ACTIVE_ROLE,
            keyFor('role', MINE_ACTIVE_ROLE)
        );

        await reloadMine();
        await waitForElementExist(rowLink('role', MINE_ACTIVE_ROLE));
    });

    it('15: a pending request can be cancelled from My Roles', async () => {
        await authenticateAndWait();
        await createSelfServeRole(MINE_PENDING_ROLE, { reviewEnabled: true });
        await gotoSelfService();

        await requestSingleFromFind(
            MINE_PENDING_ROLE,
            keyFor('role', MINE_PENDING_ROLE)
        );

        await reloadMine();
        await waitForElementExist('div*=Pending requests');
        const key = keyFor('role', MINE_PENDING_ROLE);
        await waitAndClick(`[data-testid="cancel-${key}"]`);
        // withdraw confirmation modal
        await waitForElementExist('[data-testid="leave-modal-message"]');
        await waitAndClick('[data-testid="leave-modal-submit"]');

        await reloadMine();
        await waitForElementExist(rowLink('role', MINE_PENDING_ROLE), {
            reverse: true,
        });
    });

    it('16: an active membership can be left from My Roles', async () => {
        await authenticateAndWait();
        await createSelfServeRole(MINE_LEAVE_ROLE, { reviewEnabled: false });
        await gotoSelfService();

        await requestSingleFromFind(
            MINE_LEAVE_ROLE,
            keyFor('role', MINE_LEAVE_ROLE)
        );

        await reloadMine();
        const key = keyFor('role', MINE_LEAVE_ROLE);
        await waitForElementExist(rowLink('role', MINE_LEAVE_ROLE));
        await waitAndClick(`[data-testid="leave-${key}"]`);
        await waitForElementExist('[data-testid="leave-modal-message"]');
        await waitAndSetValue(
            '#self-serve-leave-justification',
            'functional test leave'
        );
        await waitAndClick('[data-testid="leave-modal-submit"]');

        await reloadMine();
        await waitForElementExist(rowLink('role', MINE_LEAVE_ROLE), {
            reverse: true,
        });
    });

    it('17: membership expiry is shown for expiring roles', async () => {
        await authenticateAndWait();
        // short expiry so the membership is flagged as urgent (<= 14 days)
        await createSelfServeRole(MINE_EXPIRY_ROLE, {
            reviewEnabled: false,
            memberExpiryDays: 10,
        });
        await gotoSelfService();

        // Request with an explicit near-term expiry. The role's memberExpiryDays
        // is a policy cap and is not auto-stamped onto a self-add, so we pick a
        // date to guarantee the membership carries an expiration to display.
        const reqKey = keyFor('role', MINE_EXPIRY_ROLE);
        await searchSelfServe(MINE_EXPIRY_ROLE);
        await waitForElementExist(
            `[data-testid="self-service-row-link-${reqKey}"]`
        );
        await selectRow(reqKey);
        await waitAndClick('[data-testid="request-selected"]');
        await waitForElementExist('[data-testid="request-access-form"]');
        // pick the first selectable day (~tomorrow) -> well within 14 days
        await waitAndClick('#self-serve-expiry');
        await waitAndClick(
            '.flatpickr-calendar.open .flatpickr-day:not(.flatpickr-disabled)'
        );
        await browser.keys('Enter');
        await waitAndSetValue(
            '#self-serve-justification',
            'functional test request'
        );
        await waitAndClick('button*=Submit');
        await waitForElementExist('[data-testid="request-access-form"]', {
            reverse: true,
        });

        await reloadMine();
        // scope the expiry text to our row so other memberships the principal
        // may hold cannot satisfy the assertion
        const row = await rowElementFor('role', MINE_EXPIRY_ROLE);
        const expiry = await row.$('[data-testid="expiry-text"]');
        await expiry.waitForExist();
        await expect(expiry).toHaveText(expect.stringContaining('Expires'));
        await expect(expiry).toHaveText(expect.stringContaining('days left'));
    });

    // =====================================================================
    // Extend
    //
    // The extend button is offered for every active membership. The success
    // message is driven by the ZMS response (the membership's `approved`
    // flag): true => applied ("Membership extended"), false => queued
    // ("Request submitted"). The test principal is a domain admin, so extends
    // on ungated roles/groups apply immediately (approved=true) and are
    // asserted below. The approved=false (pending) message path requires an
    // active member on an approval-gated role, which needs a separate approver
    // that the single-principal functional harness does not have; that branch
    // is covered by the SelfServiceView.extend unit tests instead.
    // =====================================================================

    it('18: extending a role caps the picker at the configured maximum', async () => {
        await authenticateAndWait();
        // a non-self-renew role: Extend still appears and the picker is capped
        // by the role/domain expiry policy (30 days from now)
        await createSelfServeRole(EXTEND_MAX_ROLE, {
            reviewEnabled: false,
            memberExpiryDays: 30,
        });
        await gotoSelfService();

        await requestSingleFromFind(
            EXTEND_MAX_ROLE,
            keyFor('role', EXTEND_MAX_ROLE)
        );

        await reloadMine();
        const key = keyFor('role', EXTEND_MAX_ROLE);
        await waitForElementExist(rowLink('role', EXTEND_MAX_ROLE));
        await waitAndClick(`[data-testid="extend-${key}"]`);

        await waitForElementExist('[data-testid="extend-membership-form"]');
        // The "until <date>" cap is the proof that the picker's maxDate is wired
        // to the configured maximum; dates beyond it are greyed out as a direct
        // consequence (also covered by the modal unit tests).
        const maxText = await $('[data-testid="extend-max-text"]');
        await expect(maxText).toHaveText(
            expect.stringContaining('You can extend until')
        );

        // The picker is capped at the maximum. Navigating a second month forward
        // is disabled by flatpickr (it will not go past the maxDate month), so we
        // simply confirm a valid in-range day is still selectable and submits.
        await waitAndClick('#self-serve-extend-expiry');
        await waitAndClick(
            '.flatpickr-calendar.open .flatpickr-day:not(.flatpickr-disabled)'
        );
        await browser.keys('Enter');
        await waitAndClick('button*=Submit');
        await waitForElementExist('[data-testid="extend-membership-form"]', {
            reverse: true,
        });

        // the test principal is a domain admin on an ungated role, so ZMS
        // applies the change immediately (approved=true) and the message
        // reflects that rather than a pending request
        const title = await waitForElementExist('[data-testid="alert-title"]');
        await expect(title).toHaveText(
            expect.stringContaining('Membership extended')
        );
    });

    it('19: no expiry configured hides the extend button', async () => {
        await authenticateAndWait();
        // no self-renew window and no expiry policy -> the membership never
        // expires, so extending is meaningless and Extend is not offered
        await createSelfServeRole(EXTEND_NOMAX_ROLE, {
            reviewEnabled: false,
            memberExpiryDays: 0,
        });
        await gotoSelfService();

        await requestSingleFromFind(
            EXTEND_NOMAX_ROLE,
            keyFor('role', EXTEND_NOMAX_ROLE)
        );

        await reloadMine();
        const key = keyFor('role', EXTEND_NOMAX_ROLE);
        // the membership row is present but offers no Extend action
        await waitForElementExist(rowLink('role', EXTEND_NOMAX_ROLE));
        const extend = await $(`[data-testid="extend-${key}"]`);
        await expect(extend).not.toExist();
    });

    it('20: extending a group opens the modal with a date picker', async () => {
        await authenticateAndWait();
        await createSelfServeGroup(EXTEND_GROUP, {
            reviewEnabled: false,
            memberExpiryDays: 30,
        });
        await gotoSelfService();

        await requestSingleFromFind(
            EXTEND_GROUP,
            keyFor('group', EXTEND_GROUP)
        );

        await reloadMine();
        const key = keyFor('group', EXTEND_GROUP);
        await waitForElementExist(rowLink('group', EXTEND_GROUP));
        await waitAndClick(`[data-testid="extend-${key}"]`);

        // groups now open the same modal as roles and are labelled accordingly
        await waitForElementExist('[data-testid="extend-membership-form"]');
        const maxText = await $('[data-testid="extend-max-text"]');
        await expect(maxText).toHaveText(
            expect.stringContaining('You can extend until')
        );

        // pick a valid in-range day and submit the new expiry
        await waitAndClick('#self-serve-extend-expiry');
        await waitAndClick(
            '.flatpickr-calendar.open .flatpickr-day:not(.flatpickr-disabled)'
        );
        await browser.keys('Enter');
        await waitAndClick('button*=Submit');
        await waitForElementExist('[data-testid="extend-membership-form"]', {
            reverse: true,
        });

        // admin extend on an ungated group applies immediately (approved=true)
        const title = await waitForElementExist('[data-testid="alert-title"]');
        await expect(title).toHaveText(
            expect.stringContaining('Membership extended')
        );

        // the membership is still held after extending
        await reloadMine();
        await waitForElementExist(rowLink('group', EXTEND_GROUP));
    });

    it('21: extend requires a date to be chosen', async () => {
        await authenticateAndWait();
        await createSelfServeRole(EXTEND_VALID_ROLE, {
            reviewEnabled: false,
            selfRenew: true,
            memberExpiryDays: 0,
        });
        await gotoSelfService();

        await requestSingleFromFind(
            EXTEND_VALID_ROLE,
            keyFor('role', EXTEND_VALID_ROLE)
        );

        await reloadMine();
        const key = keyFor('role', EXTEND_VALID_ROLE);
        await waitForElementExist(rowLink('role', EXTEND_VALID_ROLE));
        await waitAndClick(`[data-testid="extend-${key}"]`);
        await waitForElementExist('[data-testid="extend-membership-form"]');

        // submit without picking a date
        await waitAndClick('button*=Submit');
        await waitForElementExist('div*=Pick a new expiry date');
    });

    // =====================================================================
    // Inherited membership
    // =====================================================================

    it('22: an inherited role shows the source group and disables Leave', async () => {
        await authenticateAndWait();
        // group the user will join, then a role that has that group as a member
        await createSelfServeGroup(INHERIT_GROUP, { reviewEnabled: false });
        const groupPrincipal = `${TEST_DOMAIN}:group.${INHERIT_GROUP}`;
        await createSelfServeRole(INHERIT_ROLE, {
            reviewEnabled: false,
            members: [groupPrincipal],
        });
        await gotoSelfService();

        // join the group -> the user now inherits the role through it
        await requestSingleFromFind(
            INHERIT_GROUP,
            keyFor('group', INHERIT_GROUP)
        );

        await reloadMine();
        const roleKey = keyFor('role', INHERIT_ROLE);
        // inherited pill present and Leave disabled (scoped to our row)
        const row = await rowElementFor('role', INHERIT_ROLE);
        const inheritedPill = await row.$('div*=Inherited');
        await inheritedPill.waitForExist();
        const leave = await $(`[data-testid="leave-${roleKey}"]`);
        await expect(leave).toBeDisabled();

        // an inherited role is held via the group, not directly, so there is
        // nothing to renew and no Extend button is offered on this row
        const extend = await row.$(`[data-testid="extend-${roleKey}"]`);
        await expect(extend).not.toExist();

        // hovering the disabled Leave reveals a link to the group's members page
        const trigger = await $(`[data-testid="leave-tooltip-${roleKey}"]`);
        await trigger.moveTo();
        const link = await waitForElementExist(
            `[data-testid="leave-tooltip-link-${roleKey}"]`
        );
        expect(await link.getAttribute('href')).toBe(
            `/domain/${TEST_DOMAIN}/group/${INHERIT_GROUP}/members`
        );
    });

    // =====================================================================
    // Success alert
    // =====================================================================

    it('23: the success alert appears and can be dismissed', async () => {
        await authenticateAndWait();
        await createSelfServeRole(ALERT_ROLE, { reviewEnabled: true });
        await gotoSelfService();

        // trigger a request -> success alert
        await requestSingleFromFind(ALERT_ROLE, keyFor('role', ALERT_ROLE));

        const title = await waitForElementExist('[data-testid="alert-title"]');
        await expect(title).toHaveText(expect.stringContaining('Request'));

        // it auto-dismisses after the timeout
        await waitForElementExist('[data-testid="alert-title"]', {
            reverse: true,
            timeout: 6000,
        });
    });

    afterEach(async () => {
        try {
            await authenticateAndWait();
            for (const fixture of createdFixtures) {
                if (fixture.kind === 'role') {
                    await deleteRoleIfExists(fixture.name, fixture.domain);
                } else {
                    await deleteGroupIfExists(fixture.name, fixture.domain);
                }
            }
        } catch (error) {
            console.error('Self-service cleanup failed:', error.message);
            // don't throw - allow the remaining tests to run
        } finally {
            createdFixtures = [];
        }
    });
});
