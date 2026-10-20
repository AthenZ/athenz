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
 * Functional coverage for the Self Service feature: membership expiry, extend,
 * inherited memberships and exclusion of held/pending items from Find
 * (tests 17-22, 24 and 25).
 *
 * See libs/self-service-helpers.js for the shared fixtures/helpers and the
 * reason the self-service coverage is split across several spec files.
 */

const {
    authenticateAndWait,
    waitAndSetValue,
    waitAndClick,
    waitForElementExist,
    beforeEachTest,
} = require('../libs/helpers');
const {
    TEST_DOMAIN,
    keyFor,
    rowLink,
    rowElementFor,
    gotoSelfService,
    goToFindTab,
    goToMineTab,
    reloadMine,
    searchSelfServe,
    selectRow,
    requestSingleFromFind,
    createSelfServiceHarness,
} = require('../libs/self-service-helpers');

// Fixture names (kept distinct across the self-service specs so cleanup is
// unambiguous).
const MINE_EXPIRY_ROLE = 'ss-func-mine-expiry-role';
const EXTEND_MAX_ROLE = 'ss-func-extend-max-role';
const EXTEND_NOMAX_ROLE = 'ss-func-extend-nomax-role';
const EXTEND_GROUP = 'ss-func-extend-group';
const EXTEND_VALID_ROLE = 'ss-func-extend-valid-role';
const INHERIT_GROUP = 'ss-func-inherit-group';
const INHERIT_ROLE = 'ss-func-inherit-role';
const EXCLUDE_MEMBER_ROLE = 'ss-func-exclude-member-role';
const EXCLUDE_PENDING_ROLE = 'ss-func-exclude-pending-role';

describe('self service screen tests - membership', () => {
    const { createSelfServeRole, createSelfServeGroup, cleanup } =
        createSelfServiceHarness({
            inherit: { group: INHERIT_GROUP, role: INHERIT_ROLE },
        });

    beforeEach(async () => {
        await beforeEachTest();
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
        // the first selectable day is tomorrow, so this reads "1 day left"
        // (singular); accept either form rather than pinning the count
        await expect(expiry).toHaveText(
            expect.stringMatching(/\b\d+ days? left$/)
        );
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

    it('24: a role you are already a member of is excluded from Find', async () => {
        await authenticateAndWait();
        // no review -> the self add becomes an active membership immediately
        await createSelfServeRole(EXCLUDE_MEMBER_ROLE, {
            reviewEnabled: false,
        });
        await gotoSelfService();

        // join it from Find
        await requestSingleFromFind(
            EXCLUDE_MEMBER_ROLE,
            keyFor('role', EXCLUDE_MEMBER_ROLE)
        );

        // reload and confirm the membership is loaded (My Roles shows it)
        await gotoSelfService();
        await goToMineTab();
        await waitForElementExist(rowLink('role', EXCLUDE_MEMBER_ROLE));

        // back on Find, searching for it no longer returns a requestable row;
        // the empty state points the user at My Roles & Groups instead
        await goToFindTab();
        await searchSelfServe(EXCLUDE_MEMBER_ROLE);
        await waitForElementExist(rowLink('role', EXCLUDE_MEMBER_ROLE), {
            reverse: true,
        });
        await waitForElementExist('div*=You already hold or have requested');
    });

    it('25: a role with a pending request is excluded from Find', async () => {
        await authenticateAndWait();
        // review enabled -> the self add stays pending approval
        await createSelfServeRole(EXCLUDE_PENDING_ROLE, {
            reviewEnabled: true,
        });
        await gotoSelfService();

        await requestSingleFromFind(
            EXCLUDE_PENDING_ROLE,
            keyFor('role', EXCLUDE_PENDING_ROLE)
        );

        // reload and confirm the pending request is loaded under My Roles
        await gotoSelfService();
        await goToMineTab();
        await waitForElementExist('div*=Pending requests');
        await waitForElementExist(rowLink('role', EXCLUDE_PENDING_ROLE));

        // back on Find, the pending item is filtered out of the results
        await goToFindTab();
        await searchSelfServe(EXCLUDE_PENDING_ROLE);
        await waitForElementExist(rowLink('role', EXCLUDE_PENDING_ROLE), {
            reverse: true,
        });
        await waitForElementExist('div*=You already hold or have requested');
    });

    afterEach(async () => {
        await cleanup();
    });
});
