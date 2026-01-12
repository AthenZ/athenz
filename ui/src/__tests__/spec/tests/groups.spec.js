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

const config = require('../../../config/config');
const {
    waitAndClick,
    waitAndSetValue,
    waitForElementExist,
    navigateAndWait,
    authenticateAndWait,
    beforeEachTest,
    closeAlert,
} = require('../libs/helpers');
const testdata = config().testdata;
const headlessUser = testdata.userHeadless1.id;
const headlessUserType = testdata.userHeadless1.type;
const humanUser = testdata.user1.id;
const humanUserType = testdata.user1.type;

const reviewExtendTest = 'review-extend-test';
const historyTestGroup = 'history-test-group';
const domainFilterTest = 'domain-filter-test';
const memberExpiryTest = 'member-expiry-test';
const advancedSettingsTest = 'advanced-settings-test';
const auditGroupTest = 'audit-group-test';

const TEST_DOMAIN = 'athenz.dev.functional-test';
const AUDIT_ENABLED_DOMAIN = 'avtest';

const GROUP_URI = `/domain/${TEST_DOMAIN}/group`;
const AUDIT_ENABLED_GROUP_URI = `/domain/${AUDIT_ENABLED_DOMAIN}/group`;

const TEST_NAME_GROUP_HISTORY_VISIBLE_AFTER_REFRESH =
    'group history should be visible when navigating to it and after page refresh';
const TEST_NAME_GROUP_ADD_USER_INPUT =
    'dropdown input for adding user during group creation - should preserve input on blur, make input bold when selected in dropdown, reject unselected input';
const TEST_NAME_GROUP_REVIEW_EXTEND =
    'Group Review - Extend radio button should be enabled only when Expiry/Review (Days) are set in settings';
const TEST_NAME_GROUP_DOMAIN_FILTER =
    'Domain Filter - only principals matching specific domain(s) can be added to a group';
const TEST_GROUP_MEMBER_EXPIRATION =
    'Group member with an expiration date can be added to a group';
const TEST_GROUP_ADVANCED_SETTINGS =
    'Advanced settings can be configured for the group';
const TEST_AUDIT_ENABLED_GROUP =
    'Audit enabled group should require approval when adding users';

describe('group screen tests:', () => {
    let currentTest;
    beforeEach(async () => {
        await beforeEachTest();
    });

    it(TEST_NAME_GROUP_HISTORY_VISIBLE_AFTER_REFRESH, async () => {
        currentTest = TEST_NAME_GROUP_HISTORY_VISIBLE_AFTER_REFRESH;
        // open browser
        await authenticateAndWait();
        await navigateAndWait(`/domain/${TEST_DOMAIN}/group`);

        // ADD test group
        await createGroup(historyTestGroup, headlessUser);

        // Verify history entry of added group member is present
        // open history
        await waitAndClick(
            `.//*[local-name()="svg" and @id="group-history-icon-${historyTestGroup}"]`
        );
        // find row with 'ADD'
        let addTd = await waitForElementExist('td=ADD');
        await expect(addTd).toHaveText('ADD');
        // find row with headless user present
        let spanUnix = await waitForElementExist(`span*=${headlessUser}`);
        await expect(spanUnix).toHaveText(headlessUser);

        // Verify history is displayed after page refresh
        // refresh page
        await browser.refresh();
        // find row with 'ADD'
        addTd = await waitForElementExist('td=ADD');
        await expect(addTd).toHaveText('ADD');
        // find row with headless user present
        spanUnix = await waitForElementExist(`span*=${headlessUser}`);
        await expect(spanUnix).toHaveText(headlessUser);
    });

    it(TEST_NAME_GROUP_ADD_USER_INPUT, async () => {
        currentTest = TEST_NAME_GROUP_ADD_USER_INPUT;
        // open browser
        await authenticateAndWait();
        await navigateAndWait(GROUP_URI);

        // open Add Group modal
        await waitAndClick('button*=Add Group');

        // add group info
        let groupName = 'input-dropdown-test-group';
        await waitAndSetValue('#group-name-input', groupName);
        // add user
        let addMemberInput = await $('[name="member-name"]');
        // add invalid item
        await waitAndSetValue(addMemberInput, 'invalidusername');
        // blur
        await browser.keys('Tab');
        await browser.keys('Tab');
        // input did not change
        expect(await addMemberInput.getValue()).toBe('invalidusername');
        // input is not bold
        let fontWeight = await addMemberInput.getCSSProperty('font-weight')
            .value;
        expect(fontWeight).toBeUndefined();
        // submit (item in dropdown is not selected)
        let submitButton = await $('button*=Submit');
        await waitAndClick(submitButton);
        // verify error message
        let errorMessage = await waitForElementExist(
            'div[data-testid="error-message"]'
        );
        expect(await errorMessage.getText()).toBe(
            'Member must be selected in the dropdown or member input field must be empty.'
        );
        // clear input
        await waitAndClick(
            `.//*[local-name()="svg" and @data-wdio="clear-input"]`
        );
        // add valid input
        await waitAndSetValue(addMemberInput, headlessUser);
        // click dropdown
        await waitAndClick(`div*=${headlessUser}`);
        // verify input contains pes service
        expect(await addMemberInput.getValue()).toBe(headlessUser);
        // verify input is in bold
        fontWeight = await addMemberInput.getCSSProperty('font-weight');
        expect(fontWeight.value === 700).toBe(true);
    });

    it(TEST_NAME_GROUP_REVIEW_EXTEND, async () => {
        currentTest = TEST_NAME_GROUP_REVIEW_EXTEND;
        // open browser
        await authenticateAndWait();
        await navigateAndWait(GROUP_URI);

        // ADD GROUP WITH USER
        await waitAndClick('button*=Add Group');
        // add group info
        await waitAndSetValue('#group-name-input', reviewExtendTest);
        // add user
        await waitAndSetValue('[name="member-name"]', headlessUser);
        await waitAndClick(`div*=${headlessUser}`);
        // submit role
        await waitAndClick('button*=Submit');

        // go to review - the extend radio should be disabled
        await waitAndClick(
            `.//*[local-name()="svg" and @data-wdio="${reviewExtendTest}-review"]`
        );
        let extendRadio = await waitForElementExist('input[value="extend"]');
        await expect(extendRadio).toBeDisabled();

        // go to settings set user expiry days, submit
        await waitAndClick('div*=Settings');
        await waitAndSetValue('input[id="setting-memberExpiryDays"]', 10);
        await waitAndClick('button*=Submit');
        await waitAndClick('button[data-testid="update-modal-update"]');
        await closeAlert();

        // go to review - the extend radio should be enabled
        await waitAndClick('div*=Review');
        extendRadio = await waitForElementExist('input[value="extend"]');
        await expect(extendRadio).toBeEnabled();

        // go to settings, set service expiry days, submit
        await waitAndClick('div*=Settings');
        await waitAndSetValue('input[id="setting-memberExpiryDays"]', 0);
        await waitAndSetValue('input[id="setting-serviceExpiryDays"]', 10);
        await waitAndClick('button*=Submit');
        await waitAndClick('button[data-testid="update-modal-update"]');
        await closeAlert();

        // go to review - the extend radio should be enabled
        await waitAndClick('div*=Review');
        extendRadio = await waitForElementExist('input[value="extend"]');
        await expect(extendRadio).toBeEnabled();
    });

    it(TEST_NAME_GROUP_DOMAIN_FILTER, async () => {
        currentTest = TEST_NAME_GROUP_DOMAIN_FILTER;
        // open browser
        await authenticateAndWait();
        await navigateAndWait(GROUP_URI);

        // create group
        await createGroup(domainFilterTest);

        // specify headless user type domain in settings
        // open settings
        await waitAndClick(
            `.//*[local-name()="svg" and @id="group-settings-icon-${domainFilterTest}"]`
        );
        // add headless domain
        await waitAndSetValue(
            '#setting-principalDomainFilter',
            headlessUserType
        );
        // submit
        await waitAndClick('button*=Submit');
        await waitAndClick('button[data-testid="update-modal-update"]');
        await closeAlert();

        // attempt to add non-headless user
        await waitAndClick('div*=Members');
        await waitAndClick('button*=Add Member');
        await waitAndSetValue('input[name="member-name"]', humanUser);
        await waitAndClick(`div*=${humanUser}`);
        // submit
        await waitAndClick('button*=Submit');
        // verify fail message
        const errorMessage = await waitForElementExist(
            'div[data-testid="error-message"]'
        );
        expect(await errorMessage.getText()).toBe(
            `Status: 400. Message: Principal ${humanUser} is not allowed for the group`
        );
        // since headless domain was specified in domain filter
        // headless user is valid to be added
        // add headless user
        await waitAndClick(
            `.//*[local-name()="svg" and @data-wdio="clear-input"]`
        );
        await waitAndSetValue('input[name="member-name"]', headlessUser);
        await waitAndClick(`div*=${headlessUser}`);
        // submit
        await waitAndClick('button*=Submit');
        // check headless user was added
        const headlessMemberRow = await waitForElementExist(
            `tr[data-wdio='${headlessUser}-member-row']`
        );
        const memberRow = await headlessMemberRow.$(`td*=${headlessUser}`);
        await expect(memberRow).toHaveText(
            expect.stringContaining(headlessUser)
        );

        // specify user domain to be able to add non-headless user
        await waitAndClick('div*=Settings');
        // append user domain to headless domain
        await waitAndSetValue(
            '#setting-principalDomainFilter',
            `${headlessUserType},${humanUserType}`
        );
        // submit
        await waitAndClick('button*=Submit');
        await waitAndClick('button[data-testid="update-modal-update"]');
        await closeAlert();

        // add non-headless user
        await waitAndClick('div*=Members');
        await waitAndClick('button*=Add Member');
        await waitAndSetValue('input[name="member-name"]', humanUser);
        await waitAndClick(`div*=${humanUser}`);
        // submit
        await waitAndClick('button*=Submit');
        // check non-headless user was added
        const humanMemberRow = await waitForElementExist(
            `tr[data-wdio='${humanUser}-member-row']`
        );
        const memberRow2 = await humanMemberRow.$(`td*=${humanUser}`);
        await expect(memberRow2).toHaveText(expect.stringContaining(humanUser));
    });

    it(TEST_GROUP_MEMBER_EXPIRATION, async () => {
        currentTest = TEST_GROUP_MEMBER_EXPIRATION;

        await authenticateAndWait();
        await navigateAndWait(GROUP_URI);

        await waitAndClick('button*=Add Group');
        await waitAndSetValue('#group-name-input', memberExpiryTest);

        await waitAndSetValue('[name="member-name"]', headlessUser);
        await waitAndClick(`div*=${headlessUser}`);

        await waitAndClick('input[id="groupMemberExpiry"]');
        await waitAndClick('.flatpickr-day:not(.flatpickr-disabled)');
        await browser.keys('Enter');

        const date = await $('input[data-testid="flatPicker"]').getValue();

        await waitAndClick('button*=Submit');

        const groupRows = await $$(`tr[data-testid='group-row']`);

        expect(groupRows).toHaveText(memberExpiryTest);

        await waitAndClick(
            `.//*[local-name()="svg" and @data-wdio="${memberExpiryTest}-view-members"]`
        );

        expect(
            await $(`tr[data-wdio="${memberExpiryTest}-member-row"]`)
        ).toHaveText(date);
    });

    it(TEST_GROUP_ADVANCED_SETTINGS, async () => {
        currentTest = TEST_GROUP_ADVANCED_SETTINGS;

        const EXPIRY_DAYS = 3;
        const ONE_HOUR_MINS = 60;
        const MAX_MEMBERS = 2;
        const DOMAIN_FILTER = 'user';

        await authenticateAndWait();
        await navigateAndWait(GROUP_URI);

        await waitAndClick('button*=Add Group');
        await waitAndSetValue('#group-name-input', advancedSettingsTest);

        await waitAndClick(
            `.//*[local-name()="svg" and @id="advanced-settings-icon"]`
        );

        // Configure advanced settings
        await waitAndClick('label[for="switch-settingreviewEnabled"]');
        await waitAndClick('label[for="switch-settingdeleteProtection"]');
        await waitAndClick('label[for="switch-settingselfServe"]');
        await waitAndClick('label[for="switch-settingselfRenew"]');

        const reviewMins = await $('input[id="setting-selfRenewMins"]');
        await waitAndSetValue(reviewMins, ONE_HOUR_MINS.toString());

        const memberExpiry = await $('input[id="setting-memberExpiryDays"]');
        await waitAndSetValue(memberExpiry, EXPIRY_DAYS.toString());

        const serviceExpiry = await $('input[id="setting-serviceExpiryDays"]');
        await waitAndSetValue(serviceExpiry, EXPIRY_DAYS.toString());

        // set authority filters
        const authFiltersDropdown = await $(
            'div[data-testid="denali-multiselect"]'
        );
        await waitAndClick(authFiltersDropdown);
        await browser.keys('Tab');
        await browser.keys('Tab');

        // set authority expiration
        const authExpiration = await $(
            '[name="setting-userAuthorityExpiration"]'
        );
        await waitAndClick(authExpiration);
        await waitAndClick('div*=ElevatedClearance');

        const maxMembers = await $('input[id="setting-maxMembers"]');
        await waitAndSetValue(maxMembers, MAX_MEMBERS.toString());

        const domainFilter = await $(
            'input[id="setting-principalDomainFilter"]'
        );
        await waitAndSetValue(domainFilter, DOMAIN_FILTER);

        await waitAndClick('button*=Submit');

        const groupRows = await $$(`tr[data-testid='group-row']`);

        expect(groupRows).toHaveText(advancedSettingsTest);

        await waitAndClick(
            `.//*[local-name()="svg" and @id="group-settings-icon-${advancedSettingsTest}"]`
        );

        expect(
            await $('input[id="switch-settingreviewEnabled"]').getValue()
        ).toBeTruthy();
        expect(
            await $('input[id="switch-settingdeleteProtection"]').getValue()
        ).toBeTruthy();
        expect(
            await $('input[id="switch-settingselfServe"]').getValue()
        ).toBeTruthy();
        expect(
            await $('input[id="switch-settingselfRenew"]').getValue()
        ).toBeTruthy();

        expect(await reviewMins.getValue()).toBe(ONE_HOUR_MINS.toString());
        expect(await memberExpiry.getValue()).toBe(EXPIRY_DAYS.toString());
        expect(await serviceExpiry.getValue()).toBe(EXPIRY_DAYS.toString());

        expect(authFiltersDropdown).toHaveText('OnShore-US');
        expect(authFiltersDropdown).toHaveText('DataGovernance');
        expect(await authExpiration.getValue()).toBe('ElevatedClearance');

        expect(await maxMembers.getValue()).toBe(MAX_MEMBERS.toString());
        expect(await domainFilter.getValue()).toBe(DOMAIN_FILTER.toString());
    });

    it(TEST_AUDIT_ENABLED_GROUP, async () => {
        currentTest = TEST_AUDIT_ENABLED_GROUP;

        await authenticateAndWait();
        await navigateAndWait(AUDIT_ENABLED_GROUP_URI);

        await waitAndClick('button*=Add Group');
        await waitAndSetValue('#group-name-input', auditGroupTest);
        await waitAndSetValue(
            'input[id="justification"]',
            'create group for functional test'
        );

        await waitAndClick(
            `.//*[local-name()="svg" and @id="advanced-settings-icon"]`
        );

        await waitAndClick('label[for="switch-settingauditEnabled"]');

        const memberInput = await waitForElementExist(
            'input[name="member-name"]'
        );
        expect(memberInput).toBeDisabled();

        await waitAndClick('button*=Submit');

        const groupRows = await $$(`tr[data-testid='group-row']`);
        expect(groupRows).toHaveText(auditGroupTest);

        await waitAndClick(
            `.//*[local-name()="svg" and @data-wdio="${auditGroupTest}-view-members"]`
        );

        await waitAndClick('button*=Add Member');
        await waitAndSetValue('input[name="member-name"]', headlessUser);
        await waitAndClick(`div*=${headlessUser}`);
        await waitAndSetValue(
            'input[id="justification"]',
            'Add user for functional test'
        );
        await waitAndClick('button*=Submit');

        const pendingUsersTable = await $$(
            'table[data-testid="member-table"]'
        )[1];

        expect(pendingUsersTable).toHaveText('Pending');
        expect(pendingUsersTable).toHaveText(auditGroupTest);
    });

    const deleteGroup = async (groupName, auditEnabled = false) => {
        await authenticateAndWait();

        if (auditEnabled) {
            await navigateAndWait(AUDIT_ENABLED_GROUP_URI);
        } else {
            await navigateAndWait(GROUP_URI);
        }

        await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

        // wait for screen to complete loading
        const screenReady = await $('button*=Add Group');
        await waitForElementExist(screenReady);

        let deleteSvg = await $(
            `.//*[local-name()="svg" and @id="delete-group-icon-${groupName}"]`
        );
        // give it time to appear, but don't fail if it doesn't
        const groupAppeared = await deleteSvg
            .waitForExist({ timeout: 5000 })
            .catch(() => false);
        if (!groupAppeared) {
            console.warn(
                `GROUP FOR DELETION NOT FOUND (after wait): ${groupName}`
            );
            return;
        }
        // found, proceed to delete
        await waitAndClick(deleteSvg);

        // if justification input appears, set it
        const justificationInput = await $('input[id="justification"]');
        const justificationAppeared = await justificationInput
            .waitForExist({ timeout: 1000 })
            .catch(() => false);

        if (justificationAppeared) {
            await waitAndSetValue(
                'input[id="justification"]',
                'functional test cleanup'
            );
        }

        await waitAndClick('button*=Delete');
    };

    afterEach(async () => {
        try {
            // runs after each test and checks which test was run to perform corresponding cleanup logic
            switch (currentTest) {
                case TEST_NAME_GROUP_HISTORY_VISIBLE_AFTER_REFRESH:
                    await deleteGroup(historyTestGroup);
                    break;
                case TEST_NAME_GROUP_REVIEW_EXTEND:
                    await deleteGroup(reviewExtendTest);
                    break;
                case TEST_NAME_GROUP_DOMAIN_FILTER:
                    await deleteGroup(domainFilterTest);
                    break;
                case TEST_GROUP_MEMBER_EXPIRATION:
                    await deleteGroup(memberExpiryTest);
                    break;
                case TEST_GROUP_ADVANCED_SETTINGS:
                    await deleteGroup(advancedSettingsTest);
                    break;
                case TEST_AUDIT_ENABLED_GROUP:
                    await deleteGroup(auditGroupTest, true);
                    break;
            }
        } catch (error) {
            console.error(
                `Cleanup failed for test ${currentTest}:`,
                error.message
            );
            // Don't throw - allow other tests to continue
        } finally {
            // reset current test
            currentTest = '';
        }
    });
});

async function createGroup(groupName, ...members) {
    await waitAndClick('button*=Add Group');
    await waitAndSetValue('#group-name-input', groupName);

    // add members
    for (const member of members) {
        await waitAndSetValue('input[name="member-name"]', member);
        await waitAndClick(`div*=${member}`);
        await waitAndClick(`button[data-wdio="add-group-member"]`);
    }

    await waitAndClick('button*=Submit');

    // Check for "already exists" error
    const errorMessage = await $('div[data-testid="error-message"]');
    const exists = await errorMessage
        .waitForExist({ timeout: 1000 })
        .catch(() => false);
    if (exists) {
        const text = await errorMessage.getText();
        if (
            text.includes(
                `Status: 409. Message: Group ${groupName} already exists`
            )
        ) {
            throw new Error(
                `Group "${groupName}" already exists - failing to perform cleanup.`
            );
        } else {
            throw new Error(`Unexpected error during group creation: ${text}`);
        }
    }
}
