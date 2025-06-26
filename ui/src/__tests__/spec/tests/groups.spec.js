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

describe('group screen tests', () => {
    let currentTest;

    it(TEST_NAME_GROUP_HISTORY_VISIBLE_AFTER_REFRESH, async () => {
        currentTest = TEST_NAME_GROUP_HISTORY_VISIBLE_AFTER_REFRESH;
        // open browser
        await browser.newUser();
        await browser.url(`/`);
        // select domain
        let testDomain = await $(`a*=${TEST_DOMAIN}`);
        await testDomain.click();

        // ADD test group
        // navigate to groups page
        let groups = await $('div*=Groups');
        await groups.click();
        // open Add Group screen
        let addGroupButton = await $('button*=Add Group');
        await addGroupButton.click();
        // add group info
        let inputGroupName = await $('#group-name-input');
        let groupName = 'history-test-group';
        await inputGroupName.addValue(groupName);
        // add user
        let addMemberInput = await $('[name="member-name"]'); //TODO rename the field
        await addMemberInput.addValue(headlessUser);
        let userOption = await $(`div*=${headlessUser}`);
        await userOption.click();
        // submit role
        let buttonSubmit = await $('button*=Submit');
        await buttonSubmit.click();

        // Verify history entry of added group member is present
        // open history
        let historySvg = await $(
            './/*[local-name()="svg" and @id="group-history-icon-history-test-group"]'
        );
        await historySvg.click();
        // find row with 'ADD'
        let addTd = await $('td=ADD');
        await expect(addTd).toHaveText('ADD');
        // find row with headless user present
        let spanUnix = await $(`span*=${headlessUser}`);
        await expect(spanUnix).toHaveText(headlessUser);

        // Verify history is displayed after page refresh
        // refresh page
        await browser.refresh();
        // find row with 'ADD'
        addTd = await $('td=ADD');
        await expect(addTd).toHaveText('ADD');
        // find row with headless user present
        spanUnix = await $(`span*=${headlessUser}`);
        await expect(spanUnix).toHaveText(headlessUser);
    });

    it(TEST_NAME_GROUP_ADD_USER_INPUT, async () => {
        currentTest = TEST_NAME_GROUP_ADD_USER_INPUT;
        // open browser
        await browser.newUser();
        await browser.url(GROUP_URI);

        // open Add Group modal
        let addGroupButton = await $('button*=Add Group');
        await addGroupButton.click();

        // add group info
        let inputGroupName = await $('#group-name-input');
        let groupName = 'input-dropdown-test-group';
        await inputGroupName.addValue(groupName);
        // add user
        let addMemberInput = await $('[name="member-name"]');
        // add invalid item
        await addMemberInput.addValue('invalidusername');
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
        await submitButton.click();
        // verify error message
        let errorMessage = await $('div[data-testid="error-message"]');
        expect(await errorMessage.getText()).toBe(
            'Member must be selected in the dropdown or member input field must be empty.'
        );
        // clear input
        let clearInput = await $(
            `.//*[local-name()="svg" and @data-wdio="clear-input"]`
        );
        await clearInput.click();
        // add valid input
        await addMemberInput.addValue(headlessUser);
        // click dropdown
        let userOption = await $(`div*=${headlessUser}`);
        await userOption.click();
        // verify input contains pes service
        expect(await addMemberInput.getValue()).toBe(headlessUser);
        // verify input is in bold
        fontWeight = await addMemberInput.getCSSProperty('font-weight');
        expect(fontWeight.value === 700).toBe(true);
    });

    it(TEST_NAME_GROUP_REVIEW_EXTEND, async () => {
        currentTest = TEST_NAME_GROUP_REVIEW_EXTEND;
        // open browser
        await browser.newUser();
        await browser.url(GROUP_URI);

        // ADD GROUP WITH USER
        let addGroupBttn = await $('button*=Add Group');
        await addGroupBttn.click();
        // add group info
        let inputGroupName = await $('#group-name-input');
        await inputGroupName.addValue(reviewExtendTest);
        // add user
        let addMemberInput = await $('[name="member-name"]');
        await addMemberInput.addValue(headlessUser);
        let userOption = await $(`div*=${headlessUser}`);
        await userOption.click();
        // submit role
        let buttonSubmit = await $('button*=Submit');
        await buttonSubmit.click();

        // go to review - the extend radio should be disabled
        let reviewSvg = await $(
            `.//*[local-name()="svg" and @data-wdio="${reviewExtendTest}-review"]`
        );
        await reviewSvg.click();
        let extendRadio = await $('input[value="extend"]');
        await expect(extendRadio).toBeDisabled();

        // go to settings set user expiry days, submit
        let settingsDiv = await $('div*=Settings');
        await settingsDiv.click();
        let memberExpiryDays = await $('input[id="setting-memberExpiryDays"]');
        await memberExpiryDays.addValue(10);
        let submitBtn = await $('button*=Submit');
        await submitBtn.click();
        let confirmSubmit = await $(
            'button[data-testid="update-modal-update"]'
        );
        await confirmSubmit.click();
        let alertClose = await $('div[data-wdio="alert-close"]');
        await alertClose.click();

        // go to review - the extend radio should be enabled
        let reviewDiv = await $('div*=Review');
        await reviewDiv.click();
        extendRadio = await $('input[value="extend"]');
        await expect(extendRadio).toBeEnabled();

        // go to settings, set service expiry days, submit
        await settingsDiv.click();
        memberExpiryDays = await $('input[id="setting-memberExpiryDays"]');
        await memberExpiryDays.clearValue();
        await memberExpiryDays.setValue(0);
        let serviceExpiryDays = await $(
            'input[id="setting-serviceExpiryDays"]'
        );
        await serviceExpiryDays.addValue(10);
        await submitBtn.click();
        confirmSubmit = await $('button[data-testid="update-modal-update"]');
        await confirmSubmit.click();
        await alertClose.click();

        // go to review - the extend radio should be enabled
        reviewDiv = await $('div*=Review');
        await reviewDiv.click();
        extendRadio = await $('input[value="extend"]');
        await expect(extendRadio).toBeEnabled();
    });

    it(TEST_NAME_GROUP_DOMAIN_FILTER, async () => {
        currentTest = TEST_NAME_GROUP_DOMAIN_FILTER;
        // open browser
        await browser.newUser();
        await browser.url(GROUP_URI);

        // open add group modal
        let addGroupButton = await $('button*=Add Group');
        await addGroupButton.click();
        // add group name
        await $('#group-name-input').addValue(domainFilterTest);
        // submit
        let submitButton = await $('button*=Submit');
        await submitButton.click();

        // specify headless user type domain in settings
        // open settings
        await $(
            `.//*[local-name()="svg" and @id="group-settings-icon-${domainFilterTest}"]`
        ).click();
        // add headless domain
        let principalDomainFilter = await $('#setting-principalDomainFilter');
        await principalDomainFilter.addValue(headlessUserType);
        // submit
        await $('button*=Submit').click();
        await $('button[data-testid="update-modal-update"]').click();

        // attempt to add non-headless user
        await $('div*=Members').click();
        await $('button*=Add Member').click();
        let memberInput = await $('input[name="member-name"]');
        await memberInput.addValue(humanUser);
        await $(`div*=${humanUser}`).click();
        // submit
        await $('button*=Submit').click();
        // verify fail message
        errorMessage = await $('div[data-testid="error-message"]');
        expect(await errorMessage.getText()).toBe(
            `Status: 400. Message: Principal ${humanUser} is not allowed for the group`
        );
        // since headless domain was specified in domain filter
        // headless user is valid to be added
        // add headless user
        let clearInput = await $(
            `.//*[local-name()="svg" and @data-wdio="clear-input"]`
        );
        clearInput.click();
        await memberInput.addValue(headlessUser);
        await $(`div*=${headlessUser}`).click();
        // submit
        await $('button*=Submit').click();
        // check headless user was added
        memberRow = await $(`tr[data-wdio='${headlessUser}-member-row']`).$(
            `td*=${headlessUser}`
        );
        await expect(memberRow).toHaveText(
            expect.stringContaining(headlessUser)
        );

        // specify user domain to be able to add non-headless user
        await $('div*=Settings').click();
        principalDomainFilter = await $('#setting-principalDomainFilter');
        await principalDomainFilter.clearValue();
        // append user domain to headless domain
        await principalDomainFilter.addValue(
            `${headlessUserType},${humanUserType}`
        );
        // submit
        await $('button*=Submit').click();
        await $('button[data-testid="update-modal-update"]').click();

        // add non-headless user
        await $('div*=Members').click();
        await $('button*=Add Member').click();
        memberInput = await $('input[name="member-name"]');
        await memberInput.addValue(humanUser);
        await $(`div*=${humanUser}`).click();
        // submit
        await $('button*=Submit').click();
        // check non-headless user was added
        memberRow = await $(`tr[data-wdio='${humanUser}-member-row']`).$(
            `td*=${humanUser}`
        );
        await expect(memberRow).toHaveText(expect.stringContaining(humanUser));
    });

    it(TEST_GROUP_MEMBER_EXPIRATION, async () => {
        currentTest = TEST_GROUP_MEMBER_EXPIRATION;

        await browser.newUser();
        await browser.url(GROUP_URI);

        await $('button*=Add Group').click();
        await $('#group-name-input').addValue(memberExpiryTest);

        await $('[name="member-name"]').addValue(headlessUser);
        await $(`div*=${headlessUser}`).click();

        await $('input[id="groupMemberExpiry"]').click();
        await $('.flatpickr-day:not(.flatpickr-disabled)').click();
        await browser.keys('Enter');

        const date = await $('input[data-testid="flatPicker"]').getValue();

        await $('button*=Submit').click();

        const groupRows = await $$(`tr[data-testid='group-row']`);

        expect(groupRows).toHaveText(memberExpiryTest);

        await $(
            `.//*[local-name()="svg" and @data-wdio="${memberExpiryTest}-view-members"]`
        ).click();

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

        await browser.newUser();
        await browser.url(GROUP_URI);

        await $('button*=Add Group').click();
        await $('#group-name-input').addValue(advancedSettingsTest);

        await $(
            `.//*[local-name()="svg" and @id="advanced-settings-icon"]`
        ).click();

        // Configure advanced settings
        await $('label[for="switch-settingreviewEnabled"]').click();
        await $('label[for="switch-settingdeleteProtection"]').click();
        await $('label[for="switch-settingselfServe"]').click();
        await $('label[for="switch-settingselfRenew"]').click();

        const reviewMins = await $('input[id="setting-selfRenewMins"]');
        await reviewMins.addValue(ONE_HOUR_MINS);

        const memberExpiry = await $('input[id="setting-memberExpiryDays"]');
        await memberExpiry.addValue(EXPIRY_DAYS);

        const serviceExpiry = await $('input[id="setting-serviceExpiryDays"]');
        await serviceExpiry.addValue(EXPIRY_DAYS);

        // set authority filters
        const authFiltersDropdown = await $(
            'div[data-testid="denali-multiselect"]'
        );
        await authFiltersDropdown.click();
        await browser.keys('Tab');
        await browser.keys('Tab');

        // set authority expiration
        const authExpiration = await $(
            '[name="setting-userAuthorityExpiration"]'
        );
        await authExpiration.click();
        await $('div*=ElevatedClearance').click();

        const maxMembers = await $('input[id="setting-maxMembers"]');
        await maxMembers.addValue(MAX_MEMBERS);

        const domainFilter = await $(
            'input[id="setting-principalDomainFilter"]'
        );
        await domainFilter.addValue(DOMAIN_FILTER);

        await $('button*=Submit').click();

        const groupRows = await $$(`tr[data-testid='group-row']`);

        expect(groupRows).toHaveText(advancedSettingsTest);

        await $(
            `.//*[local-name()="svg" and @id="group-settings-icon-${advancedSettingsTest}"]`
        ).click();

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

        await browser.newUser();
        await browser.url(AUDIT_ENABLED_GROUP_URI);

        await $('button*=Add Group').click();
        await $('#group-name-input').addValue(auditGroupTest);
        await $('input[id="justification"]').addValue(
            'create group for functional test'
        );

        await $(
            `.//*[local-name()="svg" and @id="advanced-settings-icon"]`
        ).click();

        await $('label[for="switch-settingauditEnabled"]').click();

        const memberInput = await $('input[name="member-name"]');
        expect(memberInput).toBeDisabled();

        await $('button*=Submit').click();

        const groupRows = await $$(`tr[data-testid='group-row']`);
        expect(groupRows).toHaveText(auditGroupTest);

        await $(
            `.//*[local-name()="svg" and @data-wdio="${auditGroupTest}-view-members"]`
        ).click();

        await $('button*=Add Member').click();
        await $('input[name="member-name"]').addValue(headlessUser);
        await $(`div*=${headlessUser}`).click();
        await $('input[id="justification"]').addValue(
            'Add user for functional test'
        );
        await $('button*=Submit').click();

        const pendingUsersTable = await $$(
            'table[data-testid="member-table"]'
        )[1];

        expect(pendingUsersTable).toHaveText('Pending');
        expect(pendingUsersTable).toHaveText(auditGroupTest);
    });

    const deleteGroup = async (groupName, auditEnabled = false) => {
        await browser.newUser();

        if (auditEnabled) {
            await browser.url(AUDIT_ENABLED_GROUP_URI);
        } else {
            await browser.url(GROUP_URI);
        }

        await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

        await $(
            `.//*[local-name()="svg" and @id="delete-group-icon-${groupName}"]`
        ).click();

        const justification = await $('input[id="justification"]');

        if (await justification.isExisting()) {
            justification.addValue('functional test cleanup');
        }

        await $('button*=Delete').click();
    };

    afterEach(async () => {
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

        // to reset currentTest after running cleanup
        currentTest = '';
    });
});
