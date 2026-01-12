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
    authenticateAndWait,
    navigateAndWait,
    waitAndSetValue,
    waitAndClick,
    waitForElementExist,
    waitForTabToOpenAndSwitch,
    beforeEachTest,
    closeAlert,
} = require('../libs/helpers');
const testdata = config().testdata;
const headlessUser = testdata.userHeadless1.id;
const humanUser = testdata.user1.id;

const delegatedRole = 'delegated-role';
const dropdownTestRoleName = 'dropdown-test-role';
const reviewExtendTest1 = 'review-extend-test1';
const reviewExtendTest2 = 'review-extend-test2';
const domainFilterTest = 'domain-filter-test';
const multipleMemberRole = 'multiple-member-role';
const historyTestRole = 'history-test-role';
const multiSelectRole = 'multi-select-role';

const TEST_DOMAIN = 'athenz.dev.functional-test';
const TEST_DOMAIN_SETTINGS_URI = `/domain/${TEST_DOMAIN}/domain-settings`;
const TEST_DOMAIN_ROLE_URI = `/domain/${TEST_DOMAIN}/role`;

const TEST_NAME_HISTORY_VISIBLE_AFTER_PAGE_REFRESH =
    'role history should be visible when navigating to it and after page refresh';
const TEST_NAME_DELEGATED_ROLE_ADDITIONAL_SETTINGS_ARE_DISABLED =
    'when creating or editing a delegated role, all additional settings except description must be disabled';
const TEST_NAME_ADD_ROLE_MEMBER_INPUT_PRESERVES_CONTENTS_ON_BLUR =
    'member dropdown when creating a role and adding to existing role - should preserve input on blur, make input bold when selected in dropdown, reject unselected input';
const TEST_NAME_ROLE_REVIEW_EXTEND_DISABLED =
    'Role Review - Extend radio button should be enabled when Expiry/Review (Days) are set in settings';
const TEST_DOMAIN_EXPIRY_ENFORCED_BY_DEFAULT =
    'Role Review - Extend radio button should be enabled when domain expiry is set and role expiry is empty';
const TEST_NAME_DOMAIN_FILTER =
    'Domain Filter - only principals matching specific domain(s) can be added to a role';
const TEST_ADD_ROLE_WITH_MULTIPLE_MEMBERS = 'Add role with multiple members';
const TEST_ROLE_RULE_POLICIES_EXPANDED =
    'Rule policies for a role are expanded by default when opened';
const TEST_MULTISELECT_AUTHORITY_FILTERS =
    'Multiple authority filters for a role can be selected';

async function resetDomainExpiry() {
    await authenticateAndWait();
    await navigateAndWait(TEST_DOMAIN_SETTINGS_URI);

    const memberExpiry = await $('input[id="setting-memberExpiryDays"]');
    const groupExpiry = await $('input[id="setting-groupExpiryDays"]');
    const serviceExpiry = await $('input[id="setting-serviceExpiryDays"]');

    await waitAndSetValue(memberExpiry, '0', { clearFirst: true });
    await waitAndSetValue(groupExpiry, '0', { clearFirst: true });
    await waitAndSetValue(serviceExpiry, '0', { clearFirst: true });

    await waitAndClick('button*=Submit');
    await waitAndClick('button[data-testid="update-modal-update"]');
    await closeAlert();
}

async function deleteRoleIfExists(roleName) {
    console.info(`Deleting role if exists: ${roleName}`);
    await authenticateAndWait();
    await navigateAndWait(TEST_DOMAIN_ROLE_URI);
    await expect(browser).toHaveUrl(expect.stringContaining('athenz'));
    // wait for screen to complete loading
    await waitForElementExist('button*=Add Role');

    const deleteSvg = await $(
        `.//*[local-name()="svg" and @id="${roleName}-delete-role-button"]`
    );
    // give role delete button time to appear, but don't fail if it doesn't
    const appeared = await deleteSvg
        .waitForExist({ timeout: 5000 })
        .catch(() => false);

    if (!appeared) {
        console.info(`Role ${roleName} does not exist, nothing to delete`);
        return;
    }
    // found, proceed to delete
    await waitAndClick(deleteSvg, { timeout: 5000 });

    // wait until modal is visible
    await waitForElementExist('div[data-testid="modal-title"]');

    const confirmDelete = await $('button*=Delete');
    await waitAndClick(confirmDelete, { timeout: 5000 });
}

describe('role screen tests', () => {
    beforeEach(async () => {
        // Clear cookies and storage between tests
        await beforeEachTest();
    });
    let currentTest;

    it(TEST_NAME_HISTORY_VISIBLE_AFTER_PAGE_REFRESH, async () => {
        currentTest = TEST_NAME_HISTORY_VISIBLE_AFTER_PAGE_REFRESH;
        // open browser
        await authenticateAndWait();
        await navigateAndWait(TEST_DOMAIN_ROLE_URI);

        await createRoleWithMembers(historyTestRole, headlessUser);

        // Verify history entry of added role member is present
        // open history
        let historySvg = await $(
            `.//*[local-name()="svg" and @id="${historyTestRole}-history-role-button"]`
        );
        await waitAndClick(historySvg);
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
        await expect(addTd).toHaveText('ADD');
        // find row with headless user present
        await expect(spanUnix).toHaveText(headlessUser);
    });

    it(TEST_NAME_DELEGATED_ROLE_ADDITIONAL_SETTINGS_ARE_DISABLED, async () => {
        currentTest = TEST_NAME_DELEGATED_ROLE_ADDITIONAL_SETTINGS_ARE_DISABLED;
        // open browser
        await authenticateAndWait();
        await navigateAndWait(TEST_DOMAIN_ROLE_URI);

        // open Add Role screen
        await waitAndClick('button*=Add Role');
        // select Delegated
        await waitAndClick('div*=Delegated');
        // verify all settings except Description are disabled
        await waitAndClick('#advanced-settings-icon');
        let switchSettingAuditEnabled = await $('#switch-settingauditEnabled');
        await expect(switchSettingAuditEnabled).toBeDisabled();
        let switchSettingReviewEnabled = await $(
            '#switch-settingreviewEnabled'
        );
        await expect(switchSettingReviewEnabled).toBeDisabled();
        let switchSettingDeleteProtection = await $(
            '#switch-settingdeleteProtection'
        );
        await expect(switchSettingDeleteProtection).toBeDisabled();
        let switchSettingSelfServe = await $('#switch-settingselfServe');
        await expect(switchSettingSelfServe).toBeDisabled();
        let switchSettingSelfRenew = await $('#switch-settingselfRenew');
        await expect(switchSettingSelfRenew).toBeDisabled();
        let inputSelfRenewMins = await $('#setting-selfRenewMins');
        await expect(inputSelfRenewMins).toBeDisabled();
        let inputMemberExpiryDays = await $('#setting-memberExpiryDays');
        await expect(inputMemberExpiryDays).toBeDisabled();
        let inputGroupExpiryDays = await $('#setting-groupExpiryDays');
        await expect(inputGroupExpiryDays).toBeDisabled();
        let inputGroupReviewDays = await $('#setting-groupReviewDays');
        await expect(inputGroupReviewDays).toBeDisabled();
        let inputServiceExpiryDays = await $('#setting-serviceExpiryDays');
        await expect(inputServiceExpiryDays).toBeDisabled();
        let inputServiceReviewDays = await $('#setting-serviceReviewDays');
        await expect(inputServiceReviewDays).toBeDisabled();
        let inputTokenExpiryMins = await $('#setting-tokenExpiryMins');
        await expect(inputTokenExpiryMins).toBeDisabled();
        let inputCertExpiryMins = await $('#setting-certExpiryMins');
        await expect(inputCertExpiryMins).toBeDisabled();
        let dropdownUserAuthorityExpiration = await $(
            '[name="setting-userAuthorityExpiration"]'
        );
        await expect(dropdownUserAuthorityExpiration).toBeDisabled();
        let inputSettingDescription = await $('#setting-description');
        await expect(inputSettingDescription).toBeEnabled();
        let inputMaxMembers = await $('#setting-maxMembers');
        await expect(inputMaxMembers).toBeDisabled();

        // add role info
        await waitAndSetValue('#role-name-input', delegatedRole);
        await waitAndSetValue('#delegated-to-input', 'athenz.dev');
        // submit role
        await waitAndClick('button*=Submit');

        // find row with 'delegated-role' in name and click settings svg
        await waitAndClick(
            `.//*[local-name()="svg" and @id="${delegatedRole}-setting-role-button"]`
        );

        // verify all settings except Description are disabled
        await expect(switchSettingReviewEnabled).toBeDisabled();
        await expect(switchSettingDeleteProtection).toBeDisabled();
        await expect(switchSettingSelfServe).toBeDisabled();
        await expect(switchSettingSelfRenew).toBeDisabled();
        await expect(inputSelfRenewMins).toBeDisabled();
        await expect(inputMemberExpiryDays).toBeDisabled();
        await expect(inputGroupExpiryDays).toBeDisabled();
        await expect(inputGroupReviewDays).toBeDisabled();
        await expect(inputServiceExpiryDays).toBeDisabled();
        await expect(inputServiceReviewDays).toBeDisabled();
        await expect(inputTokenExpiryMins).toBeDisabled();
        await expect(inputCertExpiryMins).toBeDisabled();
        await expect(dropdownUserAuthorityExpiration).toBeDisabled();
        await expect(inputSettingDescription).toBeEnabled();
        await expect(inputMaxMembers).toBeDisabled();
    });

    it(TEST_NAME_ADD_ROLE_MEMBER_INPUT_PRESERVES_CONTENTS_ON_BLUR, async () => {
        currentTest =
            TEST_NAME_ADD_ROLE_MEMBER_INPUT_PRESERVES_CONTENTS_ON_BLUR;
        await authenticateAndWait();
        await navigateAndWait(TEST_DOMAIN_ROLE_URI);
        await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

        // click add role
        await waitAndClick('button*=Add Role');

        await waitAndSetValue(
            'input[id="role-name-input"]',
            dropdownTestRoleName
        );

        const invalidMember = 'admi';
        // add random text to modal input
        let memberInput = await $('input[name="member-name"]');
        await waitAndSetValue(memberInput, invalidMember);

        // blur without causing calendar widget to close other elements
        await browser.keys('Tab');
        await waitAndClick(memberInput);

        // input did not change
        expect(await memberInput.getValue()).toBe(invalidMember);

        // input is not bold
        let fontWeight = await memberInput.getCSSProperty('font-weight').value;
        expect(fontWeight).toBeUndefined();

        // submit (item in dropdown is not selected)
        await waitAndClick('button*=Submit');

        // verify error message
        let errorMessage = await waitForElementExist(
            'div[data-testid="error-message"]'
        );
        expect(await errorMessage.getText()).toBe(
            'Member must be selected in the dropdown or member input field must be empty.'
        );

        // type valid input and select item in dropdown
        await waitAndClick(
            `.//*[local-name()="svg" and @data-wdio="clear-input"]`
        );
        await waitAndSetValue(memberInput, headlessUser);
        await waitAndClick(`div*=${headlessUser}`);

        // verify input contains selected member
        expect(await memberInput.getValue()).toBe(headlessUser);

        // verify input is in bold
        fontWeight = await memberInput.getCSSProperty('font-weight');
        expect(fontWeight.value === 700).toBe(true);

        // submit
        await waitAndClick('button*=Submit');

        // role can be seen added
        let roleRow = await $(
            `div[data-wdio=${dropdownTestRoleName}-role-row]`
        ).$(`span*=${dropdownTestRoleName}`);
        await expect(roleRow).toHaveText(
            expect.stringContaining(dropdownTestRoleName)
        );

        // view role members
        await waitAndClick(
            `.//*[local-name()="svg" and @data-wdio="${dropdownTestRoleName}-view-members"]`
        );

        // role has added member
        let memberRow = await $(`tr[data-wdio='${headlessUser}-member-row']`).$(
            `td*=${headlessUser}`
        );
        await expect(memberRow).toHaveText(
            expect.stringContaining(headlessUser)
        );

        // delete member
        await waitAndClick(
            `.//*[local-name()="svg" and @data-wdio="${headlessUser}-delete-member"]`
        );
        await waitAndClick('button*=Delete');
        // close alert
        await closeAlert();

        // TEST ADD MEMBER TO EXISTING ROLE

        // open add member window
        await waitAndClick('button*=Add Member');

        // test incomplete input in dropdown
        memberInput = await $('input[name="member-name"]');
        await waitAndSetValue(memberInput, invalidMember);

        // blur
        await browser.keys('Tab');
        await waitAndClick(memberInput);

        // input did not change
        expect(await memberInput.getValue()).toBe(invalidMember);

        // input is not bold
        fontWeight = await memberInput.getCSSProperty('font-weight').value;
        expect(fontWeight).toBeUndefined();

        // submit (item in dropdown is not selected)
        submitButton = await $('button*=Submit');
        await waitAndClick(submitButton);

        // verify error message
        errorMessage = await waitForElementExist(
            'div[data-testid="error-message"]'
        );
        expect(await errorMessage.getText()).toBe(
            'Member must be selected in the dropdown.'
        );

        // type valid input and select item in dropdown
        clearInput = await $(
            `.//*[local-name()="svg" and @data-wdio="clear-input"]`
        );
        await waitAndClick(clearInput);
        await waitAndSetValue(memberInput, headlessUser);
        await waitAndClick(
            `.//div[@role='option' and contains(., '${headlessUser}')]`
        );

        // verify input contains selected memeber
        expect(await memberInput.getValue()).toBe(headlessUser);

        // verify input is in bold
        fontWeight = await memberInput.getCSSProperty('font-weight');
        expect(fontWeight.value === 700).toBe(true);

        // submit
        await waitAndClick(submitButton);

        // verify new member was added
        let validMemberTd = await $(
            `tr[data-wdio='${headlessUser}-member-row']`
        ).$(`td*=${headlessUser}`);
        expect(validMemberTd).toHaveText(`${headlessUser}`);
    });

    it(TEST_NAME_ROLE_REVIEW_EXTEND_DISABLED, async () => {
        currentTest = TEST_NAME_ROLE_REVIEW_EXTEND_DISABLED;
        // open browser
        await authenticateAndWait();
        await navigateAndWait(TEST_DOMAIN_ROLE_URI);

        await createRoleWithMembers(reviewExtendTest1, headlessUser);

        // go to review - the extend radio should be disabled
        let reviewSvg = await $(
            `.//*[local-name()="svg" and @data-wdio="${reviewExtendTest1}-review"]`
        );
        await waitAndClick(reviewSvg);
        let extendRadio = await $('input[value="extend"]');
        await expect(extendRadio).toBeDisabled();

        // go to settings set user expiry days, submit
        await waitAndClick('div*=Settings');
        let memberExpiryDays = await $('input[id="setting-memberExpiryDays"]');
        await waitAndSetValue(memberExpiryDays, '10');
        await waitAndClick('button*=Submit');
        await waitAndClick('button[data-testid="update-modal-update"]');
        await closeAlert();

        // go to review - the extend radio should be enabled
        await waitAndClick('div*=Review');
        await expect(extendRadio).toBeEnabled();

        // go to settings, set user review days, submit
        await waitAndClick('div*=Settings');
        await memberExpiryDays.clearValue();
        await waitAndSetValue(memberExpiryDays, '0');
        let memberReviewDays = await $('input[id="setting-memberReviewDays"]');
        await waitAndSetValue(memberReviewDays, '10');
        await waitAndClick('button*=Submit');
        await waitAndClick('button[data-testid="update-modal-update"]');
        await closeAlert();

        // go to review - the extend radio should be enabled
        await waitAndClick('div*=Review');
        await expect(extendRadio).toBeEnabled();

        // go to settings, set group expiry days, submit
        await waitAndClick('div*=Settings');
        await memberReviewDays.clearValue();
        await waitAndSetValue(memberReviewDays, '0');
        let groupExpiryDays = await $('input[id="setting-groupExpiryDays"]');
        await waitAndSetValue(groupExpiryDays, '10');
        await waitAndClick('button*=Submit');
        await waitAndClick('button[data-testid="update-modal-update"]');
        await closeAlert();

        // go to review - the extend radio should be enabled
        await waitAndClick('div*=Review');
        await expect(extendRadio).toBeEnabled();

        // go to settings, set group review days, submit
        await waitAndClick('div*=Settings');
        await groupExpiryDays.clearValue();
        await waitAndSetValue(groupExpiryDays, '0');
        let groupReviewDays = await $('input[id="setting-groupReviewDays"]');
        await waitAndSetValue(groupReviewDays, '10');
        await waitAndClick('button*=Submit');
        await waitAndClick('button[data-testid="update-modal-update"]');
        await closeAlert();

        // go to review - the extend radio should be enabled
        await waitAndClick('div*=Review');
        await expect(extendRadio).toBeEnabled();

        // go to settings, set service review days, submit
        await waitAndClick('div*=Settings');
        await groupReviewDays.clearValue();
        await waitAndSetValue(groupReviewDays, '0');
        let serviceExpiryDays = await $(
            'input[id="setting-serviceExpiryDays"]'
        );
        await waitAndSetValue(serviceExpiryDays, '10');
        await waitAndClick('button*=Submit');
        await waitAndClick('button[data-testid="update-modal-update"]');
        await closeAlert();

        // go to review - the extend radio should be enabled
        await waitAndClick('div*=Review');
        await expect(extendRadio).toBeEnabled();

        // go to settings, set service expiry days, submit
        await waitAndClick('div*=Settings');
        await serviceExpiryDays.clearValue();
        await waitAndSetValue(serviceExpiryDays, '0');
        let serviceReviewDays = await $(
            'input[id="setting-serviceReviewDays"]'
        );
        await waitAndSetValue(serviceReviewDays, '10');
        await waitAndClick('button*=Submit');
        await waitAndClick('button[data-testid="update-modal-update"]');
        await closeAlert();

        // go to review - the extend radio should be enabled
        await waitAndClick('div*=Review');
        await expect(extendRadio).toBeEnabled();
    });

    it(TEST_DOMAIN_EXPIRY_ENFORCED_BY_DEFAULT, async () => {
        currentTest = TEST_DOMAIN_EXPIRY_ENFORCED_BY_DEFAULT;

        const MEMBER_EXPIRY_DAYS = 10;
        const GROUP_EXPIRY_DAYS = 20;
        const SERVICE_EXPIRY_DAYS = 30;

        await authenticateAndWait();
        await navigateAndWait(TEST_DOMAIN_SETTINGS_URI);

        await waitAndSetValue(
            'input[id="setting-memberExpiryDays"]',
            MEMBER_EXPIRY_DAYS
        );
        await waitAndSetValue(
            'input[id="setting-groupExpiryDays"]',
            GROUP_EXPIRY_DAYS
        );
        await waitAndSetValue(
            'input[id="setting-serviceExpiryDays"]',
            SERVICE_EXPIRY_DAYS
        );
        await waitAndClick('button*=Submit');

        await waitAndClick('button[data-testid="update-modal-update"]');
        await closeAlert();

        await navigateAndWait(TEST_DOMAIN_ROLE_URI);

        await createRoleWithMembers(reviewExtendTest2, headlessUser);

        await waitAndClick(
            `.//*[local-name()="svg" and @data-wdio="${reviewExtendTest2}-review"]`
        );

        const extendRadio = await waitForElementExist('input[value="extend"]');
        const expirySpan = await waitForElementExist(
            'span[data-testid="role-expiration-details"]'
        );
        const expiryDetails = await expirySpan.getText();

        expect(extendRadio).toBeEnabled();
        expect(expiryDetails).toContain(
            `Domain Member Expiry: ${MEMBER_EXPIRY_DAYS} days`
        );
        expect(expiryDetails).toContain(
            `Domain Group Expiry: ${GROUP_EXPIRY_DAYS} days`
        );
        expect(expiryDetails).toContain(
            `Domain Service Expiry: ${SERVICE_EXPIRY_DAYS} days`
        );
    });

    it(TEST_NAME_DOMAIN_FILTER, async () => {
        currentTest = TEST_NAME_DOMAIN_FILTER;
        // open browser
        await authenticateAndWait();
        await navigateAndWait(TEST_DOMAIN_ROLE_URI);

        // open add role modal
        let addiRoleButton = await $('button*=Add Role');
        await waitAndClick(addiRoleButton);
        // add role name
        let inputRoleName = await $('#role-name-input');
        await waitAndSetValue(inputRoleName, domainFilterTest);
        // specify domain
        let advancedSettingsIcon = await $('#advanced-settings-icon');
        await waitAndClick(advancedSettingsIcon);
        let principalDomainFilter = await $('#setting-principalDomainFilter');
        await waitAndSetValue(principalDomainFilter, 'athenz');
        // attempt to submit a member that doesn't belong to specified domain
        // add user
        await waitAndSetValue('input[name="member-name"]', humanUser);
        let dropdownOption = await $(`div*=${humanUser}`);
        await waitAndClick(dropdownOption);
        // submit
        let submitButton = await $('button*=Submit');
        await waitAndClick(submitButton);
        // verify fail message
        let errorMessage = await waitForElementExist(
            'div[data-testid="error-message"]'
        );
        await expect(await errorMessage.getText()).toBe(
            `Status: 400. Message: Principal ${humanUser} is not allowed for the role`
        );
        // change to specified domain
        await principalDomainFilter.clearValue();
        await waitAndSetValue(principalDomainFilter, 'user');
        // submit - success
        await waitAndClick(submitButton);
        // view role members
        await waitAndClick(
            `.//*[local-name()="svg" and @data-wdio="${domainFilterTest}-view-members"]`
        );
        // verify member was added to the role
        let memberRow = await $(`tr[data-wdio='${humanUser}-member-row']`).$(
            `td*=${humanUser}`
        );
        await expect(memberRow).toHaveText(expect.stringContaining(humanUser));

        // check that domain filter applies to an existing role
        // let's reuse the role created above
        await waitAndClick('button*=Add Member');
        // attempt to add headless user
        await waitAndSetValue('input[name="member-name"]', headlessUser);
        await waitAndClick(`div*=${headlessUser}`);
        // submit
        await waitAndClick('button*=Submit');
        // verify fail message - headless domain is not registered in the filter yet
        expect(await errorMessage.getText()).toBe(
            `Status: 400. Message: Principal ${headlessUser} is not allowed for the role`
        );
        // close modal
        await waitAndClick('button*=Cancel');

        // let's add headless user to domain filter in role settings
        await waitAndClick('div*=Settings');
        await principalDomainFilter.clearValue();
        await waitAndSetValue(
            principalDomainFilter,
            `${testdata.userHeadless1.type},${testdata.user1.type}`
        );
        // submit
        await waitAndClick('button*=Submit');
        await waitAndClick('button[data-testid="update-modal-update"]');
        await closeAlert();

        // now it must be possible to add member of a headless domain
        // add headless user
        await waitAndClick('div*=Members');
        await waitAndClick('button*=Add Member');
        await waitAndSetValue('input[name="member-name"]', headlessUser);
        await waitAndClick(`div*=${headlessUser}`);
        // submit
        await waitAndClick('button*=Submit');
        // check new member was added
        memberRow = await $(`tr[data-wdio='${headlessUser}-member-row']`).$(
            `td*=${headlessUser}`
        );
        await expect(memberRow).toHaveText(
            expect.stringContaining(headlessUser)
        );
    });

    it('Pressing Cmd + Click on a role group links opens a new tab', async () => {
        // uses existing role group
        // open browser
        await authenticateAndWait();
        await navigateAndWait(TEST_DOMAIN_ROLE_URI);

        // expand aws roles
        await waitAndClick(
            './/*[local-name()="svg" and @data-wdio="AWS-roles-expand"]'
        );

        const awsRole = 'aws_instance_launch_provider';
        let awsRoleMembersIcon = await $(
            `.//*[local-name()="svg" and @data-wdio="${awsRole}-members"]`
        );
        // cmd + click on aws instance launch provider role
        // simpler browser.keys([Key.Ctrl / Key.Control / Key.Command]) don't work
        await browser.performActions([
            {
                type: 'key',
                id: 'keyboard',
                actions: [
                    { type: 'keyDown', value: '\uE03D' }, // Cmd key (Meta key) down
                ],
            },
        ]);
        await waitAndClick(awsRoleMembersIcon);
        // Release all actions to reset states
        await browser.releaseActions();

        // Wait until a new tab opens
        await waitForTabToOpenAndSwitch();

        // verify the URL of the new tab
        const url = await browser.getUrl();
        expect(url.includes(`${TEST_DOMAIN_ROLE_URI}/${awsRole}/members`)).toBe(
            true
        );

        // to check if we are on aws role page, seek for aws user in the role
        const awsUser = $(`div*='athens.aws.*'`);
        expect(awsUser).toHaveText('athens.aws.*');
    });

    it(TEST_ADD_ROLE_WITH_MULTIPLE_MEMBERS, async () => {
        currentTest = TEST_ADD_ROLE_WITH_MULTIPLE_MEMBERS;
        // open browser
        await authenticateAndWait();
        await navigateAndWait(TEST_DOMAIN_ROLE_URI);

        await createRoleWithMembers(
            multipleMemberRole,
            headlessUser,
            humanUser
        );

        // verify both members were added to the role
        await waitAndClick(
            `.//*[local-name()="svg" and @data-wdio="${multipleMemberRole}-view-members"]`
        );
        let memberRow1 = await $(
            `tr[data-wdio='${headlessUser}-member-row']`
        ).$(`td*=${headlessUser}`);
        await expect(memberRow1).toHaveText(
            expect.stringContaining(headlessUser)
        );

        let memberRow2 = await $(`tr[data-wdio='${humanUser}-member-row']`).$(
            `td*=${humanUser}`
        );
        await expect(memberRow2).toHaveText(expect.stringContaining(humanUser));
    });

    it(TEST_ROLE_RULE_POLICIES_EXPANDED, async () => {
        const adminRole = 'admin';

        // open browser
        await authenticateAndWait();
        await navigateAndWait(TEST_DOMAIN_ROLE_URI);

        // verify rule policy is expanded by default for role
        await waitAndClick(
            `.//*[local-name()="svg" and @data-wdio="${adminRole}-policy-rules"]`
        );

        const roleRow = await $(
            `tr[data-wdio='${adminRole}-policy-rule-row']`
        ).$(`td*=${adminRole}`);

        await expect(roleRow).toHaveText(
            expect.stringContaining(`${TEST_DOMAIN}:role.${adminRole}`)
        );
    });

    it(TEST_MULTISELECT_AUTHORITY_FILTERS, async () => {
        currentTest = TEST_MULTISELECT_AUTHORITY_FILTERS;
        const successAlertText = 'Successfully updated the setting(s)';
        const authFilters = ['OnShore-US', 'DataGovernance'];

        // open browser
        await authenticateAndWait();
        await navigateAndWait(TEST_DOMAIN_ROLE_URI);

        await createRoleWithMembers(multiSelectRole, headlessUser);

        await waitAndClick(
            `.//*[local-name()="svg" and @id="${multiSelectRole}-setting-role-button"]`
        );

        await waitAndClick('div[class*=denali-multiselect]');
        await waitAndClick('div*=OnShore-US');
        await waitAndClick('div*=DataGovernance');
        await waitAndClick('button*=Submit');

        await waitAndClick('button[data-testid="update-modal-update"]');
        const successAlert = await $('div[id="alert-title"]');

        const dropdownItems = await $$(
            '.denali-multiselect__multi-value__label'
        );

        await expect(successAlert).toHaveText(successAlertText);
        await expect(dropdownItems).toHaveLength(authFilters.length);

        for (let i = 0; i < authFilters.length; i++) {
            await expect(dropdownItems[i]).toHaveText(authFilters[i]);
        }
    });

    afterEach(async () => {
        try {
            switch (currentTest) {
                case TEST_NAME_HISTORY_VISIBLE_AFTER_PAGE_REFRESH:
                    await deleteRoleIfExists(historyTestRole);
                    break;
                case TEST_NAME_DELEGATED_ROLE_ADDITIONAL_SETTINGS_ARE_DISABLED:
                    await deleteRoleIfExists(delegatedRole);
                    break;
                case TEST_NAME_ADD_ROLE_MEMBER_INPUT_PRESERVES_CONTENTS_ON_BLUR:
                    await deleteRoleIfExists(dropdownTestRoleName);
                    break;
                case TEST_NAME_ROLE_REVIEW_EXTEND_DISABLED:
                    await deleteRoleIfExists(reviewExtendTest1);
                    break;
                case TEST_DOMAIN_EXPIRY_ENFORCED_BY_DEFAULT:
                    await deleteRoleIfExists(reviewExtendTest2);
                    await resetDomainExpiry();
                    break;
                case TEST_NAME_DOMAIN_FILTER:
                    await deleteRoleIfExists(domainFilterTest);
                    break;
                case TEST_ADD_ROLE_WITH_MULTIPLE_MEMBERS:
                    await deleteRoleIfExists(multipleMemberRole);
                    break;
                case TEST_MULTISELECT_AUTHORITY_FILTERS:
                    await deleteRoleIfExists(multiSelectRole);
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

    const createRoleWithMembers = async (roleName, ...members) => {
        await waitAndClick('button*=Add Role');
        // modal is open
        await waitAndSetValue('#role-name-input', roleName);
        // add members
        for (const member of members) {
            await waitAndSetValue('input[name="member-name"]', member);
            await waitAndClick(`div*=${member}`);
            await waitAndClick(`button[data-wdio="add-role-member"]`);
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
                    `Status: 409. Message: Role ${roleName} already exists`
                )
            ) {
                throw new Error(
                    `Role "${roleName}" already exists - failing to perform cleanup.`
                );
            }
        } else {
            throw new Error(`Unexpected error during role creation: ${text}`);
        }
    };
});
