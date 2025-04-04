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

const delegatedRole = 'delegated-role';
const dropdownTestRoleName = 'dropdown-test-role';
const reviewExtendTest = 'review-extend-test';
const domainFilterTest = 'domain-filter-test';
const multipleMemberRole = 'multiple-member-role';
const historyTestRole = 'history-test-role';

const TEST_NAME_HISTORY_VISIBLE_AFTER_PAGE_REFRESH =
    'role history should be visible when navigating to it and after page refresh';
const TEST_NAME_DELEGATED_ROLE_ADDITIONAL_SETTINGS_ARE_DISABLED =
    'when creating or editing a delegated role, all additional settings except description must be disabled';
const TEST_NAME_ADD_ROLE_MEMBER_INPUT_PRESERVES_CONTENTS_ON_BLUR =
    'member dropdown when creating a role and adding to existing role - should preserve input on blur, make input bold when selected in dropdown, reject unselected input';
const TEST_NAME_ROLE_REVIEW_EXTEND_DISABLED =
    'Role Review - Extend radio button should be enabled only when Expiry/Review (Days) are set in settings';
const TEST_NAME_DOMAIN_FILTER =
    'Domain Filter - only principals matching specific domain(s) can be added to a role';
const TEST_ADD_ROLE_WITH_MULTIPLE_MEMBERS = 'Add role with multiple members';
const TEST_ROLE_RULE_POLICIES_EXPANDED = "Rule policies for a role are expanded by default when opened";

async function deleteRoleIfExists(roleName) {
    await browser.newUser();
    await browser.url(`/domain/athenz.dev.functional-test/role`);
    await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

    let deleteSvg = await $(
        `.//*[local-name()="svg" and @id="${roleName}-delete-role-button"]`
    );
    if (deleteSvg.isExisting()) {
        await deleteSvg.click();
        await $('button*=Delete').click();
    } else {
        console.warn(`ROLE FOR DELETION NOT FOUND: ${roleName}`);
    }
}

describe('role screen tests', () => {
    let currentTest;

    it(TEST_NAME_HISTORY_VISIBLE_AFTER_PAGE_REFRESH, async () => {
        currentTest = TEST_NAME_HISTORY_VISIBLE_AFTER_PAGE_REFRESH;
        // open browser
        await browser.newUser();
        await browser.url(`/`);
        // select domain
        let domain = 'athenz.dev.functional-test';
        let testDomain = await $(`a*=${domain}`);
        await testDomain.click();

        // ADD test role
        // open Add Role screen
        let addRoleButton = await $('button*=Add Role');
        await addRoleButton.click();
        // add group info
        let inputRoleName = await $('#role-name-input');
        await inputRoleName.addValue(historyTestRole);
        // add user
        let addMemberInput = await $('[name="member-name"]');
        await addMemberInput.addValue('unix.yahoo');
        let userOption = await $('div*=unix.yahoo');
        await userOption.click();
        // submit role
        let buttonSubmit = await $('button*=Submit');
        await buttonSubmit.click();

        // Verify history entry of added role member is present
        // open history
        let historySvg = await $(
            `.//*[local-name()="svg" and @id="${historyTestRole}-history-role-button"]`
        );
        await historySvg.click();
        // find row with 'ADD'
        let addTd = await $('td=ADD');
        await expect(addTd).toHaveText('ADD');
        // find row with 'unix.yahoo' present
        let spanUnix = await $('span*=unix.yahoo');
        await expect(spanUnix).toHaveText('unix.yahoo');

        // Verify history is displayed after page refresh
        // refresh page
        await browser.refresh();
        // find row with 'ADD'
        addTd = await $('td=ADD');
        await expect(addTd).toHaveText('ADD');
        // find row with 'unix.yahoo' present
        spanUnix = await $('span*=unix.yahoo');
        await expect(spanUnix).toHaveText('unix.yahoo');
    });

    it(TEST_NAME_DELEGATED_ROLE_ADDITIONAL_SETTINGS_ARE_DISABLED, async () => {
        currentTest = TEST_NAME_DELEGATED_ROLE_ADDITIONAL_SETTINGS_ARE_DISABLED;
        // open browser
        await browser.newUser();
        await browser.url(`/`);
        // select domain
        let domain = 'athenz.dev.functional-test';
        let testDomain = await $(`a*=${domain}`);
        await browser.waitUntil(async () => await testDomain.isClickable());
        await testDomain.click();

        // open Add Role screen
        let addRoleButton = await $('button*=Add Role');
        await browser.waitUntil(async () => await addRoleButton.isClickable());
        await addRoleButton.click();
        // select Delegated
        let delegatedButton = await $('div*=Delegated');
        await delegatedButton.click();
        // verify all settings except Description are disabled
        let advancedSettingsIcon = await $('#advanced-settings-icon');
        await advancedSettingsIcon.click();
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
        let dropdownUserAuthorityFilter = await $(
            '[name="setting-userAuthorityFilter"]'
        );
        await expect(dropdownUserAuthorityFilter).toBeDisabled();
        let dropdownUserAuthorityExpiration = await $(
            '[name="setting-userAuthorityExpiration"]'
        );
        await expect(dropdownUserAuthorityExpiration).toBeDisabled();
        let inputSettingDescription = await $('#setting-description');
        await expect(inputSettingDescription).toBeEnabled();
        let inputMaxMembers = await $('#setting-maxMembers');
        await expect(inputMaxMembers).toBeDisabled();

        // add role info
        let inputRoleName = await $('#role-name-input');
        await inputRoleName.addValue(delegatedRole);
        let inputDelegateTo = await $('#delegated-to-input');
        await inputDelegateTo.addValue('athenz.dev');
        let buttonSubmit = await $('button*=Submit');
        // submit role
        await buttonSubmit.click();

        // find row with 'delegated-role' in name and click settings svg
        let buttonSettingsOfDelegatedRole = await $(
            `.//*[local-name()="svg" and @id="${delegatedRole}-setting-role-button"]`
        ).getElement();
        await buttonSettingsOfDelegatedRole.click();

        // verify all settings except Description are disabled
        switchSettingReviewEnabled = await $('#switch-settingreviewEnabled');
        await expect(switchSettingReviewEnabled).toBeDisabled();
        switchSettingDeleteProtection = await $(
            '#switch-settingdeleteProtection'
        );
        await expect(switchSettingDeleteProtection).toBeDisabled();
        switchSettingSelfServe = await $('#switch-settingselfServe');
        await expect(switchSettingSelfServe).toBeDisabled();
        switchSettingSelfRenew = await $('#switch-settingselfRenew');
        await expect(switchSettingSelfRenew).toBeDisabled();
        inputSelfRenewMins = await $('#setting-selfRenewMins');
        await expect(inputSelfRenewMins).toBeDisabled();
        inputMemberExpiryDays = await $('#setting-memberExpiryDays');
        await expect(inputMemberExpiryDays).toBeDisabled();
        inputGroupExpiryDays = await $('#setting-groupExpiryDays');
        await expect(inputGroupExpiryDays).toBeDisabled();
        inputGroupReviewDays = await $('#setting-groupReviewDays');
        await expect(inputGroupReviewDays).toBeDisabled();
        inputServiceExpiryDays = await $('#setting-serviceExpiryDays');
        await expect(inputServiceExpiryDays).toBeDisabled();
        inputServiceReviewDays = await $('#setting-serviceReviewDays');
        await expect(inputServiceReviewDays).toBeDisabled();
        inputTokenExpiryMins = await $('#setting-tokenExpiryMins');
        await expect(inputTokenExpiryMins).toBeDisabled();
        inputCertExpiryMins = await $('#setting-certExpiryMins');
        await expect(inputCertExpiryMins).toBeDisabled();
        dropdownUserAuthorityFilter = await $(
            '[name="setting-userAuthorityFilter"]'
        );
        await expect(dropdownUserAuthorityFilter).toBeDisabled();
        dropdownUserAuthorityExpiration = await $(
            '[name="setting-userAuthorityExpiration"]'
        );
        await expect(dropdownUserAuthorityExpiration).toBeDisabled();
        inputSettingDescription = await $('#setting-description');
        await expect(inputSettingDescription).toBeEnabled();
        inputMaxMembers = await $('#setting-maxMembers');
        await expect(inputMaxMembers).toBeDisabled();
    });

    it(TEST_NAME_ADD_ROLE_MEMBER_INPUT_PRESERVES_CONTENTS_ON_BLUR, async () => {
        currentTest =
            TEST_NAME_ADD_ROLE_MEMBER_INPUT_PRESERVES_CONTENTS_ON_BLUR;
        await browser.newUser();
        await browser.url(`/domain/athenz.dev.functional-test/role`);
        await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

        // click add role
        let addRoleBtn = await $('button*=Add Role');
        await addRoleBtn.click();

        await $('input[id="role-name-input"]').addValue(dropdownTestRoleName);

        const invalidMember = 'admi';
        // add random text to modal input
        let memberInput = await $('input[name="member-name"]');
        await memberInput.addValue(invalidMember);

        // blur without causing calendar widget to close other elements
        await browser.keys('Tab');
        await memberInput.click();

        // input did not change
        expect(await memberInput.getValue()).toBe(invalidMember);

        // input is not bold
        let fontWeight = await memberInput.getCSSProperty('font-weight').value;
        expect(fontWeight).toBeUndefined();

        // submit (item in dropdown is not selected)
        let submitButton = await $('button*=Submit');
        await submitButton.click();

        // verify error message
        let errorMessage = await $('div[data-testid="error-message"]');
        expect(await errorMessage.getText()).toBe(
            'Member must be selected in the dropdown or member input field must be empty.'
        );

        // type valid input and select item in dropdown
        let clearInput = await $(
            `.//*[local-name()="svg" and @data-wdio="clear-input"]`
        );
        await clearInput.click();
        const validMember = 'unix.yahoo';
        await memberInput.addValue(validMember);
        let dropdownOption = await $(`div*=${validMember}`);
        await dropdownOption.click();

        // verify input contains selected member
        expect(await memberInput.getValue()).toBe(validMember);

        // verify input is in bold
        fontWeight = await memberInput.getCSSProperty('font-weight');
        expect(fontWeight.value === 700).toBe(true);

        // submit
        submitButton = await $('button*=Submit');
        await submitButton.click();

        // role can be seen added
        let roleRow = await $(
            `div[data-wdio=${dropdownTestRoleName}-role-row]`
        ).$(`span*=${dropdownTestRoleName}`);
        await expect(roleRow).toHaveText(
            expect.stringContaining(dropdownTestRoleName)
        );

        // view role members
        await $(
            `.//*[local-name()="svg" and @data-wdio="${dropdownTestRoleName}-view-members"]`
        ).click();

        // role has added member
        let memberRow = await $(`tr[data-wdio='${validMember}-member-row']`).$(
            `td*=${validMember}`
        );
        await expect(memberRow).toHaveText(
            expect.stringContaining(validMember)
        );

        // delete member
        await $(
            `.//*[local-name()="svg" and @data-wdio="${validMember}-delete-member"]`
        ).click();
        await $('button*=Delete').click();

        // TEST ADD MEMBER TO EXISTING ROLE

        // open add member window
        await $('button*=Add Member').click();

        // test incomplete input in dropdown
        memberInput = await $('input[name="member-name"]');
        await memberInput.addValue(invalidMember);

        // blur
        await browser.keys('Tab');
        await memberInput.click();

        // input did not change
        expect(await memberInput.getValue()).toBe(invalidMember);

        // input is not bold
        fontWeight = await memberInput.getCSSProperty('font-weight').value;
        expect(fontWeight).toBeUndefined();

        // submit (item in dropdown is not selected)
        submitButton = await $('button*=Submit');
        await submitButton.click();

        // verify error message
        errorMessage = await $('div[data-testid="error-message"]');
        expect(await errorMessage.getText()).toBe(
            'Member must be selected in the dropdown.'
        );

        // type valid input and select item in dropdown
        clearInput = await $(
            `.//*[local-name()="svg" and @data-wdio="clear-input"]`
        );
        await clearInput.click();
        await memberInput.addValue(validMember);

        dropdownOption = await $(
            `.//div[@role='option' and contains(., '${validMember}')]`
        );
        await dropdownOption.click();

        // verify input contains selected memeber
        expect(await memberInput.getValue()).toBe(validMember);

        // verify input is in bold
        fontWeight = await memberInput.getCSSProperty('font-weight');
        expect(fontWeight.value === 700).toBe(true);

        // submit
        await submitButton.click();

        // verify new member was added
        let validMemberTd = await $(
            `tr[data-wdio='${validMember}-member-row']`
        ).$(`td*=${validMember}`);
        expect(validMemberTd).toHaveText(`${validMember}`);
    });

    it(TEST_NAME_ROLE_REVIEW_EXTEND_DISABLED, async () => {
        currentTest = TEST_NAME_ROLE_REVIEW_EXTEND_DISABLED;
        // open browser
        await browser.newUser();
        await browser.url(`/domain/athenz.dev.functional-test/role`);

        // ADD ROLE WITH USER
        let addiRoleButton = await $('button*=Add Role');
        await addiRoleButton.click();
        // add group info
        let inputRoleName = await $('#role-name-input');
        await inputRoleName.addValue(reviewExtendTest);
        // add user
        let addMemberInput = await $('[name="member-name"]');
        await addMemberInput.addValue('unix.yahoo');
        let userOption = await $('div*=unix.yahoo');
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

        // go to settings, set user review days, submit
        await settingsDiv.click();
        memberExpiryDays = await $('input[id="setting-memberExpiryDays"]');
        await memberExpiryDays.clearValue();
        await memberExpiryDays.setValue(0);
        let memberReviewDays = await $('input[id="setting-memberReviewDays"]');
        await memberReviewDays.addValue(10);
        await submitBtn.click();
        confirmSubmit = await $('button[data-testid="update-modal-update"]');
        await confirmSubmit.click();
        await alertClose.click();

        // go to review - the extend radio should be enabled
        reviewDiv = await $('div*=Review');
        await reviewDiv.click();
        extendRadio = await $('input[value="extend"]');
        await expect(extendRadio).toBeEnabled();

        // go to settings, set group expiry days, submit
        await settingsDiv.click();
        memberReviewDays = await $('input[id="setting-memberReviewDays"]');
        await memberReviewDays.clearValue();
        await memberReviewDays.setValue(0);
        let groupExpiryDays = await $('input[id="setting-groupExpiryDays"]');
        await groupExpiryDays.addValue(10);
        await submitBtn.click();
        confirmSubmit = await $('button[data-testid="update-modal-update"]');
        await confirmSubmit.click();
        await alertClose.click();

        // go to review - the extend radio should be enabled
        reviewDiv = await $('div*=Review');
        await reviewDiv.click();
        extendRadio = await $('input[value="extend"]');
        await expect(extendRadio).toBeEnabled();

        // go to settings, set group review days, submit
        await settingsDiv.click();
        groupExpiryDays = await $('input[id="setting-groupExpiryDays"]');
        await groupExpiryDays.clearValue();
        await groupExpiryDays.setValue(0);
        let groupReviewDays = await $('input[id="setting-groupReviewDays"]');
        await groupReviewDays.addValue(10);
        await submitBtn.click();
        confirmSubmit = await $('button[data-testid="update-modal-update"]');
        await confirmSubmit.click();
        await alertClose.click();

        // go to review - the extend radio should be enabled
        reviewDiv = await $('div*=Review');
        await reviewDiv.click();
        extendRadio = await $('input[value="extend"]');
        await expect(extendRadio).toBeEnabled();

        // go to settings, set service review days, submit
        await settingsDiv.click();
        groupReviewDays = await $('input[id="setting-groupReviewDays"]');
        await groupReviewDays.clearValue();
        await groupReviewDays.setValue(0);
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

        // go to settings, set service expiry days, submit
        await settingsDiv.click();
        serviceExpiryDays = await $('input[id="setting-serviceExpiryDays"]');
        await serviceExpiryDays.clearValue();
        await serviceExpiryDays.setValue(0);
        let serviceReviewDays = await $(
            'input[id="setting-serviceReviewDays"]'
        );
        await serviceReviewDays.addValue(10);
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

    it(TEST_NAME_DOMAIN_FILTER, async () => {
        currentTest = TEST_NAME_DOMAIN_FILTER;
        // open browser
        await browser.newUser();
        await browser.url(`/domain/athenz.dev.functional-test/role`);

        // open add role modal
        let addiRoleButton = await $('button*=Add Role');
        await addiRoleButton.click();
        // add role name
        let inputRoleName = await $('#role-name-input');
        await inputRoleName.addValue(domainFilterTest);
        // specify domain
        let advancedSettingsIcon = await $('#advanced-settings-icon');
        await advancedSettingsIcon.click();
        let principalDomainFilter = await $('#setting-principalDomainFilter');
        await principalDomainFilter.addValue('athenz');
        // attempt to submit a member that doesn't belong to specified domain
        // add user
        const user = 'user.aporss';
        let memberInput = await $('input[name="member-name"]');
        await memberInput.addValue(user);
        let dropdownOption = await $(`div*=${user}`);
        await dropdownOption.click();
        // submit
        let submitButton = await $('button*=Submit');
        await submitButton.click();
        // verify fail message
        let errorMessage = await $('div[data-testid="error-message"]');
        await expect(await errorMessage.getText()).toBe(
            `Status: 400. Message: Principal ${user} is not allowed for the role`
        );
        // change to specified domain
        await principalDomainFilter.clearValue();
        await principalDomainFilter.addValue('user');
        // submit - success
        await submitButton.click();
        // view role members
        await $(
            `.//*[local-name()="svg" and @data-wdio="${domainFilterTest}-view-members"]`
        ).click();
        // verify member was added to the role
        let memberRow = await $(`tr[data-wdio='${user}-member-row']`).$(
            `td*=${user}`
        );
        await expect(memberRow).toHaveText(expect.stringContaining(user));

        // check that domain filter applies to an existing role
        // let's reuse the role created above
        await $('button*=Add Member').click();
        // attempt to add unix user
        const unix = 'unix.yahoo';
        memberInput = await $('input[name="member-name"]');
        await memberInput.addValue(unix);
        await $(`div*=${unix}`).click();
        // submit
        await $('button*=Submit').click();
        // verify fail message - unix domain is not registered in the filter yet
        errorMessage = await $('div[data-testid="error-message"]');
        expect(await errorMessage.getText()).toBe(
            `Status: 400. Message: Principal ${unix} is not allowed for the role`
        );
        // close modal
        await $('button*=Cancel').click();

        // let's add unix user to domain filter in role settings
        await $('div*=Settings').click();
        principalDomainFilter = await $('#setting-principalDomainFilter');
        await principalDomainFilter.clearValue();
        await principalDomainFilter.addValue('user,unix');
        // submit
        await $('button*=Submit').click();
        await $('button[data-testid="update-modal-update"]').click();

        // now it must be possible to add member of a unix domain
        // add unix user
        await $('div*=Members').click();
        await $('button*=Add Member').click();
        await $('input[name="member-name"]').addValue(unix);
        await $(`div*=${unix}`).click();
        // submit
        await $('button*=Submit').click();
        // check new member was added
        memberRow = await $(`tr[data-wdio='${unix}-member-row']`).$(
            `td*=${unix}`
        );
        await expect(memberRow).toHaveText(expect.stringContaining(unix));
    });

    it('Pressing Cmd + Click on a role group links opens a new tab', async () => {
        // uses existing role group
        // open browser
        await browser.newUser();
        await browser.url(`/domain/athenz.dev.functional-test/role`);

        // expand aws roles
        let rolesExpand = await $(
            './/*[local-name()="svg" and @data-wdio="AWS-roles-expand"]'
        );
        await rolesExpand.click();

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
        await awsRoleMembersIcon.click();
        // Release all actions to reset states
        await browser.releaseActions();

        await browser.pause(1000); // Just to ensure the new tab opens
        // switch to opened tab
        const windowHandles = await browser.getWindowHandles();
        expect(windowHandles.length).toBeGreaterThan(1);
        const tab = windowHandles.length - 1;
        await browser.switchToWindow(windowHandles[tab]);
        // verify the URL of the new tab
        const url = await browser.getUrl();
        expect(
            url.includes(
                `domain/athenz.dev.functional-test/role/${awsRole}/members`
            )
        ).toBe(true);

        // to check if we are on aws role page, seek for aws user in the role
        const awsUser = $(`div*='athens.aws.*'`);
        expect(awsUser).toHaveText('athens.aws.*');
    });

    it(TEST_ADD_ROLE_WITH_MULTIPLE_MEMBERS, async () => {
        currentTest = TEST_ADD_ROLE_WITH_MULTIPLE_MEMBERS;
        // open browser
        await browser.newUser();
        await browser.url(`/domain/athenz.dev.functional-test/role`);

        // open add role modal
        let addRoleButton = await $('button*=Add Role');
        await addRoleButton.click();
        // add role name
        let inputRoleName = await $('#role-name-input');
        await inputRoleName.addValue(multipleMemberRole);
        // add user 1
        const user1 = 'unix.yahoo';
        let memberInput = await $('input[name="member-name"]');
        await memberInput.addValue(user1);
        await $(`div*=${user1}`).click();
        await browser.pause(1000);
        await $(`button[data-wdio="add-role-member"]`).click();
        await browser.pause(1000);
        // add second user
        const user2 = 'user.aporss';
        await $('input[name="member-name"]').addValue(user2);
        await browser.pause(1000);
        await $(`div*=${user2}`).click();
        await browser.pause(1000);
        await $(`button[data-wdio="add-role-member"]`).click();
        // submit
        await browser.pause(1000);
        await $('button*=Submit').click();

        // verify both members were added to the role
        await $(
            `.//*[local-name()="svg" and @data-wdio="${multipleMemberRole}-view-members"]`
        ).click();
        let memberRow1 = await $(`tr[data-wdio='${user1}-member-row']`).$(
            `td*=${user1}`
        );
        await expect(memberRow1).toHaveText(expect.stringContaining(user1));
        let memberRow2 = await $(`tr[data-wdio='${user2}-member-row']`).$(
            `td*=${user2}`
        );
        await expect(memberRow2).toHaveText(expect.stringContaining(user2));
    });

    it(TEST_ROLE_RULE_POLICIES_EXPANDED, async () => {
        const adminRole = 'admin';

        // open browser
        await browser.newUser();
        await browser.url(`/domain/athenz.dev.functional-test/role`);

        // verify rule policy is expanded by default for role
        await $(
            `.//*[local-name()="svg" and @data-wdio="${adminRole}-policy-rules"]`
        ).click();

        const roleRow = await $(`tr[data-wdio='${adminRole}-policy-rule-row']`).$(
            `td*=${adminRole}`
        );

        await expect(roleRow).toHaveText(expect.stringContaining(`athenz.dev.functional-test:role.${adminRole}`));
    });

    afterEach(async () => {
        if (currentTest === TEST_NAME_HISTORY_VISIBLE_AFTER_PAGE_REFRESH) {
            await deleteRoleIfExists(historyTestRole);
        } else if (
            currentTest ===
            TEST_NAME_DELEGATED_ROLE_ADDITIONAL_SETTINGS_ARE_DISABLED
        ) {
            await deleteRoleIfExists(delegatedRole);
        } else if (
            currentTest ===
            TEST_NAME_ADD_ROLE_MEMBER_INPUT_PRESERVES_CONTENTS_ON_BLUR
        ) {
            await deleteRoleIfExists(dropdownTestRoleName);
        } else if (currentTest === TEST_NAME_ROLE_REVIEW_EXTEND_DISABLED) {
            await deleteRoleIfExists(reviewExtendTest);
        } else if (currentTest === TEST_NAME_DOMAIN_FILTER) {
            await deleteRoleIfExists(domainFilterTest);
        } else if (currentTest === TEST_ADD_ROLE_WITH_MULTIPLE_MEMBERS) {
            await deleteRoleIfExists(multipleMemberRole);
        }

        // reset current test
        currentTest = '';
    });
});
