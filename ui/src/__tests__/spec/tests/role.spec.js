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

describe('role screen tests', () => {
    it('when creating or editing a delegated role, all additional settings except description must be disabled', async () => {
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
        let switchSettingReviewEnabled = await $('#switch-settingreviewEnabled');
        await expect(switchSettingReviewEnabled).toBeDisabled();
        let switchSettingDeleteProtection = await $('#switch-settingdeleteProtection');
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
        let dropdownUserAuthorityFilter = await $('[name="setting-userAuthorityFilter"]');
        await expect(dropdownUserAuthorityFilter).toBeDisabled();
        let dropdownUserAuthorityExpiration = await $('[name="setting-userAuthorityExpiration"]');
        await expect(dropdownUserAuthorityExpiration).toBeDisabled();
        let inputSettingDescription = await $('#setting-description');
        await expect(inputSettingDescription).toBeEnabled();
        let inputMaxMembers = await $('#setting-maxMembers');
        await expect(inputMaxMembers).toBeDisabled();

        // add role info
        let inputRoleName = await $('#role-name-input');
        let roleName = 'delegated-role';
        await inputRoleName.addValue(roleName);
        let inputDelegateTo = await $('#delegated-to-input');
        await inputDelegateTo.addValue('athenz.dev');
        let buttonSubmit = await $('button*=Submit');
        // submit role
        await buttonSubmit.click();

        // find row with 'delegated-role' in name and click settings svg
        let buttonSettingsOfDelegatedRole = await $('.//*[local-name()="svg" and @id="delegated-role-setting-role-button"]');
        await buttonSettingsOfDelegatedRole.click();

        // verify all settings except Description are disabled
        switchSettingReviewEnabled = await $('#switch-settingreviewEnabled');
        await expect(switchSettingReviewEnabled).toBeDisabled();
        switchSettingDeleteProtection = await $('#switch-settingdeleteProtection');
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
        dropdownUserAuthorityFilter = await $('[name="setting-userAuthorityFilter"]');
        await expect(dropdownUserAuthorityFilter).toBeDisabled();
        dropdownUserAuthorityExpiration = await $('[name="setting-userAuthorityExpiration"]');
        await expect(dropdownUserAuthorityExpiration).toBeDisabled();
        inputSettingDescription = await $('#setting-description');
        await expect(inputSettingDescription).toBeEnabled();
        inputMaxMembers = await $('#setting-maxMembers');
        await expect(inputMaxMembers).toBeDisabled();
    });

    // after - runs after the last test in order of declaration
    after(async() => {
        // open browser
        await browser.newUser();
        await browser.url(`/`);
        // select domain
        let domain = 'athenz.dev.functional-test';
        let testDomain = await $(`a*=${domain}`);
        await browser.waitUntil(async () => await testDomain.isClickable());
        await testDomain.click();

        // delete the delegate role used in the test
        // find row with 'delegated-role' in name and click delete on svg
        let buttonDeleteDelegatedRole = await $('.//*[local-name()="svg" and @id="delegated-role-delete-role-button"]');
        await buttonDeleteDelegatedRole.click();
        let modalDeleteButton = await $('button*=Delete');
        await modalDeleteButton.click();
    });
})
