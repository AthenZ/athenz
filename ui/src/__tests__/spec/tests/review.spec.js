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

describe('Review user journey', () => {
    it('should successfully add, review, and delete role', async () => {
        await browser.newUser();
        await browser.url(`/`);

        let domain = 'athenz.dev.functional-test';
        let testDomain = await $(`a*=${domain}`);
        let testRoleName = 'testrole2';
        await browser.waitUntil(async () => await testDomain.isClickable());
        await testDomain.click();

        let addRoleButton = await $('button*=Add Role');
        await browser.waitUntil(async () => await addRoleButton.isClickable());
        addRoleButton.click();
        let roleNameInput = await $('#role-name-input');
        await roleNameInput.addValue(testRoleName);

        let advancedSettingsToggleButton = await $('#advanced-settings-icon');
        advancedSettingsToggleButton.click();

        let userExpiryDaysInput = await $('#setting-memberExpiryDays');
        await userExpiryDaysInput.addValue('5');

        let userReviewDaysInput = await $('#setting-memberReviewDays');
        await userReviewDaysInput.addValue('5');

        let submitButton = await $('button*=Submit');
        await submitButton.click();

        let testRole = await $(`span*= ${testRoleName}`);
        await browser.waitUntil(async () => await testRole.isDisplayed());
        await expect(testRole).toExist();

        await browser.url('/workflow/role');

        let allJustificationInput = await $('#all-justification');
        await browser.waitUntil(
            async () => await allJustificationInput.isDisplayed()
        );
        await allJustificationInput.addValue('test');

        let submitReviewButton = await $(`#submit-button-${testRoleName}`);
        await submitReviewButton.click();
        await expect(submitReviewButton).not.toExist(); // after successful review, button should not exist
        await browser.url(`/domain/${domain}/role`);

        let deleteRoleButton = await $(`#${testRoleName}-delete-role-button`);
        await browser.waitUntil(
            async () => await deleteRoleButton.isClickable()
        );
        await deleteRoleButton.click();

        let confirmDeleteRoleButton = await $(
            'button[data-testid="delete-modal-delete"]'
        );
        await confirmDeleteRoleButton.click();
        await expect(testRole).not.toExist();
    });

    it('should successfully add, review, and delete group', async () => {
        let domain = 'athenz.dev.functional-test';
        let testGroupName = 'testgroup';
        await browser.newUser();
        await browser.url(`/domain/${domain}/group`);

        let addGroupButton = await $('button*=Add Group');
        await browser.waitUntil(async () => await addGroupButton.isClickable());
        addGroupButton.click();
        let groupNameInput = await $('#group-name-input');
        await groupNameInput.addValue(testGroupName);

        let submitButton = await $('button*=Submit');
        await submitButton.click();

        let testGroup = await $(`span*= ${testGroupName}`);
        await browser.waitUntil(async () => await testGroup.isDisplayed());
        await expect(testGroup).toExist();

        let groupSettingsIcon = await $(
            `#group-settings-icon-${testGroupName}`
        );
        await browser.waitUntil(
            async () => await groupSettingsIcon.isClickable()
        );
        await groupSettingsIcon.click();

        let userExpiryDaysInput = await $('#setting-memberExpiryDays');
        await browser.waitUntil(
            async () => await userExpiryDaysInput.isDisplayed()
        );
        await userExpiryDaysInput.addValue('5');

        submitButton = await $('button*=Submit');
        await submitButton.click();

        let confirmUpdateGroupButton = await $(
            'button[data-testid="update-modal-update"]'
        );
        await confirmUpdateGroupButton.click();

        await browser.url('/workflow/group');

        let allJustificationInput = await $('#all-justification');
        await browser.waitUntil(
            async () => await allJustificationInput.isDisplayed()
        );
        await allJustificationInput.addValue('test');

        let submitReviewButton = await $(`#submit-button-${testGroupName}`);
        await submitReviewButton.click();
        await expect(submitReviewButton).not.toExist(); // after successful review, button should not exist
        await browser.url(`/domain/${domain}/group`);

        let deleteGroupButton = await $(`#delete-group-icon-${testGroupName}`);
        await browser.waitUntil(
            async () => await deleteGroupButton.isClickable()
        );
        await deleteGroupButton.click();

        let confirmDeleteGroupButton = await $(
            'button[data-testid="delete-modal-delete"]'
        );
        await confirmDeleteGroupButton.click();
        await expect(testGroup).not.toExist();
    });
});
