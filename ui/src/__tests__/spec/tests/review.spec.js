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

const {
    authenticateAndWait,
    navigateAndWait,
    waitAndSetValue,
    waitAndClick,
    beforeEachTest,
} = require('../libs/helpers');

// TODO leaving the review tests skipped for now as we don't have a consistent way to have a member to review
describe.skip('Review user journey', () => {
    beforeEach(async () => {
        await beforeEachTest();
    });

    it('should successfully add, review, and delete role', async () => {
        await authenticateAndWait();
        await navigateAndWait(`/`);

        let domain = 'athenz.dev.functional-test';
        let testDomain = await $(`a*=${domain}`);
        let testRoleName = 'testrole2';
        await waitAndClick(testDomain);

        let addRoleButton = await $('button*=Add Role');
        await waitAndClick(addRoleButton);
        let roleNameInput = await $('#role-name-input');
        await waitAndSetValue(roleNameInput, testRoleName);

        let advancedSettingsToggleButton = await $('#advanced-settings-icon');
        await waitAndClick(advancedSettingsToggleButton);

        let userExpiryDaysInput = await $('#setting-memberExpiryDays');
        await waitAndSetValue(userExpiryDaysInput, '5');

        let userReviewDaysInput = await $('#setting-memberReviewDays');
        await waitAndSetValue(userReviewDaysInput, '5');

        let submitButton = await $('button*=Submit');
        await waitAndClick(submitButton);

        let testRole = await waitForElementExist(`span*= ${testRoleName}`);
        await expect(testRole).toExist();

        await navigateAndWait('/workflow/role');

        let allJustificationInput = await waitForElementExist(
            '#all-justification'
        );
        await waitAndSetValue(allJustificationInput, 'test');

        let submitReviewButton = await $(`#submit-button-${testRoleName}`);
        await waitAndClick(submitReviewButton);
        await expect(submitReviewButton).not.toExist(); // after successful review, button should not exist
        await navigateAndWait(`/domain/${domain}/role`);

        let deleteRoleButton = await $(`#${testRoleName}-delete-role-button`);
        await waitAndClick(deleteRoleButton);

        let confirmDeleteRoleButton = await $(
            'button[data-testid="delete-modal-delete"]'
        );
        await waitAndClick(confirmDeleteRoleButton);
        await expect(testRole).not.toExist();
    });

    it('should successfully add, review, and delete group', async () => {
        let domain = 'athenz.dev.functional-test';
        let testGroupName = 'testgroup';
        await authenticateAndWait();
        await navigateAndWait(`/domain/${domain}/group`);

        let addGroupButton = await $('button*=Add Group');
        await waitAndClick(addGroupButton);
        let groupNameInput = await $('#group-name-input');
        await waitAndSetValue(groupNameInput, testGroupName);

        let submitButton = await $('button*=Submit');
        await waitAndClick(submitButton);

        let testGroup = await waitForElementExist(`span*= ${testGroupName}`);
        await expect(testGroup).toExist();

        let groupSettingsIcon = await $(
            `#group-settings-icon-${testGroupName}`
        );
        await waitAndClick(groupSettingsIcon);

        let userExpiryDaysInput = await $('#setting-memberExpiryDays');
        await waitAndSetValue(userExpiryDaysInput, '5');

        await waitAndClick(submitButton);

        let confirmUpdateGroupButton = await $(
            'button[data-testid="update-modal-update"]'
        );
        await waitAndClick(confirmUpdateGroupButton);

        await navigateAndWait('/workflow/group');

        let allJustificationInput = await waitForElementExist(
            '#all-justification'
        );
        await waitAndSetValue(allJustificationInput, 'test');

        let submitReviewButton = await $(`#submit-button-${testGroupName}`);
        await waitAndClick(submitReviewButton);
        await expect(submitReviewButton).not.toExist(); // after successful review, button should not exist
        await navigateAndWait(`/domain/${domain}/group`);

        let deleteGroupButton = await $(`#delete-group-icon-${testGroupName}`);
        await waitAndClick(deleteGroupButton);

        let confirmDeleteGroupButton = await $(
            'button[data-testid="delete-modal-delete"]'
        );
        await waitAndClick(confirmDeleteGroupButton);
        await expect(testGroup).not.toExist();
    });
});
