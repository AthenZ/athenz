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

describe('Home page', () => {
    it('should redirect to okta without credentials', async () => {
        await browser.url(`/`);
        await expect(browser).toHaveUrlContaining('okta');
    });

    it('should login with valid credentials', async () => {
        await browser.newUser();
        await browser.url(`/`);
        await expect(browser).toHaveUrlContaining('athenz');
    });

    // TODO: Update test when able to create a new domain with unique name 'X' and create role against 'X'
    it('should successfully add and delete role', async () => {
        let testDomain = await $('a*=athenz.dev.functional-test');
        let testRoleName = 'testroleindex';
        await browser.waitUntil(async () => await testDomain.isClickable());
        await testDomain.click();

        let addRoleButton = await $('button*=Add Role');
        await browser.waitUntil(async () => await addRoleButton.isClickable());
        await addRoleButton.click();
        let roleNameInput = await $('#role-name-input');
        await roleNameInput.addValue(testRoleName);
        let submitButton = await $('button*=Submit');
        await submitButton.click();

        let testRole = await $(`span*= ${testRoleName}`);
        await browser.waitUntil(async () => await testRole.isDisplayed());
        await expect(testRole).toExist();

        let deleteRoleButton = await $(`#${testRoleName}-delete-role-button`);
        await deleteRoleButton.click();

        let confirmDeleteRoleButton = await $(
            'button[data-testid="delete-modal-delete"]'
        );
        await confirmDeleteRoleButton.click();
        await expect(testRole).not.toExist();
    });
});
