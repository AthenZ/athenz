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
    navigateAndWait,
    waitAndClick,
    waitAndSetValue,
    authenticateAndWait,
    waitForElement,
    waitForElementExist,
    beforeEachTest,
} = require('../libs/helpers');

describe('Home page', () => {
    beforeEach(async () => {
        await beforeEachTest();
    });

    it('should redirect to okta without credentials', async () => {
        await navigateAndWait('/');
        await expect(browser).toHaveUrl(expect.stringContaining('okta'));
    });

    it('should login with valid credentials', async () => {
        await authenticateAndWait();
        await navigateAndWait('/');
        await expect(browser).toHaveUrl(expect.stringContaining('athenz'));
    });

    // TODO: Update test when able to create a new domain with unique name 'X' and create role against 'X'
    it('should successfully add and delete role', async () => {
        await authenticateAndWait();
        await navigateAndWait('/');

        let testDomain = await $('a*=athenz.dev.functional-test');
        let testRoleName = 'testroleindex';
        await waitAndClick(testDomain);

        await waitAndClick('button*=Add Role');
        await waitAndSetValue('#role-name-input', testRoleName);
        await waitAndClick('button*=Submit');

        let testRole = await $(`span*= ${testRoleName}`);
        await waitForElement(testRole);
        await expect(testRole).toExist();

        await waitAndClick(`#${testRoleName}-delete-role-button`);
        await waitAndClick('button[data-testid="delete-modal-delete"]');

        await waitForElementExist(testRole, { reverse: true });
        await expect(testRole).not.toExist();
    });
});
