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
    waitAndClick,
    waitAndSetValue,
    waitForElementExist,
    beforeEachTest,
} = require('../libs/helpers');

const dropdownTestPolicyName = 'policy-dropdown-test';
const TEST_NAME_ADD_POLICY_TO_ROLE_SHOULD_PRESERVE_INPUT_ON_BLUR =
    'add policy to new role and existing role - should preserve input on blur, make input bold when selected in dropdown, reject unselected input';

describe('Policies Screen', () => {
    let currentTest;
    beforeEach(async () => {
        await beforeEachTest();
    });

    it(TEST_NAME_ADD_POLICY_TO_ROLE_SHOULD_PRESERVE_INPUT_ON_BLUR, async () => {
        currentTest =
            TEST_NAME_ADD_POLICY_TO_ROLE_SHOULD_PRESERVE_INPUT_ON_BLUR;
        await authenticateAndWait();
        await navigateAndWait(`/domain/athenz.dev.functional-test/policy`);
        await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

        // click add policy
        await waitAndClick('button*=Add Policy');

        await waitAndSetValue(
            'input[id="policy-name"]',
            dropdownTestPolicyName
        );
        await waitAndSetValue('input[id="rule-action"]', 'rule-action');
        await waitAndSetValue('input[id="rule-resource"]', 'rule-resource');

        const invalidRole = 'admi';
        // add random text to modal input
        let roleInput = await $('input[name="rule-role"]');
        await waitAndSetValue(roleInput, invalidRole);

        // blur
        await browser.keys('Tab');

        // input did not change
        expect(await roleInput.getValue()).toBe(invalidRole);

        // input is not bold
        let fontWeight = await roleInput.getCSSProperty('font-weight').value;
        expect(fontWeight).toBeUndefined();

        // submit (item in dropdown is not selected)
        await waitAndClick('button*=Submit');

        // verify error message
        let errorMessage = await waitForElementExist(
            'div[data-testid="error-message"]'
        );
        expect(await errorMessage.getText()).toBe(
            'Role must be selected in the dropdown.'
        );

        // type valid input and select item in dropdown
        let clearInput = await $(
            `.//*[local-name()="svg" and @data-wdio="clear-input"]`
        );
        await waitAndClick(clearInput);
        const validRole = 'admin';
        await waitAndSetValue(roleInput, validRole);
        await waitAndClick(`div*=${validRole}`);

        // verify input contains selected role
        expect(await roleInput.getValue()).toBe(validRole);

        // verify input is in bold
        fontWeight = await roleInput.getCSSProperty('font-weight');
        expect(fontWeight.value === 700).toBe(true);

        // submit
        await waitAndClick('button*=Submit');

        // policy can be seen added
        let policyRow = await waitForElementExist(
            `td*=${dropdownTestPolicyName}`
        );
        await expect(policyRow).toHaveText(
            expect.stringContaining(dropdownTestPolicyName)
        );

        // TEST ADD RULE TO EXISTING POLICY

        // show rules for the policy we created
        await waitAndClick(
            `.//*[local-name()="svg" and @data-wdio="${dropdownTestPolicyName}-rules"]`
        );
        // open add rule window
        await waitAndClick('a*=Add rule');
        // fill the form
        const resource = 'dropdown-test-resource';
        await waitAndSetValue('input[id="rule-action"]', 'rule-action');
        await waitAndSetValue('input[id="rule-resource"]', resource);

        // test incomplete input in dropdown
        roleInput = await $('input[name="rule-role"]');
        await waitAndSetValue(roleInput, invalidRole);

        // blur
        await browser.keys('Tab');

        // input did not change
        expect(await roleInput.getValue()).toBe(invalidRole);

        // input is not bold
        fontWeight = await roleInput.getCSSProperty('font-weight').value;
        expect(fontWeight).toBeUndefined();

        // submit (item in dropdown is not selected)
        await waitAndClick('button*=Submit');

        // verify error message
        errorMessage = await waitForElementExist(
            'div[data-testid="error-message"]'
        );
        expect(await errorMessage.getText()).toBe(
            'Role must be selected in the dropdown.'
        );

        // type valid input and select item in dropdown
        await waitAndClick(
            `.//*[local-name()="svg" and @data-wdio="clear-input"]`
        );
        await waitAndSetValue(roleInput, validRole);

        await waitAndClick(
            `.//div[@role='option' and contains(., '${validRole}')]`
        );

        // verify input contains selected role
        expect(await roleInput.getValue()).toBe(validRole);

        // verify input is in bold
        fontWeight = await roleInput.getCSSProperty('font-weight');
        expect(fontWeight.value === 700).toBe(true);

        // submit
        await waitAndClick('button*=Submit');

        // verify new rule was added
        let newRuleResource = await waitForElementExist(
            `td*=athenz.dev.functional-test:${resource}`
        );
        expect(newRuleResource).toHaveText(
            `athenz.dev.functional-test:${resource}`
        );
    });

    afterEach(async () => {
        try {
            if (
                currentTest ===
                TEST_NAME_ADD_POLICY_TO_ROLE_SHOULD_PRESERVE_INPUT_ON_BLUR
            ) {
                // delete policy created in previous test
                await authenticateAndWait();
                await navigateAndWait(
                    `/domain/athenz.dev.functional-test/policy`
                );
                await expect(browser).toHaveUrl(
                    expect.stringContaining('athenz')
                );

                await waitAndClick(
                    `.//*[local-name()="svg" and @data-wdio="${dropdownTestPolicyName}-delete"]`
                );
                await waitAndClick('button*=Delete');
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
