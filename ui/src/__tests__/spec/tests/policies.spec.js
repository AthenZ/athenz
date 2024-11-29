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

const dropdownTestPolicyName = 'policy-dropdown-test';
const TEST_NAME_ADD_POLICY_TO_ROLE_SHOULD_PRESERVE_INPUT_ON_BLUR =
    'add policy to new role and existing role - should preserve input on blur, make input bold when selected in dropdown, reject unselected input';

describe('Policies Screen', () => {
    let currentTest;
    it(TEST_NAME_ADD_POLICY_TO_ROLE_SHOULD_PRESERVE_INPUT_ON_BLUR, async () => {
        currentTest =
            TEST_NAME_ADD_POLICY_TO_ROLE_SHOULD_PRESERVE_INPUT_ON_BLUR;
        await browser.newUser();
        await browser.url(`/domain/athenz.dev.functional-test/policy`);
        await expect(browser).toHaveUrlContaining('athenz');

        // click add policy
        let addPolicyBtn = await $('button*=Add Policy');
        await browser.waitUntil(async () => await addPolicyBtn.isClickable());
        await addPolicyBtn.click();

        await $('input[id="policy-name"]').addValue(dropdownTestPolicyName);
        await $('input[id="rule-action"]').addValue('rule-action');
        await $('input[id="rule-resource"]').addValue('rule-resource');

        const invalidRole = 'admi';
        // add random text to modal input
        let roleInput = await $('input[name="rule-role"]');
        await roleInput.addValue(invalidRole);

        // blur
        await browser.keys('Tab');

        // input did not change
        expect(await roleInput.getValue()).toBe(invalidRole);

        // input is not bold
        let fontWeight = await roleInput.getCSSProperty('font-weight').value;
        expect(fontWeight).toBeUndefined();

        // submit (item in dropdown is not selected)
        let submitButton = await $('button*=Submit');
        await submitButton.click();

        // verify error message
        let errorMessage = await $('div[data-testid="error-message"]');
        expect(await errorMessage.getText()).toBe(
            'Role must be selected in the dropdown.'
        );

        // type valid input and select item in dropdown
        let clearInput = await $(
            `.//*[local-name()="svg" and @data-wdio="clear-input"]`
        );
        await clearInput.click();
        const validRole = 'admin';
        await roleInput.addValue(validRole);
        let dropdownOption = await $(`div*=${validRole}`);
        await dropdownOption.click();

        // verify input contains selected role
        expect(await roleInput.getValue()).toBe(validRole);

        // verify input is in bold
        fontWeight = await roleInput.getCSSProperty('font-weight');
        expect(fontWeight.value === 700).toBe(true);

        // submit
        submitButton = await $('button*=Submit');
        await submitButton.click();

        // policy can be seen added
        let policyRow = await $(`td*=${dropdownTestPolicyName}`);
        await expect(policyRow).toHaveTextContaining(dropdownTestPolicyName);

        // TEST ADD RULE TO EXISTING POLICY

        // show rules for the policy we created
        await $(
            `.//*[local-name()="svg" and @data-wdio="${dropdownTestPolicyName}-rules"]`
        ).click();
        // open add rule window
        await $('a*=Add rule').click();
        // fill the form
        const resource = 'dropdown-test-resource';
        await $('input[id="rule-action"]').addValue('rule-action');
        await $('input[id="rule-resource"]').addValue(resource);

        // test incomplete input in dropdown
        roleInput = await $('input[name="rule-role"]');
        await roleInput.addValue(invalidRole);

        // blur
        await browser.keys('Tab');

        // input did not change
        expect(await roleInput.getValue()).toBe(invalidRole);

        // input is not bold
        fontWeight = await roleInput.getCSSProperty('font-weight').value;
        expect(fontWeight).toBeUndefined();

        // submit (item in dropdown is not selected)
        submitButton = await $('button*=Submit');
        await submitButton.click();

        // verify error message
        errorMessage = await $('div[data-testid="error-message"]');
        expect(await errorMessage.getText()).toBe(
            'Role must be selected in the dropdown.'
        );

        // type valid input and select item in dropdown
        clearInput = await $(
            `.//*[local-name()="svg" and @data-wdio="clear-input"]`
        );
        await clearInput.click();
        await roleInput.addValue(validRole);

        dropdownOption = await $(
            `.//div[@role='option' and contains(., '${validRole}')]`
        );
        await dropdownOption.click();

        // verify input contains selected role
        expect(await roleInput.getValue()).toBe(validRole);

        // verify input is in bold
        fontWeight = await roleInput.getCSSProperty('font-weight');
        expect(fontWeight.value === 700).toBe(true);

        // submit
        await submitButton.click();

        // verify new rule was added
        let newRuleResource = await $(
            `td*=athenz.dev.functional-test:${resource}`
        );
        expect(newRuleResource).toHaveText(
            `athenz.dev.functional-test:${resource}`
        );
    });

    afterEach(async () => {
        if (
            currentTest ===
            TEST_NAME_ADD_POLICY_TO_ROLE_SHOULD_PRESERVE_INPUT_ON_BLUR
        ) {
            // delete policy created in previous test
            await browser.newUser();
            await browser.url(`/domain/athenz.dev.functional-test/policy`);
            await expect(browser).toHaveUrlContaining('athenz');

            await $(
                `.//*[local-name()="svg" and @data-wdio="${dropdownTestPolicyName}-delete"]`
            ).click();
            await $('button*=Delete').click();
        }

        // reset current test value
        currentTest = '';
    });
});
