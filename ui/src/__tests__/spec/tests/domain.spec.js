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

const TEST_ADD_BUSINESS_SERVICE_INPUT_PRESERVES_CONTENTS_ON_BLUR =
    'modal to add business service - should preserve input on blur, make input bold when selected in dropdown, reject unselected input, allow submission of empty input';
const TEST_MANAGE_DOMAINS_CHANGE_BUSINESS_SERVICE_INPUT_PRESERVES_CONTENTS_ON_BLUR =
    'Manage Domains - modal to change add business service - should preserve input on blur, make input bold when selected in dropdown, reject unselected input';

describe('Domain', () => {
    let currentTest;

    it('should successfully add domain point of contact and security poc', async () => {
        await browser.newUser();
        await browser.url(`/`);
        await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

        let testDomain = await $('a*=athenz.dev.functional-test');
        await browser.waitUntil(async () => await testDomain.isClickable());
        await testDomain.click();

        // test adding poc
        let pocAnchor = await $('a[data-testid="poc-link"]');
        await browser.waitUntil(async () => await pocAnchor.isClickable());
        await pocAnchor.click();
        let userInput = await $('input[name="poc-name"]');
        await userInput.addValue('craman');
        let userOption = await $('div*=Chandu Raman [user.craman]');
        await userOption.click();
        let submitButton = await $('button*=Submit');
        await submitButton.click();
        await expect(pocAnchor).toHaveText(
            expect.stringContaining('Chandu Raman')
        );

        // test adding security poc
        let securityPocAnchor = await $('a[data-testid="security-poc-link"]');
        await browser.waitUntil(
            async () => await securityPocAnchor.isClickable()
        );
        await securityPocAnchor.click();
        userInput = await $('input[name="poc-name"]');
        await userInput.addValue('craman');
        userOption = await $('div*=Chandu Raman [user.craman]');
        await userOption.click();
        submitButton = await $('button*=Submit');
        await submitButton.click();
        await expect(securityPocAnchor).toHaveText(
            expect.stringContaining('Chandu Raman')
        );
    });

    it('should successfully add and clear domain slack channel', async () => {
        await browser.newUser();
        await browser.url(`/`);
        await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

        let testDomain = await $('a*=athenz.dev.functional-test');
        await browser.waitUntil(async () => await testDomain.isClickable());
        await testDomain.click();

        // expand domain details
        let expand = await $(
            `.//*[local-name()="svg" and @data-wdio="domain-details-expand-icon"]`
        );
        await expand.click();

        // click add slack channel
        let addSlackChannel = await $('a[data-testid="add-slack-channel"]');
        await browser.waitUntil(
            async () => await addSlackChannel.isClickable()
        );
        await addSlackChannel.click();

        let randomInt = Math.floor(Math.random() * 100); // random number to append to slack channel name
        let slackChannelName = 'slack-channel-' + randomInt;
        let slackChannelInput = await $('input[name="slack-channel-input"]');
        await slackChannelInput.clearValue();
        await slackChannelInput.addValue(slackChannelName);
        let submitButton = await $('button*=Submit');
        await submitButton.click();
        await expect(addSlackChannel).toHaveText(
            expect.stringContaining(slackChannelName)
        );
    });

    it(TEST_ADD_BUSINESS_SERVICE_INPUT_PRESERVES_CONTENTS_ON_BLUR, async () => {
        currentTest =
            TEST_ADD_BUSINESS_SERVICE_INPUT_PRESERVES_CONTENTS_ON_BLUR;
        await browser.newUser();
        await browser.url(`/domain/athenz.dev.functional-test/role`);
        await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

        // expand domain details
        let expand = await $(
            `.//*[local-name()="svg" and @data-wdio="domain-details-expand-icon"]`
        );
        await expand.click();

        // click add business service
        let addBusinessService = await $(
            'a[data-testid="add-business-service"]'
        );
        await browser.waitUntil(
            async () => await addBusinessService.isClickable()
        );
        await addBusinessService.click();

        await browser.pause(2000); // wait to make sure dropdown options are loaded

        // add random text to modal input
        let bsInput = await $('input[name="business-service-drop"]');
        await bsInput.addValue('nonexistent.service');

        // blur
        await browser.keys('Tab');

        // input did not change
        expect(await bsInput.getValue()).toBe('nonexistent.service');

        // input is not bold
        let fontWeight = await bsInput.getCSSProperty('font-weight').value;
        expect(fontWeight).toBeUndefined();

        // submit (item in dropdown is not selected)
        let submitButton = await $('button*=Submit');
        await submitButton.click();

        // verify error message
        let errorMessage = await $('div[data-testid="error-message"]');
        expect(await errorMessage.getText()).toBe(
            'Business Service must be selected in the dropdown or clear input before submitting'
        );

        // unclick checkbox to allow selection of business services not associated with current account
        let checkbox = await $('input[id="checkbox-show-all-bservices"]');
        await browser.execute(function (checkboxElem) {
            checkboxElem.click();
        }, checkbox);

        // type valid input and select item in dropdown
        let clearInput = await $(
            `.//*[local-name()="svg" and @data-wdio="clear-input"]`
        );
        await clearInput.click();
        // make dropdown visible
        await bsInput.click();
        await bsInput.addValue('PolicyEnforcementService.GLB');
        let dropdownOption = await $(
            '//div[contains(text(), "PolicyEnforcementService.GLB")]'
        );
        await dropdownOption.click();

        // verify input contains pes service
        expect(await bsInput.getValue()).toBe('PolicyEnforcementService.GLB');

        // verify input is in bold
        fontWeight = await bsInput.getCSSProperty('font-weight');
        expect(fontWeight.value === 700).toBe(true);

        // submit
        submitButton = await $('button*=Submit');
        await submitButton.click();

        // business service can be seen added to domain
        addBusinessService = await $('a[data-testid="add-business-service"]');
        await expect(addBusinessService).toHaveText(
            expect.stringContaining('PolicyEnforcementService.GLB')
        );
    });

    it(
        TEST_MANAGE_DOMAINS_CHANGE_BUSINESS_SERVICE_INPUT_PRESERVES_CONTENTS_ON_BLUR,
        async () => {
            currentTest =
                TEST_MANAGE_DOMAINS_CHANGE_BUSINESS_SERVICE_INPUT_PRESERVES_CONTENTS_ON_BLUR;

            await browser.newUser();

            // open athenz manage domains page
            await browser.url(`/domain/manage`);
            await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

            // click add business service
            let addBusinessService = await $(
                'a[data-testid="business-service-athenz.dev.functional-test"]'
            );
            await addBusinessService.click();

            await browser.pause(4000); // wait to make sure dropdown options are loaded

            // add random text
            let bsInput = await $('input[name="business-service-drop"]');
            await bsInput.addValue('nonexistent.service');

            // blur
            await browser.keys('Tab');

            // input did not change
            expect(await bsInput.getValue()).toBe('nonexistent.service');

            // input is not bold
            let fontWeight = await bsInput.getCSSProperty('font-weight').value;
            expect(fontWeight).toBeUndefined();

            // submit (item in dropdown is not selected)
            let submitButton = await $('button*=Submit');
            await submitButton.click();

            // verify error message
            let errorMessage = await $('div[data-testid="error-message"]');
            expect(await errorMessage.getText()).toBe(
                'Business Service must be selected in the dropdown'
            );

            let clearInput = await $(
                `.//*[local-name()="svg" and @data-wdio="clear-input"]`
            );
            await clearInput.click();

            let checkbox = await $('input[id="checkbox-show-all-bservices"]');
            await browser.execute(function (checkboxElem) {
                checkboxElem.click();
            }, checkbox);

            // make dropdown visible
            await bsInput.click();
            // type valid input and select item in dropdown
            await bsInput.addValue('PolicyEnforcementService.GLB');
            let dropdownOption = await $('div*=PolicyEnforcementService.GLB');
            await dropdownOption.click();

            // verify input contains pes service
            expect(await bsInput.getValue()).toBe(
                'PolicyEnforcementService.GLB'
            );

            // verify input is in bold
            fontWeight = await bsInput.getCSSProperty('font-weight');
            expect(fontWeight.value === 700).toBe(true);

            // submit
            submitButton = await $('button*=Submit');
            await submitButton.click();

            // business service can be seen added to domain
            addBusinessService = await $(
                'a[data-testid="business-service-athenz.dev.functional-test"]'
            );
            await expect(addBusinessService).toHaveText(
                expect.stringContaining('PolicyEnforcementService.GLB')
            );
        }
    );

    it('Domain History - modal to change add business service - should preserve input on blur, make input bold when selected in dropdown', async () => {
        await browser.newUser();

        // open domain history page
        await browser.url(`/domain/athenz.dev.functional-test/history`);
        await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

        const nonexistentRole = 'nonexistent.role';

        // add random text
        let input = await $('input[name="roles"]');
        await input.addValue(nonexistentRole);

        // blur
        await browser.keys('Tab');

        // input did not change
        expect(await input.getValue()).toBe(nonexistentRole);

        // input is not bold
        let fontWeight = await input.getCSSProperty('font-weight').value;
        expect(fontWeight).toBeUndefined();

        let clearInput = await $(
            `.//*[local-name()="svg" and @data-wdio="clear-input"]`
        );
        await clearInput.click();

        // type valid input and select item in dropdown
        await input.addValue('admin');
        let dropdownOption = await $('div*=admin');
        await dropdownOption.click();

        // verify input contains pes service
        expect(await input.getValue()).toBe('admin');

        // verify input is in bold
        fontWeight = await input.getCSSProperty('font-weight');
        expect(fontWeight.value === 700).toBe(true);
    });

    it('Domain Workflow - input to select dommain - should preserve input on blur, make input bold when selected in dropdown', async () => {
        await browser.newUser();

        // open domain history page
        await browser.url(`/workflow/domain?domain=`);
        await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

        const nonexistentDomain = 'nonexistent.domain';

        // add random text
        let input = await $('input[name="domains-inputd"]');
        await input.addValue(nonexistentDomain);

        // blur
        await browser.keys('Tab');

        // input did not change
        expect(await input.getValue()).toBe(nonexistentDomain);

        // input is not bold
        let fontWeight = await input.getCSSProperty('font-weight').value;
        expect(fontWeight).toBeUndefined();

        let clearInput = await $(
            `.//*[local-name()="svg" and @data-wdio="clear-input"]`
        );
        await clearInput.click();

        // type valid input and select item in dropdown
        const testDomain = 'athenz.dev.functional-test';
        await input.addValue(testDomain);
        let dropdownOption = await $(`div*=${testDomain}`);
        await dropdownOption.click();

        // verify input contains pes service
        expect(await input.getValue()).toBe(testDomain);

        // verify input is in bold
        fontWeight = await input.getCSSProperty('font-weight');
        expect(fontWeight.value === 700).toBe(true);
    });

    afterEach(async () => {
        // runs after each test and checks what currentTest value was set and executes appropriate cleanup logic if defined
        if (
            currentTest ===
                TEST_ADD_BUSINESS_SERVICE_INPUT_PRESERVES_CONTENTS_ON_BLUR ||
            currentTest ===
                TEST_MANAGE_DOMAINS_CHANGE_BUSINESS_SERVICE_INPUT_PRESERVES_CONTENTS_ON_BLUR
        ) {
            // remove business service name that was added during test
            await browser.newUser();
            await browser.url(`/domain/athenz.dev.functional-test/role`);

            // expand domain details
            let expand = await $(
                `.//*[local-name()="svg" and @data-wdio="domain-details-expand-icon"]`
            );
            await expand.click();

            // click add business service
            let addBusinessService = await $(
                'a[data-testid="add-business-service"]'
            );
            await browser.waitUntil(
                async () => await addBusinessService.isClickable()
            );
            await addBusinessService.click();

            let bsInput = await $('input[name="business-service-drop"]');
            let inputText = await bsInput.getValue();
            console.log(inputText);
            // if business service is present - clear and submit
            if (inputText !== '') {
                // clear current input
                let clearInput = await $(
                    `.//*[local-name()="svg" and @data-wdio="clear-input"]`
                );
                await browser.waitUntil(
                    async () => await clearInput.isClickable()
                );
                await clearInput.click();

                let submitButton = await $('button*=Submit');
                await submitButton.click();
            }
        }
        // reset current test name
        currentTest = '';
    });
});
