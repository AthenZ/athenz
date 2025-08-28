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
const { ONCALL_URL } = require('../../../components/constants/constants');
const testdata = config().testdata;

const userName = testdata.user1.name;
const userId = testdata.user1.id;

const TEST_ADD_ON_CALL_TEAM =
    'modal to add on call team - should successfully save an on call team and have a redirect link';

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
        await userInput.addValue(`${userId}`);
        let userOption = await $(`div*=${userName} [${userId}]`);
        await userOption.click();
        let submitButton = await $('button*=Submit');
        await submitButton.click();
        await expect(pocAnchor).toHaveText(
            expect.stringContaining(`${userName}`)
        );

        // test adding security poc
        let securityPocAnchor = await $('a[data-testid="security-poc-link"]');
        await browser.waitUntil(
            async () => await securityPocAnchor.isClickable()
        );
        await securityPocAnchor.click();
        userInput = await $('input[name="poc-name"]');
        await userInput.addValue(`${userId}`);
        userOption = await $(`div*=${userName} [${userId}]`);
        await userOption.click();
        submitButton = await $('button*=Submit');
        await submitButton.click();
        await expect(securityPocAnchor).toHaveText(
            expect.stringContaining(`${userName}`)
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

    it(TEST_ADD_ON_CALL_TEAM, async () => {
        currentTest = TEST_ADD_ON_CALL_TEAM;

        await browser.newUser();
        await browser.url(`/domain/athenz.dev.functional-test/role`);
        await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

        const ONCALL_TEAM_NAME = 'team-1';

        // expand domain details
        await $(
            `.//*[local-name()="svg" and @data-wdio="domain-details-expand-icon"]`
        ).click();

        // click add on call team
        let addOnCallTeam = await $('a[data-testid="add-oncall-team"]');

        await browser.waitUntil(async () => await addOnCallTeam.isClickable());

        await addOnCallTeam.click();

        await $('input[id="on-call-team-input"]').addValue(ONCALL_TEAM_NAME);
        await $('button*=Submit').click();
        await $('div[data-wdio="alert-close"]').click();

        const editOnCallButton = await $(
            `.//*[local-name()="svg" and @data-wdio="edit-oncall-team"]`
        );

        // verify on call team name has been added
        addOnCallTeam = await $('a[data-testid="oncall-team-link"]');

        const onCallLink = await addOnCallTeam.getAttribute('href');

        await expect(onCallLink).toMatch(
            new RegExp(`^https://.*/teams/${ONCALL_TEAM_NAME}$`)
        );

        await expect(addOnCallTeam).toHaveText(
            expect.stringContaining(ONCALL_TEAM_NAME)
        );

        await expect(editOnCallButton).toExist();
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
        if (currentTest === TEST_ADD_ON_CALL_TEAM) {
            await browser.newUser();
            await browser.url(`/domain/athenz.dev.functional-test/role`);

            await $(
                `.//*[local-name()="svg" and @data-wdio="domain-details-expand-icon"]`
            ).click();

            await $(
                `.//*[local-name()="svg" and @data-wdio="edit-oncall-team"]`
            ).click();

            const onCallInput = await $('input[name="on-call-team-input"]');
            await onCallInput.clearValue();
            await onCallInput.setValue(' ');

            await $('button*=Submit').click();
        }
        // reset current test name
        currentTest = '';
    });
});
