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
const {
    authenticateAndWait,
    navigateAndWait,
    waitAndClick,
    waitAndSetValue,
    beforeEachTest,
    closeAlert,
} = require('../libs/helpers');
const testdata = config().testdata;

const userName = testdata.user1.name;
const userId = testdata.user1.id;

const TEST_ADD_ON_CALL_TEAM =
    'modal to add on call team - should successfully save an on call team and have a redirect link';

describe('Domain', () => {
    let currentTest;
    beforeEach(async () => {
        await beforeEachTest();
    });

    it('should successfully add domain point of contact and security poc', async () => {
        await authenticateAndWait();
        await navigateAndWait('/');

        await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

        await waitAndClick('a*=athenz.dev.functional-test');

        // test adding poc
        let pocAnchor = await $('a[data-testid="poc-link"]');
        await waitAndClick(pocAnchor);
        await waitAndSetValue('input[name="poc-name"]', `${userId}`);
        await waitAndClick(`div*=${userName} [${userId}]`);
        await waitAndClick('button*=Submit');
        // close alert
        await closeAlert();
        await expect(pocAnchor).toHaveText(
            expect.stringContaining(`${userName}`)
        );

        // test adding security poc
        let securityPocAnchor = await $('a[data-testid="security-poc-link"]');
        await waitAndClick(securityPocAnchor);
        await waitAndSetValue('input[name="poc-name"]', `${userId}`);
        await waitAndClick(`div*=${userName} [${userId}]`);
        await waitAndClick('button*=Submit');
        // close alert
        await closeAlert();
        await expect(securityPocAnchor).toHaveText(
            expect.stringContaining(`${userName}`)
        );
    });

    it('should successfully add and clear domain slack channel', async () => {
        await authenticateAndWait();
        await navigateAndWait('/');
        await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

        await waitAndClick('a*=athenz.dev.functional-test');

        // expand domain details
        await waitAndClick(
            `.//*[local-name()="svg" and @data-wdio="domain-details-expand-icon"]`
        );

        // click add slack channel
        let addSlackChannel = await $('a[data-testid="add-slack-channel"]');
        await waitAndClick(addSlackChannel);

        let randomInt = Math.floor(Math.random() * 100); // random number to append to slack channel name
        let slackChannelName = 'slack-channel-' + randomInt;
        let slackChannelInput = await $('input[name="slack-channel-input"]');
        await waitAndSetValue(slackChannelInput, slackChannelName);
        await waitAndClick('button*=Submit');
        await expect(addSlackChannel).toHaveText(
            expect.stringContaining(slackChannelName)
        );
    });

    it(TEST_ADD_ON_CALL_TEAM, async () => {
        currentTest = TEST_ADD_ON_CALL_TEAM;

        await authenticateAndWait();
        await navigateAndWait(`/domain/athenz.dev.functional-test/role`);
        await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

        const ONCALL_TEAM_NAME = 'team-1';

        // expand domain details
        await waitAndClick(
            `.//*[local-name()="svg" and @data-wdio="domain-details-expand-icon"]`
        );

        // click add on call team
        await waitAndClick('a[data-testid="add-oncall-team"]');

        await waitAndSetValue(
            'input[id="on-call-team-input"]',
            ONCALL_TEAM_NAME
        );
        await waitAndClick('button*=Submit');
        await closeAlert();

        const editOnCallButton = await $(
            `.//*[local-name()="svg" and @data-wdio="edit-oncall-team"]`
        );

        // verify on call team name has been added
        let addOnCallTeam = await $('a[data-testid="oncall-team-link"]');

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
        await authenticateAndWait();
        // open domain history page
        await navigateAndWait(`/workflow/domain?domain=`);
        await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

        const nonexistentDomain = 'nonexistent.domain';

        // add random text
        let input = await $('input[name="domains-inputd"]');
        await waitAndSetValue(input, nonexistentDomain);

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
        await waitAndClick(clearInput);

        // type valid input and select item in dropdown
        const testDomain = 'athenz.dev.functional-test';
        await waitAndSetValue(input, testDomain);
        await waitAndClick(`div*=${testDomain}`);

        // verify input contains pes service
        expect(await input.getValue()).toBe(testDomain);

        // verify input is in bold
        fontWeight = await input.getCSSProperty('font-weight');
        expect(fontWeight.value === 700).toBe(true);
    });

    afterEach(async () => {
        try {
            // runs after each test and checks what currentTest value was set and executes appropriate cleanup logic if defined
            if (currentTest === TEST_ADD_ON_CALL_TEAM) {
                await authenticateAndWait();
                // open domain history page
                await navigateAndWait(
                    `/domain/athenz.dev.functional-test/role`
                );

                await waitAndClick(
                    './/*[local-name()="svg" and @data-wdio="domain-details-expand-icon"]'
                );

                await waitAndClick(
                    `.//*[local-name()="svg" and @data-wdio="edit-oncall-team"]`
                );

                const onCallInput = await $('input[name="on-call-team-input"]');
                await waitAndSetValue(onCallInput, ' ', {
                    clearFirst: true,
                });

                await waitAndClick('button*=Submit');
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
