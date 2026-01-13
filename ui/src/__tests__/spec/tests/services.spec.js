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
    waitForTabToOpenAndSwitch,
    beforeEachTest,
} = require('../libs/helpers');

const TEST_NAME_TOOLTIP_LINK_OPENS_NEW_TAB =
    'when clicking help tooltip link, it should open a tab with athenz guide';

describe('services screen tests', () => {
    let currentTest;

    beforeEach(async () => {
        // Clear cookies and storage between tests
        await beforeEachTest();
    });

    // TODO: skipping until have stable environment to run this test
    it.skip(TEST_NAME_TOOLTIP_LINK_OPENS_NEW_TAB, async () => {
        currentTest = TEST_NAME_TOOLTIP_LINK_OPENS_NEW_TAB;
        // open browser
        await authenticateAndWait();
        await navigateAndWait(`/`);
        // select domain
        let domain = 'athenz.dev.functional-test';
        await waitAndClick(`a*=${domain}`);

        // open Services
        await waitAndClick('div*=Services');

        // add service
        const serviceName = 'tooltip-link-test-service';
        await waitAndClick('button*=Add Service');
        await waitAndSetValue('input[id="service-name"]', serviceName);
        await waitAndClick('button*=Submit');

        // navigate to tooltip
        await waitAndClick(
            `.//*[local-name()="svg" and @id="${
                'view-instances-' + serviceName
            }"]`
        );
        // open tooltip
        await waitAndClick(
            `.//*[local-name()="svg" and @id="instances-help-tooltip"]`
        );
        // click athenz guide link
        // // await browser.pause(1000); // wait a little so that onclick function is assigned to the anchor
        await waitAndClick('a*=here');
        // await browser.pause(1000); // Just to ensure the new tab opens
        // Wait until a new tab opens
        await waitForTabToOpenAndSwitch();
        // verify the URL of the new tab
        const url = await browser.getUrl();
        expect(
            url.includes('athenz-guide') || url.includes('yo/service-instances')
        ).toBe(true);
    });

    it('when clicking "Allow" button on a provider without having appropriate authorisation, the error should be displayed to the right of the button', async () => {
        // open browser
        await authenticateAndWait();
        await navigateAndWait(`/domain/athenz.dev.test-non-admin/role`);

        // open Services
        await waitAndClick('div*=Services');

        // click Providers
        await waitAndClick(
            `.//*[local-name()="svg" and @id="provider-test-service-providers"]`
        );

        // click Azure provider
        let awsProviderAllowButton = await $(
            `td[data-testid="provider-table"]`
        ).$(
            `//td[text()="AWS EC2/EKS/Fargate launches instances for the service"]/following-sibling::td//button`
        );
        await waitAndClick(awsProviderAllowButton);

        // warning should appear
        let warning = await $(`td[data-testid="provider-table"]`).$(
            `//td[text()="AWS EC2/EKS/Fargate launches instances for the service"]/following-sibling::td//div[text()="Status: 403. Message: Forbidden"]`
        );
        await waitForElementExist(warning);
        await expect(warning).toHaveText('Status: 403. Message: Forbidden');
    });

    afterEach(async () => {
        try {
            if (currentTest === TEST_NAME_TOOLTIP_LINK_OPENS_NEW_TAB) {
                // open browser
                await authenticateAndWait();
                await navigateAndWait(`/`);
                // select domain
                let domain = 'athenz.dev.functional-test';
                await waitAndClick(`a*=${domain}`);

                // open Services
                await waitAndClick('div*=Services');

                // delete service created for the test
                await waitAndClick(
                    './/*[local-name()="svg" and @id="delete-service-tooltip-link-test-service"]'
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
