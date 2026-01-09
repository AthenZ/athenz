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

const TEST_ENFORCE_AND_REPORT_WITH_TWO_HOSTS_STAR_OR_EMPTY_CANNOT_BE_USED_AS_HOST =
    "in enforce and report mode with two hosts '*' or empty cannot be used as either host";
const TEST_ENFORCEMENT_POLICY_HOSTS_SPACE =
    'Enforcement policy hosts must not contain a space';

const TEST_ADD_POLICY_ENFORCE_AND_REPORT_MULTIPLE_SOURCE_SERVICES =
    'should add a policy with enforce and report modes, multiple source services, and verify all details';
const SERVICE_NAME_ENFORCE_AND_REPORT_MULTIPLE_SOURCE_SERVICES =
    'enforce-report-multi-source-service';
const POLICY_NAME_ENFORCE_AND_REPORT_MULTIPLE_SOURCE_SERVICES =
    'enforce-report-multi-source-policy';

const SERVICE_NAME_TWO_HOSTS = 'two-hosts-test-service';
const TEST_SERVICE = 'test-service';
const TEST_POLICY = 'test-policy';

const POLICY_INSTANCE_ONE = 'test.test.tst1.com';

const TEST_DOMAIN = 'athenz.dev.functional-test';
const TEST_DOMAIN_SERVICE_URI = `/domain/${TEST_DOMAIN}/service`;
const {
    authenticateAndWait,
    navigateAndWait,
    waitAndClick,
    waitAndSetValue,
    waitForElementExist,
    beforeEachTest,
} = require('../libs/helpers');

describe('Microsegmentation', () => {
    let currentTest;
    beforeEach(async () => {
        await beforeEachTest();
    });

    it(
        TEST_ENFORCE_AND_REPORT_WITH_TWO_HOSTS_STAR_OR_EMPTY_CANNOT_BE_USED_AS_HOST,
        async () => {
            currentTest =
                TEST_ENFORCE_AND_REPORT_WITH_TWO_HOSTS_STAR_OR_EMPTY_CANNOT_BE_USED_AS_HOST;
            await authenticateAndWait();
            await navigateAndWait(`/domain/athenz.dev.functional-test/role`);
            await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

            // add service before test
            await waitAndClick('div*=Services');
            await waitAndClick('button*=Add Service');
            await waitAndSetValue(
                'input[data-wdio="service-name"]',
                SERVICE_NAME_TWO_HOSTS
            );
            await waitAndClick('button*=Submit');

            // navigate to Microsegmentation tab
            await waitAndClick('div*=Microsegmentation');
            // click add ACL policy
            await waitAndClick('button*=Add ACL Policy');
            // add identifier
            const policyName = 'noEmptyHostsInPolicyWithTwoHosts';
            await waitAndSetValue('input[data-wdio="identifier"]', policyName);

            // select destination service - TODO will need cleanup
            await waitAndClick('input[name="destinationService"]');
            await waitAndClick(
                `//div[contains(text(), "${SERVICE_NAME_TWO_HOSTS}")]`
            );

            // add PES Host
            await waitAndClick(
                `.//*[local-name()="svg" and @data-wdio="add-circle"]`
            );
            // add first host
            await waitAndSetValue(
                'input[data-wdio="instances0"]',
                POLICY_INSTANCE_ONE
            );
            // leave second hosts empty
            await waitAndSetValue('input[data-wdio="instances1"]', '');

            await waitAndSetValue(
                'input[data-wdio="destination-port"]',
                '4443'
            );
            await waitAndSetValue(
                'input[data-wdio="source-service"]',
                'yamas.api'
            );
            await waitAndClick('input[name="protocol"]');
            await waitAndClick('//div[contains(text(), "TCP")]');

            // attempt to submit
            await waitAndClick('button*=Submit');

            // verify error exists and matches
            let errorMessage = await waitForElementExist(
                'div[data-testid="error-message"]'
            );
            expect(await errorMessage.getText()).toBe(
                'The same host can not exist in both "Report" and "Enforce" modes.'
            );

            // refresh page
            await browser.refresh();

            // check that policy wasn't created - doesn't exist
            let tdWithPolicyNameExists = await $(
                `td=${policyName}`
            ).isExisting();
            await expect(tdWithPolicyNameExists).toBe(false);
        }
    );

    it(TEST_ENFORCEMENT_POLICY_HOSTS_SPACE, async () => {
        currentTest = TEST_ENFORCEMENT_POLICY_HOSTS_SPACE;

        await authenticateAndWait();
        await navigateAndWait(TEST_DOMAIN_SERVICE_URI);

        await waitAndClick('div*=Services');
        await waitAndClick('button*=Add Service');
        await waitAndSetValue('input[data-wdio="service-name"]', TEST_SERVICE);
        await waitAndClick('button*=Submit');

        await waitAndClick('div*=Microsegmentation');
        await waitAndClick('button*=Add ACL Policy');
        await waitAndSetValue('input[data-wdio="identifier"]', TEST_POLICY);

        await waitAndClick('input[name="destinationService"]');
        await waitAndClick(`//div[contains(text(), "${TEST_SERVICE}")]`);

        await waitAndClick(
            `.//*[local-name()="svg" and @data-wdio="add-circle"]`
        );

        await waitAndSetValue(
            'input[data-wdio="instances0"]',
            POLICY_INSTANCE_ONE
        );
        await waitAndSetValue('input[data-wdio="instances1"]', ' ');

        await waitAndSetValue('input[data-wdio="destination-port"]', '4443');

        await waitAndSetValue('input[data-wdio="source-service"]', 'yamas.api');

        await waitAndClick('input[name="protocol"]');
        await waitAndClick('//div[contains(text(), "TCP")]');

        await waitAndClick('button*=Submit');

        // verify error exists and matches
        let errorMessage = await waitForElementExist(
            'div[data-testid="error-message"]'
        );
        expect(await errorMessage.getText()).toBe(
            'Invalid policy enforcement hosts'
        );

        // refresh page
        await browser.refresh();

        // check that policy wasn't created - doesn't exist
        let tdWithPolicyNameExists = await $(`td=${TEST_POLICY}`).isExisting();
        await expect(tdWithPolicyNameExists).toBe(false);
    });

    const deleteService = async (serviceName) => {
        await authenticateAndWait();
        await navigateAndWait(TEST_DOMAIN_SERVICE_URI);
        await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

        // wait for screen to complete loading
        await waitForElementExist('button*=Add Service');

        let deleteSvg = await $(
            `.//*[local-name()="svg" and @id="delete-service-${serviceName}"]`
        );

        // give it time to appear, but don't fail if it doesn't
        const appeared = await deleteSvg
            .waitForExist({ timeout: 5000 })
            .catch(() => false);

        if (!appeared) {
            console.warn(
                `SERVICE FOR DELETION NOT FOUND (after wait): ${serviceName}`
            );
            return;
        }
        // found, proceed to delete
        await waitAndClick(deleteSvg, { timeout: 5000 });
        await waitAndClick('button*=Delete');
    };

    it(
        TEST_ADD_POLICY_ENFORCE_AND_REPORT_MULTIPLE_SOURCE_SERVICES,
        async () => {
            currentTest =
                TEST_ADD_POLICY_ENFORCE_AND_REPORT_MULTIPLE_SOURCE_SERVICES;

            const SERVICE_NAME = 'multi-source-service';
            const HOST_ENFORCE = 'enforce.host.com';
            const HOST_REPORT = 'report.host.com';
            const SOURCE_SERVICE_1 = 'sys.auth.zms';
            const SOURCE_SERVICE_2 = 'sys.auth.zts';

            // Add service
            await authenticateAndWait();
            await navigateAndWait(`/domain/${TEST_DOMAIN}/service`);
            await waitAndClick('div*=Services');
            await waitAndClick('button*=Add Service');
            await waitAndSetValue(
                'input[data-wdio="service-name"]',
                SERVICE_NAME_ENFORCE_AND_REPORT_MULTIPLE_SOURCE_SERVICES
            );
            await waitAndClick('button*=Submit');

            // Go to Microsegmentation tab
            await waitAndClick('div*=Microsegmentation');
            await waitAndClick('button*=Add ACL Policy');

            // Fill identifier
            await waitAndSetValue(
                'input[data-wdio="identifier"]',
                POLICY_NAME_ENFORCE_AND_REPORT_MULTIPLE_SOURCE_SERVICES
            );

            // Select destination service
            await waitAndClick('input[name="destinationService"]');
            await waitAndClick(`//div[contains(text(), "${SERVICE_NAME}")]`);

            // Add two hosts: one for report, one for enforce
            await waitAndClick(
                `.//*[local-name()="svg" and @data-wdio="add-circle"]`
            ); // add second host input
            await waitAndSetValue('input[data-wdio="instances0"]', HOST_REPORT);
            await waitAndSetValue(
                'input[data-wdio="instances1"]',
                HOST_ENFORCE
            );

            // Assuming report is selected for first set of hosts and enforce for second

            // Assuming On-Prem is selected for both first host
            // Select AWS and GCP for second host and deselect On-Prem
            await waitAndClick('label[for="scopeawsCheckBox1"]');
            await waitAndClick('label[for="scopegcpCheckBox1"]');
            await waitAndClick('label[for="scopeonpremCheckBox1"]');

            // Destination port
            await waitAndSetValue(
                'input[data-wdio="destination-port"]',
                '4443'
            );

            // Add multiple source services
            await waitAndSetValue(
                'input[data-wdio="source-service"]',
                `${SOURCE_SERVICE_1},${SOURCE_SERVICE_2}` // Add both source services in one input
            );

            // Protocol
            await waitAndClick('input[name="protocol"]');
            await waitAndClick('//div[contains(text(), "TCP")]');

            // Submit
            // await $('button*=Submit').click();

            // await browser.pause(100000);
            // TODO complete the test after msd fixes
        }
    );

    // cleanup after tests
    afterEach(async () => {
        try {
            // if executed test name matches - cleanup
            if (
                currentTest ===
                TEST_ENFORCE_AND_REPORT_WITH_TWO_HOSTS_STAR_OR_EMPTY_CANNOT_BE_USED_AS_HOST
            ) {
                await deleteService(SERVICE_NAME_TWO_HOSTS);
            } else if (currentTest === TEST_ENFORCEMENT_POLICY_HOSTS_SPACE) {
                await deleteService(TEST_SERVICE);
            } else if (
                currentTest ===
                TEST_ADD_POLICY_ENFORCE_AND_REPORT_MULTIPLE_SOURCE_SERVICES
            ) {
                await deleteService(
                    SERVICE_NAME_ENFORCE_AND_REPORT_MULTIPLE_SOURCE_SERVICES
                );
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
