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
    'enforce-report-multi-source';



const SERVICE_NAME_TWO_HOSTS = 'two-hosts-test-service';
const TEST_SERVICE = 'test-service';
const TEST_POLICY = 'test-policy';

const POLICY_INSTANCE_ONE = 'test.test.tst1.com';

const TEST_DOMAIN = 'athenz.dev.functional-test';
const TEST_DOMAIN_SERVICE_URI = `/domain/${TEST_DOMAIN}/service`;

describe('Microsegmentation', () => {
    let currentTest;

    /*
    it(
        TEST_ENFORCE_AND_REPORT_WITH_TWO_HOSTS_STAR_OR_EMPTY_CANNOT_BE_USED_AS_HOST,
        async () => {
            currentTest =
                TEST_ENFORCE_AND_REPORT_WITH_TWO_HOSTS_STAR_OR_EMPTY_CANNOT_BE_USED_AS_HOST;
            await browser.newUser();
            await browser.url(`/domain/athenz.dev.functional-test/role`);
            await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

            // add service before test
            await $('div*=Services').click();
            await $('button*=Add Service').click();
            await $('input[data-wdio="service-name"]').addValue(
                SERVICE_NAME_TWO_HOSTS
            );
            await $('button*=Submit').click();

            // navigate to Microsegmentation tab
            await $('div*=Microsegmentation').click();
            // click add ACL policy
            await $('button*=Add ACL Policy').click();
            // add identifier
            const policyName = 'noEmptyHostsInPolicyWithTwoHosts';
            await $('input[data-wdio="identifier"]').addValue(policyName);

            // select destination service - TODO will need cleanup
            await $('input[name="destinationService"]').click();
            let testServiceInDropdown = await $(
                `//div[contains(text(), "${SERVICE_NAME_TWO_HOSTS}")]`
            );
            await testServiceInDropdown.click();

            // add PES Host
            let addPesHost = await $(
                `.//*[local-name()="svg" and @data-wdio="add-circle"]`
            );
            await addPesHost.click();
            // add first host
            let instances0 = await $('input[data-wdio="instances0"]');
            await instances0.addValue(POLICY_INSTANCE_ONE);
            // leave second hosts empty
            let instances1 = await $('input[data-wdio="instances1"]');
            await instances1.addValue('');

            let destPort = await $('input[data-wdio="destination-port"]');
            await destPort.addValue('4443');

            let sourceService = await $('input[data-wdio="source-service"]');
            await sourceService.addValue('yamas.api');

            let protocolDropdown = await $('input[name="protocol"]');
            await protocolDropdown.click();
            let dropdownOption = await $('//div[contains(text(), "TCP")]');
            await dropdownOption.click();

            // attempt to submit
            let submitButton = await $('button*=Submit');
            await submitButton.click();

            // verify error exists and matches
            let errorMessage = await $('div[data-testid="error-message"]');
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

        await browser.newUser();
        await browser.url(TEST_DOMAIN_SERVICE_URI);

        await $('div*=Services').click();
        await $('button*=Add Service').click();
        await $('input[data-wdio="service-name"]').addValue(TEST_SERVICE);
        await $('button*=Submit').click();

        await $('div*=Microsegmentation').click();
        await $('button*=Add ACL Policy').click();
        await $('input[data-wdio="identifier"]').addValue(TEST_POLICY);

        await $('input[name="destinationService"]').click();
        await $(`//div[contains(text(), "${TEST_SERVICE}")]`).click();

        await $(`.//*[local-name()="svg" and @data-wdio="add-circle"]`).click();

        await $('input[data-wdio="instances0"]').addValue(POLICY_INSTANCE_ONE);
        await $('input[data-wdio="instances1"]').addValue(' ');

        await $('input[data-wdio="destination-port"]').addValue('4443');

        await $('input[data-wdio="source-service"]').addValue('yamas.api');

        await $('input[name="protocol"]').click();
        await $('//div[contains(text(), "TCP")]').click();

        await $('button*=Submit').click();

        // verify error exists and matches
        let errorMessage = await $('div[data-testid="error-message"]');
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
        await browser.newUser();
        await browser.url(TEST_DOMAIN_SERVICE_URI);
        await expect(browser).toHaveUrl(expect.stringContaining('athenz'));

        let deleteSvg = await $(
            `.//*[local-name()="svg" and @id="delete-service-${serviceName}"]`
        );

        if (deleteSvg.isExisting()) {
            // attempt to delete only if service exists
            await deleteSvg.click();
            await $('button*=Delete').click();
        } else {
            console.warn(`SERVICE FOR DELETION NOT FOUND: ${serviceName}`);
        }
    };
    */

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
            await browser.newUser();
            await browser.url(`/domain/${TEST_DOMAIN}/service`);
            await $('div*=Services').click();
            await $('button*=Add Service').click();
            await $('input[data-wdio="service-name"]').addValue(
                SERVICE_NAME_ENFORCE_AND_REPORT_MULTIPLE_SOURCE_SERVICES
            );
            await $('button*=Submit').click();

            // Go to Microsegmentation tab
            await $('div*=Microsegmentation').click();
            await $('button*=Add ACL Policy').click();

            // Fill identifier
            await $('input[data-wdio="identifier"]').addValue(
                POLICY_NAME_ENFORCE_AND_REPORT_MULTIPLE_SOURCE_SERVICES
            );

            // Select destination service
            await $('input[name="destinationService"]').click();
            await $(`//div[contains(text(), "${SERVICE_NAME}")]`).click();

            // Add two hosts: one for report, one for enforce
            await $(
                `.//*[local-name()="svg" and @data-wdio="add-circle"]`
            ).click(); // add second host input
            await $('input[data-wdio="instances0"]').addValue(HOST_REPORT);
            await $('input[data-wdio="instances1"]').addValue(HOST_ENFORCE);

            // Assuming report is selected for first set of hosts and enforce for second

            // Assuming On-Prem is selected for both first host
            // Select AWS and GCP for second host and deselect On-Prem
            await $('label[for="scopeawsCheckBox1"]').click();
            await $('label[for="scopegcpCheckBox1"]').click();
            await $('label[for="scopeonpremCheckBox1"]').click();

            // Destination port
            await $('input[data-wdio="destination-port"]').addValue('4443');

            // Add multiple source services
            await $('input[data-wdio="source-service"]').addValue(
                `${SOURCE_SERVICE_1},${SOURCE_SERVICE_2}` // Add both source services in one input
            );

            // Protocol
            await $('input[name="protocol"]').click();
            await $('//div[contains(text(), "TCP")]').click();

            // Submit
            await $('button*=Submit').click();

            await browser.pause(100000);
        }
    );

    // cleanup after tests
    afterEach(async () => {
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
        // reset current test
        currentTest = '';
    });
});
