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
    waitForUrl,
    beforeEachTest,
    closeAlert,
} = require('../libs/helpers');
const SERVICE_NAME = 'test-service-search';
const SERVICE_NAME1 = `${SERVICE_NAME}1`;
const SERVICE_NAME2 = `${SERVICE_NAME}2`;

describe('Search functionality tests', () => {
    // BEFORE ALL TESTS - create 2 services
    before(async () => {
        // open browser on services page
        await authenticateAndWait();
        await navigateAndWait(`/domain/athenz.dev.functional-test/service`);

        await createService(SERVICE_NAME1);
        await createService(SERVICE_NAME2);
    });

    beforeEach(async () => {
        // Clear cookies and storage between tests
        await beforeEachTest();
    });

    it('Search for Domain and then repeated search - search for Service from results screen', async () => {
        // open browser
        await authenticateAndWait();
        await navigateAndWait('/');

        // select Services in search type dropdown
        const searchDropdown = await waitAndClick('[name="search-type"]');
        await waitAndClick('div*=Service');
        expect(await $(searchDropdown).getValue()).toBe('Service');

        // input service name
        const searchInput = await waitAndSetValue(
            '[name="search-text"]',
            SERVICE_NAME
        );
        expect(await searchInput.getValue()).toBe(SERVICE_NAME); // to make sure we don't press Enter before search value is in input

        // press Enter to trigger search
        await browser.keys('Enter');

        // Wait until the URL has changed
        const searchResultsUrl = `search/service/${SERVICE_NAME}`;
        await waitForUrl(searchResultsUrl);

        // find the first service link in search results
        const link1 = await $(
            `div[data-wdio="search-result"] a[href*="/service/${SERVICE_NAME1}/instance/dynamic"]`
        );
        const href1 = await link1.getAttribute('href');
        // Validate that the href contains the expected URL
        expect(href1).toContain(`service/${SERVICE_NAME1}/instance/dynamic`);

        // find the second service link in search results
        const link2 = await $(
            `div[data-wdio="search-result"] a[href*="/service/${SERVICE_NAME2}/instance/dynamic"]`
        );
        const href2 = await link2.getAttribute('href');
        // Validate that the href contains the expected URL
        expect(href2).toContain(`service/${SERVICE_NAME2}/instance/dynamic`);
    });

    it('Search for Domain and then repeated search - search for Service from results screen', async () => {
        // open browser
        await authenticateAndWait();
        await navigateAndWait(`/`);

        // search for domain
        const domainName = 'athenz.dev.functional-test';
        const searchInputDomain = await waitAndSetValue(
            '[name="search-text"]',
            domainName
        );
        expect(await searchInputDomain.getValue()).toBe(domainName); // to make sure we don't press Enter before search value is in input
        // press Enter to trigger search
        await browser.keys('Enter');

        // Wait until the URL has changed
        let searchResultsUrl = `search/domain/${domainName}`;
        await waitForUrl(searchResultsUrl);

        const link = await $('div[data-wdio="search-result"] a');
        const href = await link.getAttribute('href');
        // Validate that the href contains the expected URL
        expect(href).toContain(`domain/${domainName}/role`);

        // NOW SEARCH FOR SERVICE
        // select Services in search type dropdown
        await waitAndClick('[name="search-type"]');
        await waitAndClick('div*=Service');

        // input service name
        const searchInput = await $('[name="search-text"]');
        await waitAndSetValue(searchInput, SERVICE_NAME);
        expect(await searchInput.getValue()).toBe(SERVICE_NAME); // to make sure we don't press Enter before search value is in input

        // press Enter to trigger search
        await browser.keys('Enter');

        // Wait until the URL has changed
        searchResultsUrl = `search/service/${SERVICE_NAME}`;
        await waitForUrl(searchResultsUrl);

        // find the first service link in search results
        const link1 = await $(
            `div[data-wdio="search-result"] a[href*="/service/${SERVICE_NAME1}/instance/dynamic"]`
        );
        const href1 = await link1.getAttribute('href');
        // Validate that the href contains the expected URL
        expect(href1).toContain(`service/${SERVICE_NAME1}/instance/dynamic`);

        // find the second service link in search results
        const link2 = await $(
            `div[data-wdio="search-result"] a[href*="/service/${SERVICE_NAME2}/instance/dynamic"]`
        );
        const href2 = await link2.getAttribute('href');
        // Validate that the href contains the expected URL
        expect(href2).toContain(`service/${SERVICE_NAME2}/instance/dynamic`);
    });

    // AFTER ALL TESTS - delete both services
    after(async () => {
        // open browser on services page
        await authenticateAndWait();
        await navigateAndWait(`/domain/athenz.dev.functional-test/service`);

        // delete both services used in the test
        await deleteServiceIfExists(SERVICE_NAME1);
        await deleteServiceIfExists(SERVICE_NAME2);
    });
});

async function deleteServiceIfExists(serviceName) {
    try {
        await waitAndClick(
            `.//*[local-name()="svg" and @id="delete-service-${serviceName}"]`
        );
        await waitAndClick('button*=Delete');
        // close successful deletion notification
        await closeAlert();
    } catch (e) {
        console.error(`Could not delete service ${serviceName}:`, e);
    }
}

async function createService(serviceName) {
    try {
        await waitAndClick('button*=Add Service');
        await waitAndSetValue('[name="service-name"]', serviceName);
        await waitAndClick('button*=Submit');
    } catch (e) {
        console.error(`Could not create service ${serviceName}:`, e);
    }
}
