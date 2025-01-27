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

const SERVICE_NAME = 'test-service-search';
const SERVICE_NAME1 = `${SERVICE_NAME}1`;
const SERVICE_NAME2 = `${SERVICE_NAME}2`;

describe('Search functionality tests', () => {
    // BEFORE ALL TESTS - create 2 services
    before(async () => {
        // open browser on services page
        await browser.newUser();
        await browser.url(`/domain/athenz.dev.functional-test/service`);

        // add first service
        await $('button*=Add Service').click();
        await $('[name="service-name"]').addValue(SERVICE_NAME1);
        await $('button*=Submit').click();

        // add second service
        await $('button*=Add Service').click();
        await $('[name="service-name"]').addValue(SERVICE_NAME2);
        await $('button*=Submit').click();
    });

    it('Search for Domain and then repeated search - search for Service from results screen', async () => {
        // open browser
        await browser.newUser();
        await browser.url(`/`);

        // search for domain
        const domainName = 'athenz.dev.functional-test';

        // select Services in search type dropdown
        await $('[name="search-type"]').click();
        await $('div*=Service').click();

        // input service name
        const searchInput = await $('[name="search-text"]');
        await searchInput.clearValue();
        await searchInput.addValue(SERVICE_NAME);
        expect(await searchInput.getValue()).toBe(SERVICE_NAME); // to make sure we don't press Enter before search value is in input

        // press Enter to trigger search
        await browser.keys('Enter');

        // Wait until the URL has changed
        searchResultsUrl = `search/service/${SERVICE_NAME}`;
        await browser.waitUntil(
            async () => {
                const newUrl = await browser.getUrl();
                return newUrl.includes(searchResultsUrl); // Return true if the URL has changed
            },
            {
                timeout: 5000, // Maximum time to wait
                timeoutMsg: `URL did not change to "${searchResultsUrl}" within the expected time`,
            }
        );

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
        await browser.newUser();
        await browser.url(`/`);

        // search for domain
        const domainName = 'athenz.dev.functional-test';
        await $('[name="search-text"]').addValue(domainName);
        expect(await $('[name="search-text"]').getValue()).toBe(domainName); // to make sure we don't press Enter before search value is in input
        // press Enter to trigger search
        await browser.keys('Enter');

        // Wait until the URL has changed
        let searchResultsUrl = `search/domain/${domainName}`;
        await browser.waitUntil(
            async () => {
                const newUrl = await browser.getUrl();
                return newUrl.includes(searchResultsUrl); // Return true if the URL has changed
            },
            {
                timeout: 5000, // Maximum time to wait
                timeoutMsg: `URL did not change to "${searchResultsUrl}" within the expected time`,
            }
        );

        const link = await $('div[data-wdio="search-result"] a');
        const href = await link.getAttribute('href');
        // Validate that the href contains the expected URL
        expect(href).toContain(`domain/${domainName}/role`);

        // NOW SEARCH FOR SERVICE
        // select Services in search type dropdown
        await $('[name="search-type"]').click();
        await $('div*=Service').click();

        // input service name
        const searchInput = await $('[name="search-text"]');
        await searchInput.clearValue();
        await searchInput.addValue(SERVICE_NAME);
        expect(await searchInput.getValue()).toBe(SERVICE_NAME); // to make sure we don't press Enter before search value is in input

        // press Enter to trigger search
        await browser.keys('Enter');

        // Wait until the URL has changed
        searchResultsUrl = `search/service/${SERVICE_NAME}`;
        await browser.waitUntil(
            async () => {
                const newUrl = await browser.getUrl();
                return newUrl.includes(searchResultsUrl); // Return true if the URL has changed
            },
            {
                timeout: 5000, // Maximum time to wait
                timeoutMsg: `URL did not change to "${searchResultsUrl}" within the expected time`,
            }
        );

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
        await browser.newUser();
        await browser.url(`/domain/athenz.dev.functional-test/service`);

        // delete both services used in the test
        await $(
            `.//*[local-name()="svg" and @id="delete-service-${SERVICE_NAME1}"]`
        ).click();
        await $('button*=Delete').click();

        // close successful deletion notification
        await $('div[data-wdio="alert-close"]').click();

        await $(
            `.//*[local-name()="svg" and @id="delete-service-${SERVICE_NAME2}"]`
        ).click();
        await $('button*=Delete').click();
    });
});
