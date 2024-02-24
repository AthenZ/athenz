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

describe('Domain', () => {
    it('should successfully add domain point of contact and security poc', async () => {
        await browser.newUser();
        await browser.url(`/`);
        await expect(browser).toHaveUrlContaining('athenz');

        let testDomain = await $('a*=athenz.dev.functional-test');
        await browser.waitUntil(async () => await testDomain.isClickable());
        await testDomain.click();

        // test adding poc
        let pocAnchor = await $('a[data-testid="poc-link"]');
        await browser.waitUntil(async () => await pocAnchor.isClickable());
        await pocAnchor.click();
        let userInput = await $('input[name="poc-name"]');
        await userInput.addValue('jtsang01');
        let userOption = await $('div*=Jimmy Tsang [user.jtsang01]');
        await userOption.click();
        let submitButton = await $('button*=Submit');
        await submitButton.click();
        await expect(pocAnchor).toHaveTextContaining('Jimmy Tsang');

        // test adding security poc
        let securityPocAnchor = await $('a[data-testid="security-poc-link"]');
        await browser.waitUntil(
            async () => await securityPocAnchor.isClickable()
        );
        await securityPocAnchor.click();
        userInput = await $('input[name="poc-name"]');
        await userInput.addValue('jtsang01');
        userOption = await $('div*=Jimmy Tsang [user.jtsang01]');
        await userOption.click();
        submitButton = await $('button*=Submit');
        await submitButton.click();
        await expect(securityPocAnchor).toHaveTextContaining('Jimmy Tsang');
    });
});
