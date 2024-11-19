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

const reviewExtendTest = 'review-extend-test';

describe('group screen tests', () => {
    it('group history should be visible when navigating to it and after page refresh', async () => {
        // open browser
        await browser.newUser();
        await browser.url(`/`);
        // select domain
        let domain = 'athenz.dev.functional-test';
        let testDomain = await $(`a*=${domain}`);
        await testDomain.click();

        // ADD test group
        // navigate to groups page
        let groups = await $('div*=Groups');
        await groups.click();
        // open Add Group screen
        let addGroupButton = await $('button*=Add Group');
        await addGroupButton.click();
        // add group info
        let inputGroupName = await $('#group-name-input');
        let groupName = 'history-test-group';
        await inputGroupName.addValue(groupName);
        // add user
        let addMemberInput = await $('[name="member-name"]'); //TODO rename the field
        await addMemberInput.addValue('unix.yahoo');
        let userOption = await $('div*=unix.yahoo');
        await userOption.click();
        // submit role
        let buttonSubmit = await $('button*=Submit');
        await buttonSubmit.click();

        // Verify history entry of added group member is present
        // open history
        let historySvg = await $(
            './/*[local-name()="svg" and @id="group-history-icon-history-test-group"]'
        );
        await historySvg.click();
        // find row with 'ADD'
        let addTd = await $('td=ADD');
        await expect(addTd).toHaveText('ADD');
        // find row with 'unix.yahoo' present
        let spanUnix = await $('span*=unix.yahoo');
        await expect(spanUnix).toHaveText('unix.yahoo');

        // Verify history is displayed after page refresh
        // refresh page
        await browser.refresh();
        // find row with 'ADD'
        addTd = await $('td=ADD');
        await expect(addTd).toHaveText('ADD');
        // find row with 'unix.yahoo' present
        spanUnix = await $('span*=unix.yahoo');
        await expect(spanUnix).toHaveText('unix.yahoo');
    });

    // after - runs after the last test in order of declaration
    after(async () => {
        // open browser
        await browser.newUser();
        await browser.url(`/`);
        // select domain
        let domain = 'athenz.dev.functional-test';
        let testDomain = await $(`a*=${domain}`);
        await testDomain.click();

        // navigate to groups page
        let groups = await $('div*=Groups');
        await groups.click();

        // delete the group used in the test
        let buttonDeleteGroup = await $(
            './/*[local-name()="svg" and @id="delete-group-icon-history-test-group"]'
        );
        await buttonDeleteGroup.click();
        let modalDeleteButton = await $('button*=Delete');
        await modalDeleteButton.click();
    });

    it('dropdown input for adding user during group creation - should preserve input on blur, make input bold when selected in dropdown, reject unselected input', async () => {
        // open browser
        await browser.newUser();
        await browser.url(`/domain/athenz.dev.functional-test/group`);

        // open Add Group modal
        let addGroupButton = await $('button*=Add Group');
        await addGroupButton.click();
        // add group info
        let inputGroupName = await $('#group-name-input');
        let groupName = 'input-dropdown-test-group';
        await inputGroupName.addValue(groupName);
        // add user
        let addMemberInput = await $('[name="member-name"]');
        // add invalid item
        await addMemberInput.addValue('invalidusername');
        // blur
        await browser.keys('Tab');
        // input did not change
        expect(await addMemberInput.getValue()).toBe('invalidusername');
        // input is not bold
        let fontWeight = await addMemberInput.getCSSProperty('font-weight')
            .value;
        expect(fontWeight).toBeUndefined();
        // submit (item in dropdown is not selected)
        let submitButton = await $('button*=Submit');
        await submitButton.click();
        // verify error message
        let errorMessage = await $('div[data-testid="error-message"]');
        expect(await errorMessage.getText()).toBe(
            'Member must be selected in the dropdown or member input field must be empty.'
        );
        // clear input
        let clearInput = await $(
            `.//*[local-name()="svg" and @data-wdio="clear-input"]`
        );
        await clearInput.click();
        // add valid input
        await addMemberInput.addValue('unix.yahoo');
        // click dropdown
        let userOption = await $('div*=unix.yahoo');
        await userOption.click();
        // verify input contains pes service
        expect(await addMemberInput.getValue()).toBe('unix.yahoo');
        // verify input is in bold
        fontWeight = await addMemberInput.getCSSProperty('font-weight');
        expect(fontWeight.value === 700).toBe(true);
    });

    it('Group Review - Extend radio button should be enabled only when Expiry/Review (Days) are set in settings', async () => {
        // open browser
        await browser.newUser();
        await browser.url(`/domain/athenz.dev.functional-test/group`);

        // ADD GROUP WITH USER
        let addGroupBttn = await $('button*=Add Group');
        await addGroupBttn.click();
        // add group info
        let inputGroupName = await $('#group-name-input');
        await inputGroupName.addValue(reviewExtendTest);
        // add user
        let addMemberInput = await $('[name="member-name"]');
        await addMemberInput.addValue('unix.yahoo');
        let userOption = await $('div*=unix.yahoo');
        await userOption.click();
        // submit role
        let buttonSubmit = await $('button*=Submit');
        await buttonSubmit.click();

        // go to review - the extend radio should be disabled
        let reviewSvg = await $(
            `.//*[local-name()="svg" and @data-wdio="${reviewExtendTest}-review"]`
        );
        await reviewSvg.click();
        let extendRadio = await $('input[value="extend"]');
        await expect(extendRadio).toBeDisabled();

        // go to settings set user expiry days, submit
        let settingsDiv = await $('div*=Settings');
        await settingsDiv.click();
        let memberExpiryDays = await $('input[id="setting-memberExpiryDays"]');
        await memberExpiryDays.addValue(10);
        let submitBtn = await $('button*=Submit');
        await submitBtn.click();
        let confirmSubmit = await $(
            'button[data-testid="update-modal-update"]'
        );
        await confirmSubmit.click();
        let alertClose = await $('div[data-wdio="alert-close"]');
        await alertClose.click();

        // go to review - the extend radio should be enabled
        let reviewDiv = await $('div*=Review');
        await reviewDiv.click();
        extendRadio = await $('input[value="extend"]');
        await expect(extendRadio).toBeEnabled();

        // go to settings, set service expiry days, submit
        await settingsDiv.click();
        memberExpiryDays = await $('input[id="setting-memberExpiryDays"]');
        await memberExpiryDays.clearValue();
        await memberExpiryDays.setValue(0);
        let serviceExpiryDays = await $(
            'input[id="setting-serviceExpiryDays"]'
        );
        await serviceExpiryDays.addValue(10);
        await submitBtn.click();
        confirmSubmit = await $('button[data-testid="update-modal-update"]');
        await confirmSubmit.click();
        await alertClose.click();

        // go to review - the extend radio should be enabled
        reviewDiv = await $('div*=Review');
        await reviewDiv.click();
        extendRadio = await $('input[value="extend"]');
        await expect(extendRadio).toBeEnabled();
    });

    // delete group created in previous test
    after(async () => {
        await browser.newUser();
        await browser.url(`/domain/athenz.dev.functional-test/group`);
        await expect(browser).toHaveUrlContaining('athenz');

        await $(
            `.//*[local-name()="svg" and @id="delete-group-icon-${reviewExtendTest}"]`
        ).click();
        await $('button*=Delete').click();
    });
});
