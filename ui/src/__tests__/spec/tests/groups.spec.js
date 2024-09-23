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
        let historySvg = await $('.//*[local-name()="svg" and @id="group-history-icon-history-test-group"]');
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
    after(async() => {
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
        let buttonDeleteGroup = await $('.//*[local-name()="svg" and @id="delete-group-icon-history-test-group"]');
        await buttonDeleteGroup.click();
        let modalDeleteButton = await $('button*=Delete');
        await modalDeleteButton.click();
    });
})
