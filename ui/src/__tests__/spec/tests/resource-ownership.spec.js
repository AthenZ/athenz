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

/**
 * WebdriverIO tests for externally managed resource ownership UI (icons, warnings, zms-cli hints).
 *
 * Requires manually provisioned resources in testdata.functionalTestResourceOwnership:
 *   - functionalTestResourceOwnershipFixtures.role: meta and/or members owner (≥1 member)
 *   - functionalTestResourceOwnershipFixtures.policy: objectOwner and/or assertionsOwner
 *   - functionalTestResourceOwnershipFixtures.service: objectOwner
 *   - service + functionalTestResourceOwnershipFixtures.publicKeyId with publicKeysOwner
 *   - policy should include an assertion referencing the test role (role-policy tab)
 */

const config = require('../../../config/config');
const {
    authenticateAndWait,
    navigateAndWait,
    waitAndClick,
    waitAndSetValue,
    waitForElementExist,
    beforeEachTest,
} = require('../libs/helpers');
const {
    expectManagedResourceIconInContainer,
    expectNoManagedResourceIconInContainer,
    expectResourceOwnershipCliSuggestion,
    cancelDeleteModal,
    cancelUpdateModal,
} = require('../libs/resourceOwnershipHelpers');

const testdata = config().testdata;
const ownershipFixtures =
    testdata.functionalTestResourceOwnershipFixtures || {};

const OWNERSHIP_TEST_DOMAIN = testdata.functionalTestResourceOwnership;
const OWNERSHIP_TEST_ROLE = ownershipFixtures.role;
const OWNERSHIP_TEST_POLICY = ownershipFixtures.policy;
const OWNERSHIP_TEST_SERVICE = ownershipFixtures.service;
const OWNERSHIP_TEST_PUBLIC_KEY_ID = ownershipFixtures.publicKeyId;

const OWNERSHIP_TEST_DOMAIN_ROLE_URI = `/domain/${OWNERSHIP_TEST_DOMAIN}/role`;
const OWNERSHIP_TEST_DOMAIN_POLICY_URI = `/domain/${OWNERSHIP_TEST_DOMAIN}/policy`;
const OWNERSHIP_TEST_DOMAIN_SERVICE_URI = `/domain/${OWNERSHIP_TEST_DOMAIN}/service`;

const ADD_MEMBER_PLACEHOLDER = testdata.userHeadless1.id;

describe('Externally managed resource ownership UI', () => {
    beforeEach(async () => {
        await beforeEachTest();
    });

    describe('managed-resource icons', () => {
        it('shows managed-resource icon on externally owned role row', async () => {
            await authenticateAndWait();
            await navigateAndWait(OWNERSHIP_TEST_DOMAIN_ROLE_URI);
            await waitForElementExist('button*=Add Role');
            await expectManagedResourceIconInContainer(
                `//div[@data-wdio="${OWNERSHIP_TEST_ROLE}-role-row"]`
            );
        });

        it('shows managed-resource icon on externally owned policy row', async () => {
            await authenticateAndWait();
            await navigateAndWait(OWNERSHIP_TEST_DOMAIN_POLICY_URI);
            await waitForElementExist('button*=Add Policy');

            const policyRowSelector = `//tr[@data-testid="policy-row"][.//*[contains(text(), "${OWNERSHIP_TEST_POLICY}")]]`;
            await waitForElementExist(policyRowSelector);
            await expectManagedResourceIconInContainer(policyRowSelector);
        });

        it('shows managed-resource icon on externally owned service row', async () => {
            await authenticateAndWait();
            await navigateAndWait(OWNERSHIP_TEST_DOMAIN_SERVICE_URI);
            await waitForElementExist('button*=Add Service');

            const serviceRowSelector = `//tr[@data-testid="service-row"][.//td[contains(., "${OWNERSHIP_TEST_SERVICE}")]]`;
            await waitForElementExist(serviceRowSelector);
            await expectManagedResourceIconInContainer(serviceRowSelector);
        });

        it('shows managed-resource icon on externally owned policy under role policy tab', async () => {
            await authenticateAndWait();
            await navigateAndWait(OWNERSHIP_TEST_DOMAIN_ROLE_URI);

            await waitAndClick(
                `.//*[local-name()="svg" and @data-wdio="${OWNERSHIP_TEST_ROLE}-policy-rules"]`
            );

            const policyRowSelector = `//tr[@data-testid="policy-row"][.//*[contains(., "${OWNERSHIP_TEST_POLICY}")]]`;
            await waitForElementExist(policyRowSelector);
            await expectManagedResourceIconInContainer(policyRowSelector);
        });

        it('does not show managed-resource icon on role members table rows', async () => {
            await authenticateAndWait();
            await navigateAndWait(
                `/domain/${OWNERSHIP_TEST_DOMAIN}/role/${OWNERSHIP_TEST_ROLE}/members`
            );
            await waitForElementExist('button*=Add Member');
            await waitForElementExist('tr[data-testid="member-row"]');
            // Icon may appear in the role page header; member rows/table must not show it.
            await expectNoManagedResourceIconInContainer(
                '[data-testid="member-list"]'
            );
        });
    });

    describe('resource ownership CLI suggestions on blocked mutations', () => {
        it('shows delete-role zms-cli when deleting a TF-managed role', async () => {
            await authenticateAndWait();
            await navigateAndWait(OWNERSHIP_TEST_DOMAIN_ROLE_URI);

            const deleteButton = await $(
                `.//*[local-name()="svg" and @id="${OWNERSHIP_TEST_ROLE}-delete-role-button"]`
            );
            await waitAndClick(deleteButton);
            await waitForElementExist('div[data-testid="modal-title"]');
            await waitAndClick('button[data-testid="delete-modal-delete"]');

            await expectResourceOwnershipCliSuggestion({
                domain: OWNERSHIP_TEST_DOMAIN,
                commandParts: ['delete-role', OWNERSHIP_TEST_ROLE],
            });
            await cancelDeleteModal();
        });

        it('shows delete-policy zms-cli when deleting a TF-managed policy', async () => {
            await authenticateAndWait();
            await navigateAndWait(OWNERSHIP_TEST_DOMAIN_POLICY_URI);

            await waitAndClick(
                `.//*[local-name()="svg" and @data-wdio="${OWNERSHIP_TEST_POLICY}-delete"]`
            );
            await waitForElementExist('div[data-testid="modal-title"]');
            await waitAndClick('button[data-testid="delete-modal-delete"]');

            await expectResourceOwnershipCliSuggestion({
                domain: OWNERSHIP_TEST_DOMAIN,
                commandParts: ['delete-policy', OWNERSHIP_TEST_POLICY],
            });
            await cancelDeleteModal();
        });

        it('shows delete-service zms-cli when deleting a TF-managed service', async () => {
            await authenticateAndWait();
            await navigateAndWait(OWNERSHIP_TEST_DOMAIN_SERVICE_URI);

            await waitAndClick(
                `.//*[local-name()="svg" and @id="delete-service-${OWNERSHIP_TEST_SERVICE}"]`
            );
            await waitForElementExist('div[data-testid="modal-title"]');
            await waitAndClick('button[data-testid="delete-modal-delete"]');

            await expectResourceOwnershipCliSuggestion({
                domain: OWNERSHIP_TEST_DOMAIN,
                commandParts: ['delete-service', OWNERSHIP_TEST_SERVICE],
            });
            await cancelDeleteModal();
        });

        it('shows add-member zms-cli when adding a member to a TF-managed role', async () => {
            await authenticateAndWait();
            await navigateAndWait(
                `/domain/${OWNERSHIP_TEST_DOMAIN}/role/${OWNERSHIP_TEST_ROLE}/members`
            );

            await waitAndClick('button*=Add Member');
            await waitAndSetValue(
                'input[name="member-name"]',
                ADD_MEMBER_PLACEHOLDER
            );
            await waitAndClick(`div*=${ADD_MEMBER_PLACEHOLDER}`);
            await waitAndClick('button*=Submit');

            await expectResourceOwnershipCliSuggestion({
                domain: OWNERSHIP_TEST_DOMAIN,
                commandParts: [
                    'add-member',
                    OWNERSHIP_TEST_ROLE,
                    ADD_MEMBER_PLACEHOLDER,
                ],
            });
            await waitAndClick('button*=Cancel');
        });

        it('shows delete-member zms-cli when deleting a member from a TF-managed role', async () => {
            await authenticateAndWait();
            await navigateAndWait(
                `/domain/${OWNERSHIP_TEST_DOMAIN}/role/${OWNERSHIP_TEST_ROLE}/members`
            );

            const memberRow = await waitForElementExist(
                `tr[data-wdio$="-member-row"]`
            );
            const memberWdio = await memberRow.getAttribute('data-wdio');
            const memberName = memberWdio.replace(/-member-row$/, '');

            await waitAndClick(
                `.//*[local-name()="svg" and @data-wdio="${memberName}-delete-member"]`
            );
            await waitForElementExist('div[data-testid="modal-title"]');
            await waitAndClick('button[data-testid="delete-modal-delete"]');

            await expectResourceOwnershipCliSuggestion({
                domain: OWNERSHIP_TEST_DOMAIN,
                commandParts: [
                    'delete-member',
                    OWNERSHIP_TEST_ROLE,
                    memberName,
                ],
            });
            await cancelDeleteModal();
        });

        it('shows set-role zms-cli when updating TF-managed role settings', async () => {
            await authenticateAndWait();
            await navigateAndWait(OWNERSHIP_TEST_DOMAIN_ROLE_URI);

            await waitAndClick(
                `.//*[local-name()="svg" and @id="${OWNERSHIP_TEST_ROLE}-setting-role-button"]`
            );
            await waitForElementExist('#setting-description');

            const description = await $('#setting-description');
            const original = await description.getValue();
            const updated =
                original === 'wdio-tf-test'
                    ? 'wdio-tf-test-updated'
                    : 'wdio-tf-test';
            await waitAndSetValue(description, updated, { clearFirst: true });
            await waitAndClick('button*=Submit');
            await waitAndClick('button[data-testid="update-modal-update"]');

            await expectResourceOwnershipCliSuggestion({
                domain: OWNERSHIP_TEST_DOMAIN,
                commandParts: [
                    'set-role-description',
                    OWNERSHIP_TEST_ROLE,
                    updated,
                ],
            });
            await cancelUpdateModal();
        });

        it('shows add-assertion zms-cli when adding a rule to a TF-managed policy from role policy tab', async () => {
            await authenticateAndWait();
            await navigateAndWait(OWNERSHIP_TEST_DOMAIN_ROLE_URI);

            await waitAndClick(
                `.//*[local-name()="svg" and @data-wdio="${OWNERSHIP_TEST_ROLE}-policy-rules"]`
            );
            await waitAndClick('a*=Add rule');

            await waitAndSetValue(
                `input[id="rule-action-${OWNERSHIP_TEST_POLICY}"]`,
                'tf-wdio-action'
            );
            await waitAndSetValue(
                `input[id="rule-resource-${OWNERSHIP_TEST_POLICY}"]`,
                'tf-wdio-resource'
            );
            await waitAndClick('button*=Submit');

            await expectResourceOwnershipCliSuggestion({
                domain: OWNERSHIP_TEST_DOMAIN,
                commandParts: ['add-assertion', OWNERSHIP_TEST_POLICY],
            });
            await waitAndClick('button*=Cancel');
        });

        it('shows delete-assertion zms-cli when deleting a rule from a TF-managed role policy', async () => {
            await authenticateAndWait();
            await navigateAndWait(OWNERSHIP_TEST_DOMAIN_ROLE_URI);

            await waitAndClick(
                `.//*[local-name()="svg" and @data-wdio="${OWNERSHIP_TEST_ROLE}-policy-rules"]`
            );

            const ruleRow = await waitForElementExist(
                `tr[data-wdio="${OWNERSHIP_TEST_ROLE}-policy-rule-row"]`
            );
            const trashIcons = await ruleRow.$$(
                `.//*[local-name()="svg" and @data-testid="icon"]`
            );
            await waitAndClick(trashIcons[trashIcons.length - 1]);

            await waitForElementExist('div[data-testid="modal-title"]');
            await waitAndClick('button[data-testid="delete-modal-delete"]');

            await expectResourceOwnershipCliSuggestion({
                domain: OWNERSHIP_TEST_DOMAIN,
                commandParts: ['delete-assertion', OWNERSHIP_TEST_POLICY],
            });
            await cancelDeleteModal();
        });

        it('shows delete-public-key zms-cli when deleting a TF-managed service public key', async () => {
            await authenticateAndWait();
            await navigateAndWait(OWNERSHIP_TEST_DOMAIN_SERVICE_URI);

            const serviceRow = await waitForElementExist(
                `//tr[@data-testid="service-row"][.//td[contains(., "${OWNERSHIP_TEST_SERVICE}")]]`
            );
            const rowIcons = await serviceRow.$$(
                `.//*[local-name()="svg" and @data-testid="icon"]`
            );
            // key icon is the second action icon when instance navigation is enabled
            await waitAndClick(
                `.//*[local-name()="svg" and @data-wdio="service-pubkeys-${OWNERSHIP_TEST_SERVICE}"]`
            );

            const publicKeyTable = await waitForElementExist(
                '[data-testid="public-key-table"]'
            );
            const keyLabel = await publicKeyTable.$(
                `div*=Public Key Version: ${OWNERSHIP_TEST_PUBLIC_KEY_ID}`
            );
            await expect(keyLabel).toExist();

            await waitAndClick(
                `.//*[local-name()="svg" and @data-wdio="delete-key-${OWNERSHIP_TEST_PUBLIC_KEY_ID}"]`
            );

            await waitForElementExist('div[data-testid="modal-title"]');
            await waitAndClick('button[data-testid="delete-modal-delete"]');

            await expectResourceOwnershipCliSuggestion({
                domain: OWNERSHIP_TEST_DOMAIN,
                commandParts: [
                    'delete-public-key',
                    OWNERSHIP_TEST_SERVICE,
                    OWNERSHIP_TEST_PUBLIC_KEY_ID,
                ],
            });
            await cancelDeleteModal();
        });
    });
});
