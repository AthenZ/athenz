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

/*
 * Shared fixtures and page helpers for the Self Service functional specs.
 *
 * The self-service coverage is split across several spec files so that each
 * Sauce Labs session stays well under the maxDuration cap. Every spec builds
 * its own harness via `createSelfServiceHarness()`, which tracks the fixtures
 * that spec created and exposes `cleanup()` for its afterEach hook.
 *
 * Fixture names must stay globally unique across the self-service specs: the
 * specs run in parallel against the same functional-test domain, and cleanup
 * is keyed by name.
 */

const config = require('../../../config/config');
const {
    navigateAndWait,
    waitAndSetValue,
    waitAndClick,
    waitForElementExist,
    authenticateAndWait,
} = require('./helpers');

const testdata = config().testdata;

const TEST_DOMAIN = testdata.functionalTest;
const SECOND_DOMAIN = testdata.auditEnabled;
const SELF_SERVICE_URI = '/self-service';

// Search tokens that only live in the *description* of a fixture, used to prove
// roles search name+description while groups search name-only.
const DESC_ROLE_TOKEN = 'zzsssearchtokenrole';
const DESC_GROUP_TOKEN = 'zzsssearchtokengroup';

const keyFor = (type, name, domain = TEST_DOMAIN) =>
    `${domain}:${type}.${name}`;

const rowLink = (type, name, domain) =>
    `[data-testid="self-service-row-link-${keyFor(type, name, domain)}"]`;

// Resolve the specific result row for a fixture (via its uniquely keyed link)
// so assertions on shared testids (domain, expiry, pills) are scoped to *our*
// row and never pick up another self-serve object that happens to be returned
// by the global search or held by the test principal.
const rowElementFor = async (type, name, domain) => {
    const link = await waitForElementExist(rowLink(type, name, domain));
    return link.$('./ancestor::div[@data-testid="self-service-result-row"]');
};

const gotoSelfService = async () => {
    await navigateAndWait(SELF_SERVICE_URI);
    await waitForElementExist('[data-testid="self-service"]');
};

const goToFindTab = async () => {
    await waitAndClick('div*=Find Roles & Groups');
};

const goToMineTab = async () => {
    await waitAndClick('div*=My Roles & Groups');
    await browser.pause(1000);
};

// Reload the page fresh and land on the My Roles & Groups tab. Used to make
// membership assertions deterministic after an action.
const reloadMine = async () => {
    await gotoSelfService();
    await goToMineTab();
};

const searchSelfServe = async (query) => {
    await waitAndSetValue('#self-service-search', query);
    await waitAndClick('[data-testid="self-service-search-button"]');
    await browser.pause(1000);
};

const assertNoExistsError = async (kind, name) => {
    const err = await $('div[data-testid="error-message"]');
    const exists = await err.waitForExist({ timeout: 1500 }).catch(() => false);
    if (exists) {
        const text = await err.getText();
        if (text.includes('already exists')) {
            throw new Error(
                `${kind} "${name}" already exists - cleanup required before re-run.`
            );
        }
        throw new Error(`Unexpected error creating ${kind} "${name}": ${text}`);
    }
};

const openDomainListing = async (url, readySelector, attempts = 3) => {
    for (let attempt = 1; attempt < attempts; attempt++) {
        try {
            await navigateAndWait(url);
            await $(readySelector).waitForExist({ timeout: 30000 });
            return;
        } catch {
            console.warn(
                `openDomainListing: ${url} not ready (attempt ${attempt}/${attempts}); reloading`
            );
        }
    }
    // final attempt: let navigation/wait throw the real error/timeout
    await navigateAndWait(url);
    await waitForElementExist(readySelector);
};

const deleteRoleIfExists = async (name, domain = TEST_DOMAIN) => {
    await openDomainListing(`/domain/${domain}/role`, 'button*=Add Role');
    const del = await $(
        `.//*[local-name()="svg" and @id="${name}-delete-role-button"]`
    );
    const appeared = await del
        .waitForExist({ timeout: 5000 })
        .catch(() => false);
    if (!appeared) {
        return;
    }
    await waitAndClick(del, { timeout: 5000 });
    await waitForElementExist('div[data-testid="modal-title"]');
    // audit-enabled domains ask for a justification on delete
    const justification = await $('input[id="justification"]');
    const needsJustification = await justification
        .waitForExist({ timeout: 1000 })
        .catch(() => false);
    if (needsJustification) {
        await waitAndSetValue(
            'input[id="justification"]',
            'functional test cleanup'
        );
    }
    await waitAndClick('button*=Delete');
    await browser.pause(500);
};

const deleteGroupIfExists = async (name, domain = TEST_DOMAIN) => {
    await openDomainListing(`/domain/${domain}/group`, 'button*=Add Group');
    const del = await $(
        `.//*[local-name()="svg" and @id="delete-group-icon-${name}"]`
    );
    const appeared = await del
        .waitForExist({ timeout: 5000 })
        .catch(() => false);
    if (!appeared) {
        return;
    }
    await waitAndClick(del, { timeout: 5000 });
    const justification = await $('input[id="justification"]');
    const needsJustification = await justification
        .waitForExist({ timeout: 1000 })
        .catch(() => false);
    if (needsJustification) {
        await waitAndSetValue(
            'input[id="justification"]',
            'functional test cleanup'
        );
    }
    await waitAndClick('button*=Delete');
    await browser.pause(500);
};

// Select a row's checkbox (the visible target is the label bound to the
// hidden input via for="checkbox-<key>").
const selectRow = async (key) => {
    await waitAndClick(`label[for="checkbox-${key}"]`);
};

// Find -> select -> Request access -> justify -> Submit for a single item.
const requestSingleFromFind = async (
    name,
    key,
    justification = 'functional test request'
) => {
    await searchSelfServe(name);
    await waitForElementExist(`[data-testid="self-service-row-link-${key}"]`);
    await selectRow(key);
    await waitAndClick('[data-testid="request-selected"]');
    await waitForElementExist('[data-testid="request-access-form"]');
    await waitAndSetValue('#self-serve-justification', justification);
    await waitAndClick('button*=Submit');
    await waitForElementExist('[data-testid="request-access-form"]', {
        reverse: true,
    });
};

/**
 * Build a per-spec harness. Fixtures created through the returned
 * `createSelfServeRole` / `createSelfServeGroup` are recorded and removed by
 * `cleanup()`, which the spec wires into its afterEach hook.
 *
 * @param {Object} opts
 * @param {Object} opts.inherit optional { group, role }: when `group` is
 *        cleaned up, `role` (which holds the group as a member) is deleted first.
 */
const createSelfServiceHarness = (opts = {}) => {
    let createdFixtures = [];

    // Create a self-serve role via the standard Add Role + advanced settings
    // flow. opts: { domain, selfRenew, selfRenewMins, reviewEnabled,
    // memberExpiryDays, description, members: [] }. Caller must be authenticated.
    const createSelfServeRole = async (name, roleOpts = {}) => {
        const domain = roleOpts.domain || TEST_DOMAIN;
        await deleteRoleIfExists(name, domain);
        await waitAndClick('button*=Add Role');
        await waitAndSetValue('#role-name-input', name);
        await waitAndClick('#advanced-settings-icon');
        await waitAndClick('label[for="switch-settingselfServe"]');
        if (roleOpts.reviewEnabled) {
            await waitAndClick('label[for="switch-settingreviewEnabled"]');
        }
        if (roleOpts.selfRenew) {
            await waitAndClick('label[for="switch-settingselfRenew"]');
            await waitAndSetValue(
                '#setting-selfRenewMins',
                String(roleOpts.selfRenewMins || 60)
            );
        }
        if (roleOpts.memberExpiryDays !== undefined) {
            await waitAndSetValue(
                '#setting-memberExpiryDays',
                String(roleOpts.memberExpiryDays)
            );
        }
        if (roleOpts.description) {
            await waitAndSetValue('#setting-description', roleOpts.description);
        }
        for (const member of roleOpts.members || []) {
            await waitAndSetValue('input[name="member-name"]', member);
            await waitAndClick(`div*=${member}`);
            await waitAndClick('button[data-wdio="add-role-member"]');
        }
        // audit-enabled domains require a justification to create
        if (roleOpts.justification) {
            await waitAndSetValue(
                'input[id="justification"]',
                roleOpts.justification
            );
        }
        await waitAndClick('button*=Submit');
        await assertNoExistsError('Role', name);
        createdFixtures.push({ kind: 'role', name, domain });
    };

    const createSelfServeGroup = async (name, groupOpts = {}) => {
        const domain = groupOpts.domain || TEST_DOMAIN;
        await deleteGroupIfExists(name, domain);
        await waitAndClick('button*=Add Group');
        await waitAndSetValue('#group-name-input', name);
        await waitAndClick('#advanced-settings-icon');
        await waitAndClick('label[for="switch-settingselfServe"]');
        if (groupOpts.reviewEnabled) {
            await waitAndClick('label[for="switch-settingreviewEnabled"]');
        }
        if (groupOpts.selfRenew) {
            await waitAndClick('label[for="switch-settingselfRenew"]');
            await waitAndSetValue(
                '#setting-selfRenewMins',
                String(groupOpts.selfRenewMins || 60)
            );
        }
        if (groupOpts.memberExpiryDays !== undefined) {
            await waitAndSetValue(
                '#setting-memberExpiryDays',
                String(groupOpts.memberExpiryDays)
            );
        }
        // NOTE: the Add Group flow has no description field (only roles do),
        // which is why groups are searched by name only.
        for (const member of groupOpts.members || []) {
            await waitAndSetValue('input[name="member-name"]', member);
            await waitAndClick(`div*=${member}`);
            await waitAndClick('button[data-wdio="add-group-member"]');
        }
        await waitAndClick('button*=Submit');
        await assertNoExistsError('Group', name);
        createdFixtures.push({ kind: 'group', name, domain });
    };

    const cleanup = async () => {
        try {
            await authenticateAndWait();
            for (const { kind, name, domain } of createdFixtures) {
                try {
                    if (
                        opts.inherit &&
                        kind === 'group' &&
                        name === opts.inherit.group
                    ) {
                        await deleteRoleIfExists(opts.inherit.role, domain);
                    }
                    if (kind === 'role') {
                        await deleteRoleIfExists(name, domain);
                    } else {
                        await deleteGroupIfExists(name, domain);
                    }
                } catch (error) {
                    console.error(
                        `Self-service cleanup failed for ${kind} "${name}" in ${domain}:`,
                        error.message
                    );
                }
            }
        } catch (error) {
            console.error('Self-service cleanup failed:', error.message);
            // don't throw - allow the remaining tests to run
        } finally {
            createdFixtures = [];
        }
    };

    return { createSelfServeRole, createSelfServeGroup, cleanup };
};

module.exports = {
    TEST_DOMAIN,
    SECOND_DOMAIN,
    SELF_SERVICE_URI,
    DESC_ROLE_TOKEN,
    DESC_GROUP_TOKEN,
    keyFor,
    rowLink,
    rowElementFor,
    gotoSelfService,
    goToFindTab,
    goToMineTab,
    reloadMine,
    searchSelfServe,
    openDomainListing,
    deleteRoleIfExists,
    deleteGroupIfExists,
    selectRow,
    requestSingleFromFind,
    createSelfServiceHarness,
};
