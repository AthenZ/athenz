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
 * Functional coverage for the Self Service feature: requesting access from the
 * Find tab, the My Roles & Groups tab (cancel / leave) and the success alert
 * (tests 10-16 and 23).
 *
 * See libs/self-service-helpers.js for the shared fixtures/helpers and the
 * reason the self-service coverage is split across several spec files.
 */

const {
    authenticateAndWait,
    waitAndSetValue,
    waitAndClick,
    waitForElementExist,
    beforeEachTest,
} = require('../libs/helpers');
const {
    keyFor,
    rowLink,
    rowElementFor,
    gotoSelfService,
    reloadMine,
    searchSelfServe,
    selectRow,
    requestSingleFromFind,
    createSelfServiceHarness,
} = require('../libs/self-service-helpers');

// Fixture names (kept distinct across the self-service specs so cleanup is
// unambiguous).
const REQUEST_ROLE = 'ss-func-request-role';
const JUST_ROLE = 'ss-func-just-role';
const REQUEST_GROUP = 'ss-func-request-group';
const MULTI_ROLE = 'ss-func-multi-role';
const MULTI_GROUP = 'ss-func-multi-group';
const MINE_ACTIVE_ROLE = 'ss-func-mine-active-role';
const MINE_PENDING_ROLE = 'ss-func-mine-pending-role';
const MINE_LEAVE_ROLE = 'ss-func-mine-leave-role';
const ALERT_ROLE = 'ss-func-alert-role';

describe('self service screen tests - request', () => {
    const { createSelfServeRole, createSelfServeGroup, cleanup } =
        createSelfServiceHarness();

    beforeEach(async () => {
        await beforeEachTest();
    });

    // =====================================================================
    // Request access (Find tab)
    // =====================================================================

    it('10: requesting a role submits a pending request', async () => {
        await authenticateAndWait();
        await createSelfServeRole(REQUEST_ROLE, { reviewEnabled: true });
        await gotoSelfService();

        await requestSingleFromFind(REQUEST_ROLE, keyFor('role', REQUEST_ROLE));

        await reloadMine();
        await waitForElementExist('div*=Pending requests');
        const row = await rowElementFor('role', REQUEST_ROLE);
        const pending = await row.$('div*=Pending approval');
        await pending.waitForExist();
    });

    it('11: request requires a justification', async () => {
        await authenticateAndWait();
        await createSelfServeRole(JUST_ROLE, { reviewEnabled: true });
        await gotoSelfService();

        await searchSelfServe(JUST_ROLE);
        const key = keyFor('role', JUST_ROLE);
        await waitForElementExist(
            `[data-testid="self-service-row-link-${key}"]`
        );
        await selectRow(key);
        await waitAndClick('[data-testid="request-selected"]');
        await waitForElementExist('[data-testid="request-access-form"]');
        // submit with no justification
        await waitAndClick('button*=Submit');
        await waitForElementExist('div*=Justification is required');
    });

    it('12: requesting a group shows no expiry pickers', async () => {
        await authenticateAndWait();
        await createSelfServeGroup(REQUEST_GROUP, { reviewEnabled: true });
        await gotoSelfService();

        await searchSelfServe(REQUEST_GROUP);
        const key = keyFor('group', REQUEST_GROUP);
        await waitForElementExist(
            `[data-testid="self-service-row-link-${key}"]`
        );
        await selectRow(key);
        await waitAndClick('[data-testid="request-selected"]');
        await waitForElementExist('[data-testid="request-access-form"]');

        // groups have no expiry/reminder date pickers
        await waitForElementExist('#self-serve-expiry', { reverse: true });

        await waitAndSetValue(
            '#self-serve-justification',
            'functional test group request'
        );
        await waitAndClick('button*=Submit');
        await waitForElementExist('[data-testid="request-access-form"]', {
            reverse: true,
        });
    });

    it('13: multi-select shows a breakdown and requests role + group together', async () => {
        await authenticateAndWait();
        await createSelfServeRole(MULTI_ROLE, { reviewEnabled: true });
        await createSelfServeGroup(MULTI_GROUP, { reviewEnabled: true });
        await gotoSelfService();

        await searchSelfServe('ss-func-multi');
        const roleKey = keyFor('role', MULTI_ROLE);
        const groupKey = keyFor('group', MULTI_GROUP);
        await waitForElementExist(
            `[data-testid="self-service-row-link-${roleKey}"]`
        );
        await selectRow(roleKey);
        await selectRow(groupKey);

        const bar = await waitForElementExist(
            '[data-testid="self-service-selection-bar"]'
        );
        await expect(bar).toHaveText(expect.stringContaining('2 selected'));
        await expect(bar).toHaveText(expect.stringContaining('1 role'));
        await expect(bar).toHaveText(expect.stringContaining('1 group'));

        await waitAndClick('[data-testid="request-selected"]');
        await waitForElementExist('[data-testid="request-access-form"]');
        await waitAndSetValue(
            '#self-serve-justification',
            'functional test multi request'
        );
        await waitAndClick('button*=Submit');
        await waitForElementExist('[data-testid="request-access-form"]', {
            reverse: true,
        });
    });

    // =====================================================================
    // My Roles & Groups
    // =====================================================================

    it('14: an approved self-request appears under My Roles', async () => {
        await authenticateAndWait();
        // no review -> self add becomes an active membership immediately
        await createSelfServeRole(MINE_ACTIVE_ROLE, { reviewEnabled: false });
        await gotoSelfService();

        await requestSingleFromFind(
            MINE_ACTIVE_ROLE,
            keyFor('role', MINE_ACTIVE_ROLE)
        );

        await reloadMine();
        await waitForElementExist(rowLink('role', MINE_ACTIVE_ROLE));
    });

    it('15: a pending request can be cancelled from My Roles', async () => {
        await authenticateAndWait();
        await createSelfServeRole(MINE_PENDING_ROLE, { reviewEnabled: true });
        await gotoSelfService();

        await requestSingleFromFind(
            MINE_PENDING_ROLE,
            keyFor('role', MINE_PENDING_ROLE)
        );

        await reloadMine();
        await waitForElementExist('div*=Pending requests');
        const key = keyFor('role', MINE_PENDING_ROLE);
        await waitAndClick(`[data-testid="cancel-${key}"]`);
        // withdraw confirmation modal
        await waitForElementExist('[data-testid="leave-modal-message"]');
        await waitAndClick('[data-testid="leave-modal-submit"]');

        await reloadMine();
        await waitForElementExist(rowLink('role', MINE_PENDING_ROLE), {
            reverse: true,
        });
    });

    it('16: an active membership can be left from My Roles', async () => {
        await authenticateAndWait();
        await createSelfServeRole(MINE_LEAVE_ROLE, { reviewEnabled: false });
        await gotoSelfService();

        await requestSingleFromFind(
            MINE_LEAVE_ROLE,
            keyFor('role', MINE_LEAVE_ROLE)
        );

        await reloadMine();
        const key = keyFor('role', MINE_LEAVE_ROLE);
        await waitForElementExist(rowLink('role', MINE_LEAVE_ROLE));
        await waitAndClick(`[data-testid="leave-${key}"]`);
        await waitForElementExist('[data-testid="leave-modal-message"]');
        await waitAndSetValue(
            '#self-serve-leave-justification',
            'functional test leave'
        );
        await waitAndClick('[data-testid="leave-modal-submit"]');

        await reloadMine();
        await waitForElementExist(rowLink('role', MINE_LEAVE_ROLE), {
            reverse: true,
        });
    });

    // =====================================================================
    // Success alert
    // =====================================================================

    it('23: the success alert appears and can be dismissed', async () => {
        await authenticateAndWait();
        await createSelfServeRole(ALERT_ROLE, { reviewEnabled: true });
        await gotoSelfService();

        // trigger a request -> success alert
        await requestSingleFromFind(ALERT_ROLE, keyFor('role', ALERT_ROLE));

        const title = await waitForElementExist('[data-testid="alert-title"]');
        await expect(title).toHaveText(expect.stringContaining('Request'));

        // it auto-dismisses after the timeout
        await waitForElementExist('[data-testid="alert-title"]', {
            reverse: true,
            timeout: 6000,
        });
    });

    afterEach(async () => {
        await cleanup();
    });
});
