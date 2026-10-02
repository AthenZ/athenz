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
 * Functional tests for the Snapshots section of the service Microsegmentation
 * page (transport policy snapshots served by MSD).
 *
 * The section is behind `pageFeatureFlag.microsegmentation.snapshots`; the
 * environment under test must have it enabled. Snapshot data lives in MSD, so
 * the tests that create, read or delete snapshots need the functional test
 * principal to hold `msd.GetNetworkPolicy`, `msd.UpdateNetworkPolicy` and
 * `msd.DeleteNetworkPolicy` on the test service. When the list itself fails to
 * load, TEST_SECTION_RENDERS_AND_LOADS fails (the visible signal) and the
 * MSD-backed tests skip themselves with the error logged, instead of every
 * test failing for the same cause.
 *
 * The fixture service is created on first use and deliberately kept: MSD
 * validates the service against its own copy of the ZMS data, so a service
 * created moments ago answers 404 until MSD has synced it (observed at up to
 * a few minutes). The `before` hook waits for that sync; keeping the service
 * makes later runs start warm. Snapshots are cleaned up after every test.
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

const appConfig = config();
const testdata = appConfig.testdata;

const TEST_DOMAIN = testdata.functionalTest;
const TEST_DOMAIN_SERVICE_URI = `/domain/${TEST_DOMAIN}/service`;
const TEST_SERVICE = 'snapshot-test-service';
const NON_ADMIN_DOMAIN = testdata.functionalTestNonAdmin;
// existing fixture service in the non-admin domain (see services.spec.js)
const NON_ADMIN_SERVICE = 'provider-test-service';

const TEST_SECTION_RENDERS_AND_LOADS =
    'should render the Snapshots section on the service Microsegmentation page and load the list';
const TEST_FORBIDDEN_SHOWS_INLINE_ERROR =
    'should show an inline error instead of the empty state when the principal may not read snapshots';
const TEST_NAME_VALIDATION =
    'should reject an empty or malformed snapshot name in the modal without creating anything';
const TEST_CREATE_DEFAULT_INACTIVE =
    'should create snapshots, trim the name, default to inactive and update the count';
const TEST_NAMES_CASE_SENSITIVE =
    'should treat snapshot names as case-sensitive';
const TEST_CREATE_DUPLICATE_REJECTED =
    'should keep the modal open with the MSD error when the snapshot name already exists';
const TEST_TOGGLE_ACTIVE =
    'should toggle a snapshot between active and inactive';
const TEST_EXPAND_DETAILS =
    'should show captured rules and last-used-by when a snapshot is expanded';
const TEST_DELETE_ACTIVE_NEEDS_FORCE =
    'should refuse to delete an active snapshot until the forced confirmation';
const TEST_DELETE_INACTIVE_AND_CANCEL =
    'should keep a snapshot on cancel and delete an inactive one after a single confirmation';

const SEL_SECTION = '[data-testid="snapshot-list"]';
const SEL_TABLE = '[data-testid="snapshot-table"]';
const SEL_EMPTY = '[data-testid="snapshot-list-empty"]';
const SEL_ERROR = '[data-testid="snapshot-list-error"]';
const SEL_ROWS = '[data-testid^="snapshot-row-"]';
const SEL_ADD_MODAL = '[data-testid="add-snapshot-modal"]';
const SEL_ADD_NAME = '#snapshot-name';
const SEL_ADD_ACTIVE_LABEL = 'label[for="snapshot-active"]';
const SEL_DELETE_MESSAGE = '[data-testid="delete-modal-message"]';
const SEL_DELETE_SUBMIT = '[data-testid="delete-modal-delete"]';
const SEL_DELETE_CANCEL = '[data-testid="delete-modal-cancel"]';
const SEL_TOAST_TITLE = '[data-testid="alert-title"]';
const SEL_DETAILS = '[data-testid="snapshot-details"]';
const SEL_INGRESS = '[data-testid="snapshot-ingress-table"]';
const SEL_EGRESS = '[data-testid="snapshot-egress-table"]';
const SEL_USAGE = '[data-testid="snapshot-usage"]';
const SEL_GUIDE_LINK = '//*[@data-testid="snapshot-list"]//a[text()="Guide"]';

// how long to wait for MSD to learn about a freshly created fixture service
const MSD_SYNC_TIMEOUT = 240000;
const MSD_SYNC_POLL = 15000;

const STATE_TABLE = 'table';
const STATE_EMPTY = 'empty';
const STATE_ERROR = 'error';

const rowSel = (name) => `[data-testid="snapshot-row-${name}"]`;
const viewSel = (name) => `[data-testid="snapshot-view-${name}"]`;
const deleteSel = (name) => `[data-testid="snapshot-delete-${name}"]`;
// Denali Switch derives the label target from the input name
const activeSwitchSel = (name) => `label[for="switch-snapshot-active-${name}"]`;
const textSel = (text) => `//*[contains(text(), "${text}")]`;

/**
 * Waits for the snapshot list to leave its loading state and reports which
 * of the three terminal states it reached.
 */
const waitForSnapshotList = async () => {
    await waitForElementExist(SEL_SECTION);
    let state;
    await browser.waitUntil(
        async () => {
            if (await $(SEL_TABLE).isExisting()) {
                state = STATE_TABLE;
            } else if (await $(SEL_EMPTY).isExisting()) {
                state = STATE_EMPTY;
            } else if (await $(SEL_ERROR).isExisting()) {
                state = STATE_ERROR;
            }
            return !!state;
        },
        {
            timeout: 30000,
            timeoutMsg: 'Snapshot list did not finish loading within 30s',
        }
    );
    return state;
};

const openSnapshots = async (domain, service) => {
    await authenticateAndWait();
    await navigateAndWait(
        `/domain/${domain}/service/${service}/microsegmentation`
    );
    await waitForElementExist('[data-testid="service-microsegmentation"]');
    return waitForSnapshotList();
};

/**
 * Opens the test service's snapshot section; skips the calling test when MSD
 * returned an error for the list, since nothing below can work then.
 */
const openSnapshotsOrSkip = async (ctx) => {
    const state = await openSnapshots(TEST_DOMAIN, TEST_SERVICE);
    if (state === STATE_ERROR) {
        const message = await $(SEL_ERROR).getText();
        console.warn(
            `Snapshot list unavailable, skipping "${ctx.test.title}": ${message}`
        );
        ctx.skip();
    }
    return state;
};

const snapshotCount = async () => (await $$(SEL_ROWS)).length;

const headerCount = async () => {
    const text = await $(SEL_SECTION).getText();
    const match = /Snapshots \((\d+)\)/.exec(text);
    return match ? Number(match[1]) : NaN;
};

const statusLabel = async (name) =>
    $(rowSel(name)).$('.label-content').getText();

/**
 * Success toasts are modal overlays that close themselves after two seconds;
 * assert the title and wait it out so the next click lands on the page.
 */
const expectToast = async (title) => {
    const toast = await waitForElementExist(SEL_TOAST_TITLE);
    expect(await toast.getText()).toBe(title);
    await waitForElementExist(SEL_TOAST_TITLE, { reverse: true });
};

const openAddModal = async () => {
    await waitAndClick('button*=Add Snapshot');
    await waitForElementExist(SEL_ADD_MODAL);
};

const createSnapshot = async (name, active = false) => {
    await openAddModal();
    await waitAndSetValue(SEL_ADD_NAME, name);
    if (active) {
        await waitAndClick(SEL_ADD_ACTIVE_LABEL);
    }
    await waitAndClick('button*=Submit');
    const created = name.trim();
    await expectToast(`Snapshot ${created} created`);
    // MSD's list occasionally lags the create it just confirmed; one reload
    // (logged) keeps that backend lag from failing an unrelated assertion
    const listed = await $(rowSel(created))
        .waitForExist({ timeout: 10000 })
        .catch(() => false);
    if (!listed) {
        console.warn(
            `Snapshot ${created} was created but not yet listed, reloading`
        );
        await browser.refresh();
        await waitForSnapshotList();
    }
    await waitForElementExist(rowSel(created));
    return created;
};

/**
 * Confirms the open delete modal; when MSD answers 409 for an active snapshot
 * the modal turns into the forced confirmation, which is confirmed as well.
 */
const confirmDeleteWithForceIfNeeded = async (name) => {
    await waitAndClick(SEL_DELETE_SUBMIT);
    await browser.waitUntil(
        async () => {
            if (!(await $(rowSel(name)).isExisting())) {
                return true;
            }
            const button = $(SEL_DELETE_SUBMIT);
            return (
                (await button.isExisting()) &&
                (await button.getText()) === 'Force delete'
            );
        },
        {
            timeout: 30000,
            timeoutMsg: `Delete of snapshot ${name} neither completed nor asked for force`,
        }
    );
    if (await $(rowSel(name)).isExisting()) {
        await waitAndClick(SEL_DELETE_SUBMIT);
    }
    await waitForElementExist(rowSel(name), { reverse: true });
};

const deleteAllSnapshots = async () => {
    const state = await openSnapshots(TEST_DOMAIN, TEST_SERVICE);
    if (state !== STATE_TABLE) {
        return;
    }
    // collect the names first so later deletions cannot stale the elements
    const names = [];
    for (const row of await $$(SEL_ROWS)) {
        names.push(
            (await row.getAttribute('data-testid')).replace('snapshot-row-', '')
        );
    }
    for (const name of names) {
        await waitAndClick(deleteSel(name));
        await waitForElementExist(SEL_DELETE_MESSAGE);
        await confirmDeleteWithForceIfNeeded(name);
        await waitForElementExist(SEL_TOAST_TITLE, { reverse: true });
    }
};

const serviceDeleteIconSel = (serviceName) =>
    `.//*[local-name()="svg" and @id="delete-service-${serviceName}"]`;

const ensureTestService = async () => {
    await authenticateAndWait();
    await navigateAndWait(TEST_DOMAIN_SERVICE_URI);
    await waitForElementExist('button*=Add Service');
    const exists = await $(serviceDeleteIconSel(TEST_SERVICE))
        .waitForExist({ timeout: 5000 })
        .catch(() => false);
    if (exists) {
        return;
    }
    await waitAndClick('button*=Add Service');
    await waitAndSetValue('input[data-wdio="service-name"]', TEST_SERVICE);
    await waitAndClick('button*=Submit');
    await waitForElementExist(serviceDeleteIconSel(TEST_SERVICE));
};

/**
 * Polls the snapshot list until MSD stops answering 404 for the fixture
 * service (its ZMS data sync lags service creation). Any other error is left
 * for TEST_SECTION_RENDERS_AND_LOADS to report.
 */
const waitForMsdToKnowTestService = async () => {
    const deadline = Date.now() + MSD_SYNC_TIMEOUT;
    let state = await openSnapshots(TEST_DOMAIN, TEST_SERVICE);
    while (state === STATE_ERROR && Date.now() < deadline) {
        const message = await $(SEL_ERROR).getText();
        if (!/^Status: 404\b/.test(message)) {
            return;
        }
        console.warn(
            `MSD does not know ${TEST_DOMAIN}.${TEST_SERVICE} yet (${message}), retrying in ${MSD_SYNC_POLL}ms`
        );
        await browser.pause(MSD_SYNC_POLL);
        await browser.refresh();
        state = await waitForSnapshotList();
    }
};

describe('Microsegmentation snapshots', () => {
    let currentTest;
    let needsSnapshotCleanup = false;

    before(async function () {
        this.timeout(MSD_SYNC_TIMEOUT + 120000);
        await beforeEachTest();
        await ensureTestService();
        await waitForMsdToKnowTestService();
    });

    beforeEach(async () => {
        await beforeEachTest();
        needsSnapshotCleanup = false;
    });

    it(TEST_SECTION_RENDERS_AND_LOADS, async () => {
        currentTest = TEST_SECTION_RENDERS_AND_LOADS;

        const state = await openSnapshots(TEST_DOMAIN, TEST_SERVICE);

        // the list must reach a data state; an error here means MSD is not
        // reachable or the principal is not authorized in this environment
        if (state === STATE_ERROR) {
            const message = await $(SEL_ERROR).getText();
            throw new Error(
                `Snapshot list failed to load for ${TEST_DOMAIN}.${TEST_SERVICE}: ${message}`
            );
        }
        expect([STATE_TABLE, STATE_EMPTY]).toContain(state);

        // header carries the count once loaded and the count matches the rows
        expect(await headerCount()).toBe(await snapshotCount());
        await waitForElementExist('button*=Add Snapshot');

        // the guide link is config driven: shown only when a link is set
        const guideLink =
            appConfig.pageFeatureFlag &&
            appConfig.pageFeatureFlag.microsegmentation &&
            appConfig.pageFeatureFlag.microsegmentation.snapshotsGuideLink;
        if (guideLink) {
            const guide = await waitForElementExist(SEL_GUIDE_LINK);
            expect(await guide.getAttribute('href')).toBe(guideLink);
        } else {
            expect(await $(SEL_GUIDE_LINK).isExisting()).toBe(false);
        }
    });

    it(TEST_FORBIDDEN_SHOWS_INLINE_ERROR, async () => {
        currentTest = TEST_FORBIDDEN_SHOWS_INLINE_ERROR;

        const state = await openSnapshots(NON_ADMIN_DOMAIN, NON_ADMIN_SERVICE);

        // MSD's refusal must be rendered as the section's own error banner:
        // never as "No snapshots", and never by replacing the whole page
        expect(state).toBe(STATE_ERROR);
        expect(await $(SEL_ERROR).getText()).toMatch(
            /^You are not authorized to view the policy snapshots of this service\./
        );
        expect(await $(SEL_EMPTY).isExisting()).toBe(false);
        expect(await $(SEL_TABLE).isExisting()).toBe(false);
        expect(
            await $('[data-testid="service-microsegmentation"]').isExisting()
        ).toBe(true);
        await waitForElementExist('button*=Add Snapshot');
    });

    it(TEST_NAME_VALIDATION, async () => {
        currentTest = TEST_NAME_VALIDATION;

        // the Add button is rendered regardless of the list state
        await openSnapshots(TEST_DOMAIN, TEST_SERVICE);
        const before = await snapshotCount();

        await openAddModal();

        // empty name is rejected client-side
        await waitAndClick('button*=Submit');
        await waitForElementExist(textSel('Snapshot name is required.'));

        // whitespace only counts as empty
        await waitAndSetValue(SEL_ADD_NAME, '   ');
        await waitAndClick('button*=Submit');
        await waitForElementExist(textSel('Snapshot name is required.'));

        // names must be dot-separated simple names: no spaces or punctuation
        for (const badName of [
            'bad name',
            'bad!name',
            '.leading-dot',
            'trailing-dot.',
            'double..dot',
            '-leading-dash',
        ]) {
            await waitAndSetValue(SEL_ADD_NAME, badName);
            await waitAndClick('button*=Submit');
            await waitForElementExist(
                textSel('Snapshot name may contain letters, digits')
            );
        }

        // typing clears the error, cancel closes without a request
        await waitAndSetValue(SEL_ADD_NAME, 'valid-name');
        await waitForElementExist(
            textSel('Snapshot name may contain letters, digits'),
            { reverse: true }
        );
        await waitAndClick('button*=Cancel');
        await waitForElementExist(SEL_ADD_MODAL, { reverse: true });

        await browser.refresh();
        await waitForSnapshotList();
        expect(await snapshotCount()).toBe(before);
    });

    it(TEST_CREATE_DEFAULT_INACTIVE, async function () {
        currentTest = TEST_CREATE_DEFAULT_INACTIVE;
        await openSnapshotsOrSkip(this);
        needsSnapshotCleanup = true;
        const before = await snapshotCount();

        // plain name, active switch left off
        await createSnapshot('v1');
        expect(await statusLabel('v1')).toBe('Inactive');
        expect(await snapshotCount()).toBe(before + 1);
        expect(await headerCount()).toBe(before + 1);

        // surrounding whitespace is trimmed before the request
        const trimmed = await createSnapshot('  trim-me  ');
        expect(trimmed).toBe('trim-me');
        expect(await $(rowSel('trim-me')).isExisting()).toBe(true);

        // dots, dashes and underscores are legal separators and characters
        await createSnapshot('rel-1.0_a');
        expect(await snapshotCount()).toBe(before + 3);
        expect(await headerCount()).toBe(before + 3);

        // the list survives a reload with the same rows
        await browser.refresh();
        await waitForSnapshotList();
        for (const name of ['v1', 'trim-me', 'rel-1.0_a']) {
            await waitForElementExist(rowSel(name));
        }
        expect(await snapshotCount()).toBe(before + 3);
    });

    it(TEST_NAMES_CASE_SENSITIVE, async function () {
        currentTest = TEST_NAMES_CASE_SENSITIVE;
        await openSnapshotsOrSkip(this);
        needsSnapshotCleanup = true;
        const before = await snapshotCount();

        await createSnapshot('v1');
        await createSnapshot('V1');

        // two distinct snapshots, neither lower-cased nor merged
        await waitForElementExist(rowSel('v1'));
        await waitForElementExist(rowSel('V1'));
        expect(await snapshotCount()).toBe(before + 2);

        // deleting one leaves the other in place
        await waitAndClick(deleteSel('V1'));
        await waitForElementExist(SEL_DELETE_MESSAGE);
        await confirmDeleteWithForceIfNeeded('V1');
        await expectToast('Snapshot V1 deleted');
        expect(await $(rowSel('v1')).isExisting()).toBe(true);
        expect(await snapshotCount()).toBe(before + 1);
    });

    it(TEST_CREATE_DUPLICATE_REJECTED, async function () {
        currentTest = TEST_CREATE_DUPLICATE_REJECTED;
        await openSnapshotsOrSkip(this);
        needsSnapshotCleanup = true;

        await createSnapshot('dup');
        const before = await snapshotCount();

        await openAddModal();
        await waitAndSetValue(SEL_ADD_NAME, 'dup');
        await waitAndClick('button*=Submit');

        // MSD answers 409; the modal stays open with the MSD message inline
        const error = await waitForElementExist(textSel('Status: 409.'));
        expect(await error.getText()).toMatch(/^Status: 409\. Message: /);
        expect(await $(SEL_ADD_MODAL).isExisting()).toBe(true);

        await waitAndClick('button*=Cancel');
        await waitForElementExist(SEL_ADD_MODAL, { reverse: true });
        expect(await snapshotCount()).toBe(before);
    });

    it(TEST_TOGGLE_ACTIVE, async function () {
        currentTest = TEST_TOGGLE_ACTIVE;
        await openSnapshotsOrSkip(this);
        needsSnapshotCleanup = true;

        await createSnapshot('toggle-me');
        expect(await statusLabel('toggle-me')).toBe('Inactive');

        // inactive -> active
        await waitAndClick(activeSwitchSel('toggle-me'));
        await expectToast('Snapshot toggle-me marked active');
        await browser.waitUntil(
            async () => (await statusLabel('toggle-me')) === 'Active',
            { timeout: 30000, timeoutMsg: 'Snapshot did not become active' }
        );
        expect(
            await $('[data-testid="snapshot-update-error"]').isExisting()
        ).toBe(false);

        // state comes from MSD, not from the click: it survives a reload
        await browser.refresh();
        await waitForSnapshotList();
        expect(await statusLabel('toggle-me')).toBe('Active');

        // active -> inactive
        await waitAndClick(activeSwitchSel('toggle-me'));
        await expectToast('Snapshot toggle-me marked inactive');
        await browser.waitUntil(
            async () => (await statusLabel('toggle-me')) === 'Inactive',
            { timeout: 30000, timeoutMsg: 'Snapshot did not become inactive' }
        );
    });

    it(TEST_EXPAND_DETAILS, async function () {
        currentTest = TEST_EXPAND_DETAILS;
        await openSnapshotsOrSkip(this);
        needsSnapshotCleanup = true;

        await createSnapshot('details');
        expect(await $(SEL_DETAILS).isExisting()).toBe(false);

        // expand: the snapshot and its usage are fetched on first open
        await waitAndClick(viewSel('details'));
        await waitForElementExist(SEL_DETAILS);
        await waitForElementExist(SEL_INGRESS);
        await waitForElementExist(SEL_EGRESS);

        const details = await $(SEL_DETAILS).getText();
        expect(details).toMatch(/Inbound \(\d+\)/);
        expect(details).toMatch(/Outbound \(\d+\)/);
        expect(details).toContain('Last used by');

        // usage resolves to one of its terminal states: a list of principals,
        // an authoritative "no use", an incomplete warning, or MSD's error
        await browser.waitUntil(
            async () => {
                const usage = await $(SEL_USAGE).getText();
                return (
                    /No recorded use|Usage data is incomplete|Status: \d+/.test(
                        usage
                    ) ||
                    (await $(
                        '[data-testid="snapshot-usage-table"]'
                    ).isExisting())
                );
            },
            { timeout: 30000, timeoutMsg: 'Usage section did not load' }
        );
        // a snapshot that was just created has never been used
        expect(await $(SEL_USAGE).getText()).toMatch(
            /No recorded use|Usage data is incomplete/
        );

        // collapse hides the details row again
        await waitAndClick(viewSel('details'));
        await waitForElementExist(SEL_DETAILS, { reverse: true });
    });

    it(TEST_DELETE_ACTIVE_NEEDS_FORCE, async function () {
        currentTest = TEST_DELETE_ACTIVE_NEEDS_FORCE;
        await openSnapshotsOrSkip(this);
        needsSnapshotCleanup = true;

        await createSnapshot('active-one', true);
        expect(await statusLabel('active-one')).toBe('Active');

        // first confirmation is the plain delete
        await waitAndClick(deleteSel('active-one'));
        const message = await waitForElementExist(SEL_DELETE_MESSAGE);
        expect(await message.getText()).toContain(
            'Are you sure you want to permanently delete the snapshot'
        );
        expect(await $(SEL_DELETE_SUBMIT).getText()).toBe('Delete');
        await waitAndClick(SEL_DELETE_SUBMIT);

        // MSD refuses with 409; the modal asks again quoting MSD and offering force
        await browser.waitUntil(
            async () =>
                (await $(SEL_DELETE_SUBMIT).getText()) === 'Force delete',
            {
                timeout: 30000,
                timeoutMsg: 'Delete modal did not switch to force delete',
            }
        );
        const forceMessage = await $(SEL_DELETE_MESSAGE).getText();
        expect(forceMessage).toContain('Force delete snapshot');
        expect(forceMessage).toContain('active-one');
        expect(await $(rowSel('active-one')).isExisting()).toBe(true);

        // cancelling the forced confirmation keeps the snapshot
        await waitAndClick(SEL_DELETE_CANCEL);
        await waitForElementExist(SEL_DELETE_MESSAGE, { reverse: true });
        await browser.refresh();
        await waitForSnapshotList();
        await waitForElementExist(rowSel('active-one'));
        expect(await statusLabel('active-one')).toBe('Active');

        // starting over: plain delete -> 409 -> force delete removes it
        await waitAndClick(deleteSel('active-one'));
        await waitForElementExist(SEL_DELETE_MESSAGE);
        await waitAndClick(SEL_DELETE_SUBMIT);
        await browser.waitUntil(
            async () =>
                (await $(SEL_DELETE_SUBMIT).getText()) === 'Force delete',
            {
                timeout: 30000,
                timeoutMsg: 'Delete modal did not switch to force delete',
            }
        );
        await waitAndClick(SEL_DELETE_SUBMIT);
        await expectToast('Snapshot active-one deleted');
        await waitForElementExist(rowSel('active-one'), { reverse: true });

        await browser.refresh();
        await waitForSnapshotList();
        expect(await $(rowSel('active-one')).isExisting()).toBe(false);
    });

    it(TEST_DELETE_INACTIVE_AND_CANCEL, async function () {
        currentTest = TEST_DELETE_INACTIVE_AND_CANCEL;
        await openSnapshotsOrSkip(this);
        needsSnapshotCleanup = true;

        await createSnapshot('inactive-one');
        const before = await snapshotCount();

        // cancel leaves the snapshot untouched
        await waitAndClick(deleteSel('inactive-one'));
        await waitForElementExist(SEL_DELETE_MESSAGE);
        await waitAndClick(SEL_DELETE_CANCEL);
        await waitForElementExist(SEL_DELETE_MESSAGE, { reverse: true });
        expect(await $(rowSel('inactive-one')).isExisting()).toBe(true);
        expect(await snapshotCount()).toBe(before);

        // an inactive snapshot goes with a single confirmation, no force step
        await waitAndClick(deleteSel('inactive-one'));
        await waitForElementExist(SEL_DELETE_MESSAGE);
        await waitAndClick(SEL_DELETE_SUBMIT);
        await expectToast('Snapshot inactive-one deleted');
        await waitForElementExist(rowSel('inactive-one'), { reverse: true });
        expect(await snapshotCount()).toBe(before - 1);
        expect(await headerCount()).toBe(before - 1);

        // gone for good, not just from the client state
        await browser.refresh();
        const state = await waitForSnapshotList();
        expect(await $(rowSel('inactive-one')).isExisting()).toBe(false);
        if (before - 1 === 0) {
            expect(state).toBe(STATE_EMPTY);
        }
    });

    // cleanup after tests
    afterEach(async () => {
        try {
            if (needsSnapshotCleanup) {
                await deleteAllSnapshots();
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

    // the fixture service itself is kept on purpose, see the file comment
    after(async () => {
        try {
            await deleteAllSnapshots();
        } catch (error) {
            console.error(
                `Cleanup failed for service ${TEST_SERVICE}:`,
                error.message
            );
        }
    });
});
