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

const { waitForElementExist, waitAndClick } = require('./helpers');

let defaultZmsUrl;
try {
    defaultZmsUrl = require('../../../config/config')().zms;
} catch (_e) {
    defaultZmsUrl = null;
}

const {
    getCliSuggestionWarningLead,
    resolveResourceOwnershipUi,
} = require('../../../components/utils/resourceOwnershipUi');
const { shellQuote } = require('../../../components/utils/zmsCliCommands');

let appConfig = {};
try {
    appConfig = require('../../../config/config')();
} catch (_e) {
    appConfig = {};
}

const RESOURCE_OWNERSHIP_MANAGED_WARNING = getCliSuggestionWarningLead(
    resolveResourceOwnershipUi(appConfig.resourceOwnershipUi)
);

module.exports.RESOURCE_OWNERSHIP_MANAGED_WARNING =
    RESOURCE_OWNERSHIP_MANAGED_WARNING;

/**
 * Assert the managed-resource icon appears within a row/container matched by selector.
 * @param {String} containerSelector - CSS or XPath selector for the row
 */

module.exports.expectManagedResourceIconInContainer = async (
    containerSelector
) => {
    const container = await $(containerSelector);
    await container.waitForExist({
        timeout: 10000,
        timeoutMsg: `Container not found: ${containerSelector}`,
    });

    // XPath relative to container works regardless of container selector strategy.
    const icon = await container.$(
        `.//*[local-name()="svg" and @data-wdio="resource-ownership-managed"]`
    );
    await icon.waitForExist({
        timeout: 10000,
        timeoutMsg: `Managed-resource icon not found in ${containerSelector}`,
    });
};

/**
 * Assert the managed-resource icon does not appear within a container.
 * @param {String} containerSelector
 */
module.exports.expectNoManagedResourceIconInContainer = async (
    containerSelector
) => {
    const container = await $(containerSelector);
    await container.waitForExist({
        timeout: 5000,
        timeoutMsg: `Container not found: ${containerSelector}`,
    });
    const icon = await container.$(
        `.//*[local-name()="svg" and @data-wdio="resource-ownership-managed"]`
    );
    expect(await icon.isExisting()).toBe(false);
};

/**
 * Wait for resource-ownership CLI suggestion and verify expected substrings in the command/warning text.
 * @param {Object} options
 * @param {String} options.domain - Athenz domain for zms-cli -d flag
 * @param {String[]} options.commandParts - substrings expected in the zms-cli command (e.g. 'delete-role')
 * @param {Boolean} [options.expectIgnoreFlag=true] - expect `-r ignore` resource-owner bypass flag
 * @param {String} [options.zmsUrl] - when set, expect `-z` with this ZMS base URL
 */
module.exports.expectResourceOwnershipCliSuggestion = async (options) => {
    const {
        domain,
        commandParts,
        expectIgnoreFlag = true,
        zmsUrl = defaultZmsUrl,
    } = options;
    const suggestion = await waitForElementExist(
        '[data-testid="resource-ownership-cli-suggestion"]'
    );
    const text = await suggestion.getText();
    expect(text).toContain(RESOURCE_OWNERSHIP_MANAGED_WARNING);
    if (expectIgnoreFlag) {
        expect(text).toContain('zms-cli');
        if (zmsUrl) {
            expect(text).toContain(`-z ${shellQuote(zmsUrl)}`);
        }
        expect(text).toContain(`-d ${shellQuote(domain)}`);
        expect(text).toContain('-r ignore');
    }
    for (const part of commandParts) {
        expect(text).toContain(part);
    }
    const copyButton = await suggestion.$(
        '[data-testid="resource-ownership-cli-copy"]'
    );
    await expect(copyButton).toExist();
};

/**
 * Close an open delete modal without submitting.
 */
module.exports.cancelDeleteModal = async () => {
    const cancel = await $('button[data-testid="delete-modal-cancel"]');
    if (await cancel.isExisting()) {
        await waitAndClick(cancel);
    }
};

/**
 * Close an open update modal without submitting.
 */
module.exports.cancelUpdateModal = async () => {
    const cancel = await $('button[data-testid="update-modal-cancel"]');
    if (await cancel.isExisting()) {
        await waitAndClick(cancel);
    }
};
