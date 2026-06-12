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
 * See the License for the specific language governing permissions and limitations
 * under the License.
 */
import {
    DEFAULT_RESOURCE_OWNERSHIP_UI,
    formatResourceOwnershipUiString,
    getCliSuggestionBody,
    getCliSuggestionWarningLead,
    getManagedIconTooltip,
    getMembersManagedIconTooltip,
    getRoleListManagedIconTooltip,
    resolveResourceOwnershipUi,
} from '../../../components/utils/resourceOwnershipUi';

const config = require('../../../config/config');

describe('resourceOwnershipUi', () => {
    it('uses built-in defaults when config is missing', () => {
        const ui = resolveResourceOwnershipUi();
        expect(ui.icon).toBe('terraform');
        expect(ui.label).toBe('Terraform');
    });

    it('merges deployment overrides', () => {
        const ui = resolveResourceOwnershipUi({
            label: 'OpenTofu',
            icon: 'terraform',
        });
        expect(ui.label).toBe('OpenTofu');
        expect(getManagedIconTooltip(ui)).toBe(
            'This resource is managed by OpenTofu (ownership in ZMS).'
        );
        expect(getCliSuggestionBody(ui)).toContain('OpenTofu-managed');
        expect(getCliSuggestionBody(ui)).toContain(
            'through OpenTofu configuration'
        );
    });

    it('substitutes {{label}} in templates', () => {
        expect(
            formatResourceOwnershipUiString('Managed by {{label}}.', 'Custom')
        ).toBe('Managed by Custom.');
        expect(
            formatResourceOwnershipUiString(
                'Managed by {{label}}.',
                DEFAULT_RESOURCE_OWNERSHIP_UI.label
            )
        ).toBe('Managed by Terraform.');
    });

    it('formats members managed icon tooltip', () => {
        expect(getMembersManagedIconTooltip({ label: 'OpenTofu' })).toBe(
            'Role membership is managed by OpenTofu (members owner).'
        );
    });

    it('uses members tooltip for members-only role list rows', () => {
        expect(
            getRoleListManagedIconTooltip(
                { membersOwner: 'terraform' },
                { label: 'Terraform' }
            )
        ).toBe('Role membership is managed by Terraform (members owner).');
    });

    it('config resourceOwnershipUi matches DEFAULT_RESOURCE_OWNERSHIP_UI', () => {
        expect(config().resourceOwnershipUi).toEqual(
            DEFAULT_RESOURCE_OWNERSHIP_UI
        );
    });

    it('exposes warning lead for functional tests', () => {
        expect(getCliSuggestionWarningLead()).toBe(
            'This resource is Terraform-managed and cannot be edited via the Athenz UI'
        );
    });
});
