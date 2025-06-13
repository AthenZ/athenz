import MockApi from '../../../mock/MockApi';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';
import React from 'react';
import AddGroupAdvancedSettings from '../../../components/group/AddGroupAdvancedSettings';

describe('AddGroup', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
        cleanup();
    });

    it('should have auditEnabled switch', async () => {
        const state = {
            reviewEnabled: false,
            group: {
                auditEnabled: false,
            },
        };

        const toggleAuditEnabled = jest.fn();

        renderWithRedux(
            <AddGroupAdvancedSettings
                advancedSettingsChanged={jest.fn()}
                reviewEnabledChanged={jest.fn()}
                deleteProtectionChanged={jest.fn()}
                auditEnabledChanged={toggleAuditEnabled}
                isDomainAuditEnabled={true}
                members={''}
                group={state.group}
                reviewEnabled={state.reviewEnabled}
            />
        );

        expect(
            screen.getByTestId('settingauditEnabled-switch-input')
        ).toBeInTheDocument();

        expect(
            screen.getByTestId('settingauditEnabled-switch-input')
        ).toBeEnabled();

        expect(
            screen.getAllByTestId('settingauditEnabled-switch-input')
        ).toHaveLength(1);

        fireEvent.click(screen.getByTestId('settingauditEnabled-switch-input'));

        expect(toggleAuditEnabled).toHaveBeenCalled();
    });

    it('should open advanced settings with auditEnabled switch', async () => {
        const state = {
            reviewEnabled: false,
            group: {
                auditEnabled: false,
            },
        };

        const toggleAuditEnabled = jest.fn();

        renderWithRedux(
            <AddGroupAdvancedSettings
                advancedSettingsChanged={jest.fn()}
                reviewEnabledChanged={jest.fn()}
                deleteProtectionChanged={jest.fn()}
                auditEnabledChanged={toggleAuditEnabled}
                isDomainAuditEnabled={true}
                members={''}
                group={state.group}
                reviewEnabled={state.reviewEnabled}
            />
        );

        await waitFor(() => {
            expect(
                screen.queryByTestId('settingauditEnabled-switch-input')
            ).toBeEnabled();
        });
    });
});
