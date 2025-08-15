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
import React from 'react';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import {
    buildServicesForState,
    getStateWithServices,
    renderWithRedux,
} from '../../../tests_utils/ComponentsTestUtils';
import AddSegmentation from '../../../components/microsegmentation/AddSegmentation';
import { resetIdCounter } from 'downshift';
import RegexUtils from '../../../components/utils/RegexUtils';

jest.mock('../../../components/utils/RegexUtils', () => ({
    __esModule: true,
    default: {
        validate: jest.fn(),
    },
}));

const services = buildServicesForState([
    { name: 'domain.service1' },
    { name: 'domain.service2' },
]);

describe('AddSegmentation', () => {
    beforeEach(() => {
        resetIdCounter();
    });
    const pageFeatureFlag = {
        policyValidation: true,
    };

    beforeEach(() => resetIdCounter());

    it('should render', () => {
        let domain = 'domain';
        const showAddSegmentation = true;
        const cancel = function () {};
        const submit = function () {};
        let _csrf = 'csrf';
        const { getByTestId } = renderWithRedux(
            <AddSegmentation
                domain={domain}
                onSubmit={submit}
                onCancel={cancel}
                _csrf={_csrf}
                showAddSegment={showAddSegmentation}
                justificationRequired={false}
                pageFeatureFlag={pageFeatureFlag}
            />,
            getStateWithServices(services)
        );
        const addsegment = getByTestId('add-segment');
        expect(addsegment).toMatchSnapshot();
    });

    it('should render fail to submit add-segmentation: destinationService is required', () => {
        const showAddSegmentation = true;
        const cancel = function () {};
        const domain = 'domain';
        const submit = function () {};
        let _csrf = 'csrf';
        const { getByTestId, getByText } = renderWithRedux(
            <AddSegmentation
                domain={domain}
                onSubmit={submit}
                onCancel={cancel}
                _csrf={_csrf}
                showAddSegment={showAddSegmentation}
                justificationRequired={false}
                pageFeatureFlag={pageFeatureFlag}
            />
        );
        const addSegmentation = getByTestId('add-modal-message');
        expect(addSegmentation).toMatchSnapshot();
    });
});

describe('AddSegmentation scope handling', () => {
    beforeEach(() => resetIdCounter());

    const pageFeatureFlag = { policyValidation: true };
    const mockOnSubmit = jest.fn();
    const showError = jest.fn();

    const defaultProps = {
        domain: 'domain',
        onSubmit: mockOnSubmit,
        onCancel: jest.fn(),
        _csrf: 'csrf',
        showAddSegment: true,
        justificationRequired: false,
        pageFeatureFlag,
        showError: showError,
    };

    it('should handle scopeall checkbox correctly', async () => {
        renderWithRedux(
            <AddSegmentation {...defaultProps} />,
            getStateWithServices(services)
        );

        const scopeAllCheckbox = screen.getByLabelText('All');
        // Initially, scope All checkbox should be unchecked
        expect(scopeAllCheckbox.checked).toBe(false);

        fireEvent.click(scopeAllCheckbox);
        // It should be checked now
        expect(scopeAllCheckbox.checked).toBe(true);
        // Other scope checkboxes should be disabled
        const onPremCheckbox = screen.getByLabelText('On-Prem');
        expect(onPremCheckbox.disabled).toBe(true);
        const gcpCheckbox = screen.getByLabelText('GCP');
        expect(gcpCheckbox.disabled).toBe(true);
        const awsCheckbox = screen.getByLabelText('AWS');
        expect(awsCheckbox.disabled).toBe(true);

        fireEvent.click(scopeAllCheckbox);
        // It should be unchecked now
        expect(scopeAllCheckbox.checked).toBe(false);
        expect(onPremCheckbox.disabled).toBe(false);
        expect(gcpCheckbox.disabled).toBe(false);
        expect(awsCheckbox.disabled).toBe(false);
    });

    it('should display validation errors for mandatory fields', async () => {
        // mock regex validation to always return true
        RegexUtils.validate.mockImplementation((value, regex) => {
            return true;
        });

        renderWithRedux(
            <AddSegmentation {...defaultProps} />,
            getStateWithServices(services)
        );

        const submitButton = screen.getByText('Submit');
        fireEvent.click(submitButton);
        // first error for destination service
        await waitFor(() => {
            expect(
                screen.getByText('Destination service is required.')
            ).toBeInTheDocument();
        });

        const destServiceInput = screen.getByPlaceholderText(
            'Select Destination Service'
        );
        fireEvent.click(destServiceInput);
        fireEvent.click(screen.getByText('service1'));
        fireEvent.click(submitButton);
        // next error for destination port
        await waitFor(() => {
            expect(
                screen.getByText('Destination Port is required.')
            ).toBeInTheDocument();
        });

        const destPortInput = screen.getByPlaceholderText('eg: 4443');
        fireEvent.change(destPortInput, { target: { value: '443' } });
        fireEvent.click(submitButton);
        // next error for source service
        await waitFor(() => {
            expect(
                screen.getByText('Invalid source service')
            ).toBeInTheDocument();
        });

        const sourceServiceInput = screen.getByPlaceholderText(
            'eg: yamas.api, sys.auth.zms'
        );
        fireEvent.change(sourceServiceInput, {
            target: { value: 'domain.sourceservice' },
        });
        fireEvent.click(submitButton);
        // next error for protocol
        await waitFor(() => {
            expect(
                screen.getByText('Protocol is required.')
            ).toBeInTheDocument();
        });

        const protocolDropdown = screen.getByPlaceholderText('Select Protocol');
        fireEvent.click(protocolDropdown);
        fireEvent.click(screen.getByText('TCP'));
        fireEvent.click(submitButton);
        // next error for identifier
        await waitFor(() => {
            expect(
                screen.getByText('Identifier is required.')
            ).toBeInTheDocument();
        });

        const identifierInput = screen.getByPlaceholderText(
            'Enter a unique identifier for this ACL policy'
        );
        fireEvent.change(identifierInput, {
            target: { value: 'testidentifier' },
        });
        // Uncheck all scopes to test scope validation
        const onPremCheckbox = screen.getByLabelText('On-Prem');
        fireEvent.click(onPremCheckbox); // Uncheck the default checked On-Prem
        fireEvent.click(submitButton);
        // last error for scope
        await waitFor(() => {
            expect(
                screen.getByText('Please select at least one scope.')
            ).toBeInTheDocument();
        });
    });
});
