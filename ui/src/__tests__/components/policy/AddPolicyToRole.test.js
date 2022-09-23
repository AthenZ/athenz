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
import { render, fireEvent } from '@testing-library/react';
import AddPolicyToRole from '../../../components/policy/AddPolicyToRole';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';

describe('AddPolicyToRole', () => {
    it('should render', () => {
        const showAddPolicy = true;
        const cancel = function () {};
        const domain = 'domain';
        const role = 'roleName';
        const { getByTestId } = renderWithRedux(
            <AddPolicyToRole
                showAddPolicy={showAddPolicy}
                onCancel={cancel}
                domain={domain}
                role={role}
            />
        );
        const addPolicy = getByTestId('add-modal-message');
        expect(addPolicy).toMatchSnapshot();
    });

    it('should render fail to submit policy name is required', () => {
        const showAddPolicy = true;
        const cancel = function () {};
        const domain = 'domain';
        const role = 'roleName';
        const { getByTestId, getByText } = renderWithRedux(
            <AddPolicyToRole
                showAddPolicy={showAddPolicy}
                onCancel={cancel}
                domain={domain}
                role={role}
            />
        );
        const addPolicy = getByTestId('add-modal-message');
        expect(addPolicy).toMatchSnapshot();

        fireEvent.click(getByText('Submit'));

        expect(getByText('Policy name is required.')).not.toBeNull();
    });

    it('should render failed to submit action is required', () => {
        const showAddPolicy = true;
        const cancel = function () {};
        const domain = 'domain';
        const role = 'roleName';
        const { getByTestId, getByText, getByPlaceholderText } =
            renderWithRedux(
                <AddPolicyToRole
                    showAddPolicy={showAddPolicy}
                    onCancel={cancel}
                    domain={domain}
                    role={role}
                />
            );
        const addPolicy = getByTestId('add-modal-message');
        expect(addPolicy).toMatchSnapshot();

        fireEvent.change(getByPlaceholderText('Policy Name'), {
            target: { value: 'policyname' },
        });
        fireEvent.click(getByText('Submit'));

        expect(getByText('Rule action is required.')).not.toBeNull();
    });
});
