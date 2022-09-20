/*
 * Copyright 2020 Verizon Media
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
import { render } from '@testing-library/react';
import AddRole from '../../../components/role/AddRole';
import API from '../../../api';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';

describe('AddRole', () => {
    it('should render', () => {
        let domain = 'domain';
        const onCancelMock = jest.fn();

        const { getByTestId } = renderWithRedux(
            <AddRole
                domain={domain}
                justificationRequired={true}
                showAddRole={true}
                onCancel={onCancelMock}
            />
        );
        const addRoleForm = getByTestId('add-role');
        expect(addRoleForm).toMatchSnapshot();
    });
});
