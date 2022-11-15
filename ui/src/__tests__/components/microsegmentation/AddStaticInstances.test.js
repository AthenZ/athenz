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
import { fireEvent, render } from '@testing-library/react';
import AddStaticinstances from '../../../components/microsegmentation/AddStaticInstances';
import API from '../../../api';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';
import { resetIdCounter } from 'downshift';

describe('AddStaticInstances', () => {
    beforeEach(() => resetIdCounter());
    it('should render', () => {
        let domain = 'domain';
        const showAddStaticinstances = true;
        const cancel = function () {};
        const submit = function () {};
        let _csrf = 'csrf';

        const { getByTestId } = renderWithRedux(
            <AddStaticinstances
                domainName={domain}
                onSubmit={submit}
                onCancel={cancel}
                _csrf={_csrf}
                showAddInstance={showAddStaticinstances}
                justificationRequired={false}
            />
        );
        const addinstances = getByTestId('add-modal-message');
        expect(addinstances).toMatchSnapshot();
    });

    it('should render fail to submit add-segmentation: ResourceType is required', () => {
        const showAddStaticinstances = true;
        const cancel = function () {};
        const domain = 'domain';
        let role = 'roleName';
        const submit = function () {};
        let _csrf = 'csrf';
        const { getByTestId, getByText } = renderWithRedux(
            <AddStaticinstances
                domainName={domain}
                onSubmit={submit}
                onCancel={cancel}
                _csrf={_csrf}
                showAddInstance={showAddStaticinstances}
            />
        );
        const addStaticinstances = getByTestId('add-modal-message');
        expect(addStaticinstances).toMatchSnapshot();

        fireEvent.click(getByText('Submit'));

        expect(getByText('Resource Type is required.')).not.toBeNull();
    });
});
