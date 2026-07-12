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
import React from 'react';
import { render } from '@testing-library/react';
import { Provider } from 'react-redux';
import { createStore } from 'redux';
import ResourceOwnershipModalFeedback from '../../../components/resource-ownership/ResourceOwnershipModalFeedback';

const store = createStore(() => ({
    domains: { headerDetails: {} },
}));

function renderWithStore(ui) {
    return render(<Provider store={store}>{ui}</Provider>);
}

describe('ResourceOwnershipModalFeedback', () => {
    it('shows CLI suggestion instead of raw error when command is set', () => {
        const { getByTestId, queryByText } = renderWithStore(
            <ResourceOwnershipModalFeedback
                errorMessage='Forbidden'
                resourceOwnershipCliCommand={() => 'zms-cli -d dom'}
            />
        );
        expect(getByTestId('resource-ownership-cli-suggestion')).toBeTruthy();
        expect(queryByText('Forbidden')).toBeNull();
    });

    it('shows error when no CLI command', () => {
        const { getByText } = renderWithStore(
            <ResourceOwnershipModalFeedback
                errorMessage='Forbidden'
                resourceOwnershipCliCommand={null}
            />
        );
        expect(getByText('Forbidden')).toBeTruthy();
    });
});
