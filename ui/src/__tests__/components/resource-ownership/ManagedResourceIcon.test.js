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
import { ManagedResourceIcon } from '../../../components/resource-ownership/ManagedResourceIcon';

describe('ManagedResourceIcon', () => {
    it('renders nothing when show is false', () => {
        const { container } = render(<ManagedResourceIcon show={false} />);
        expect(container.firstChild).toBeNull();
    });

    it('renders icon with stable data-wdio when shown', () => {
        const { container } = render(
            <ManagedResourceIcon
                show={true}
                resourceOwnershipUi={{ icon: 'terraform', label: 'OpenTofu' }}
                tooltip='Custom tooltip'
            />
        );
        const svg = container.querySelector(
            '[data-wdio="resource-ownership-managed"]'
        );
        expect(svg).toBeTruthy();
    });
});
