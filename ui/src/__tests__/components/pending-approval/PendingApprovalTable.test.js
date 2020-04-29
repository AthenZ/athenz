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
import PendingApprovalTable from '../../../components/pending-approval/PendingApprovalTable';

describe('PendingApprovalTable', () => {
    it('should render', () => {
        const query = {
            domain: 'dom',
        };
        const domains = ['athens', 'athens.ci'];
        const userId = 'pgote';
        const domain = 'home.pgote';
        const api = {};
        const { getByTestId } = render(
            <PendingApprovalTable
                domains={domains}
                req='req'
                userId={userId}
                query={query}
                domain={domain}
                pendingData={undefined}
                domainResult={[]}
                api={api}
            />
        );

        const pendingapprovaltable = getByTestId('pending-approval-table');
        expect(pendingapprovaltable).toMatchSnapshot();
    });
});
