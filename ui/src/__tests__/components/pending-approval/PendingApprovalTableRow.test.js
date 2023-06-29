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
import { render } from '@testing-library/react';
import PendingApprovalTableRow from '../../../components/pending-approval/PendingApprovalTableRow';
import { PENDING_STATE_ENUM } from '../../../components/constants/constants';

describe('PendingApprovalTable', () => {
    it('should render', () => {
        const color = 'white';
        const domainName = 'a';
        const memberName = 'b';
        const roleName = 'c';
        const checked = false;
        const userComment = 'd';
        const timeZone = 'UTC';

        const { getByTestId } = render(
            <table>
                <tbody>
                    <PendingApprovalTableRow
                        color={color}
                        domainName={domainName}
                        memberName={memberName}
                        roleName={roleName}
                        checkedf={checked}
                        userComment={userComment}
                        pendingDecision={() => {}}
                        auditRefMissing={false}
                        pendingState={PENDING_STATE_ENUM.ADD}
                        timeZone={timeZone}
                    />
                </tbody>
            </table>
        );

        const pendingapprovaltablerow = getByTestId(
            'pending-approval-table-row'
        );
        expect(pendingapprovaltablerow).toMatchSnapshot();
    });
});
