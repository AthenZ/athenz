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
import ReviewMembersRow from '../../../components/role/ReviewMembersRow';
import { colors } from '../../../components/denali/styles';

describe('ReviewMembersRow', () => {
    it('should render', () => {
        let idx = 'role-review-0';
        let details = {
            memberName: 'user.abhijetv',
            expiration: '2020-04-09T04:43:07.028Z',
            approved: true,
            auditRef: 'Added using Athenz UI',
        };
        let role = 'self-serve1';
        let color = colors.white;
        let submittedReview = false;

        const { getByTestId } = render(
            <table>
                <tbody>
                    <ReviewMembersRow
                        details={details}
                        role={role}
                        color={color}
                        idx={idx}
                        submittedReview={submittedReview}
                    />
                </tbody>
            </table>
        );
        const roleReviewRow = getByTestId('role-review-row');

        expect(roleReviewRow).toMatchSnapshot();
    });
});
