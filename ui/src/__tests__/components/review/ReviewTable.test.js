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
import ReviewTable from '../../../components/review/ReviewTable';
import API from '../../../api';

describe('ReviewTable', () => {
    it('should render review table', () => {
        let members = [];
        let domain= 'domain';
        let role = 'roleName';
        const roleDetails = {
            memberExpiryDays: 15,
            serviceExpiryDays: 15,
            groupExpiryDays: null,
            memberReviewDays: null,
            serviceReviewDays: null,
            groupReviewDays: null,
        }
        let user1 = {
            memberName: 'user1',
            approved: true,
        }
        let user2 = {
            memberName: 'user2',
            approved: false,
        }
        let user3 = {
            memberName: 'user3',
            approved: false,
        }
        let user4 = {
            memberName: 'user4',
            approved: true,
        }
        members.push(user1);
        members.push(user2);
        members.push(user3);
        members.push(user4);

        const { getByTestId } = render(
            <ReviewTable api={API()} domain={domain} role={role} roleDetails={roleDetails} members={members} justificationRequired={true} />
        );
        const reviewTable = getByTestId('review-table');

        expect(reviewTable).toMatchSnapshot();
    });
    it('should render review table with reminder settings', () => {
        let members = [];
        let domain= 'domain';
        let role = 'roleName';
        const roleDetails = {
            memberExpiryDays: null,
            serviceExpiryDays: null,
            groupExpiryDays: null,
            memberReviewDays: 5,
            serviceReviewDays: 10,
            groupReviewDays: 15,
        }
        let user1 = {
            memberName: 'user1',
            approved: true,
        }
        let user2 = {
            memberName: 'user2',
            approved: false,
        }
        let user3 = {
            memberName: 'user3',
            approved: false,
        }
        let user4 = {
            memberName: 'user4',
            approved: true,
        }
        members.push(user1);
        members.push(user2);
        members.push(user3);
        members.push(user4);

        const { getByTestId } = render(
            <ReviewTable api={API()} domain={domain} role={role} roleDetails={roleDetails} members={members} justificationRequired={true} />
        );
        const reviewTableReminder = getByTestId('review-table');

        expect(reviewTableReminder).toMatchSnapshot();
    });
    it('should render review table without expiry settings', () => {
        let members = [];
        let domain= 'domain';
        let role = 'roleName';
        const roleDetails = {
            memberExpiryDays: null,
            serviceExpiryDays: null,
            groupExpiryDays: null,
            memberReviewDays: null,
            serviceReviewDays: null,
            groupReviewDays: null,
        }
        let user1 = {
            memberName: 'user1',
            approved: true,
        }
        let user2 = {
            memberName: 'user2',
            approved: false,
        }
        let user3 = {
            memberName: 'user3',
            approved: false,
        }
        let user4 = {
            memberName: 'user4',
            approved: true,
        }
        members.push(user1);
        members.push(user2);
        members.push(user3);
        members.push(user4);

        const { getByTestId } = render(
            <ReviewTable api={API()} domain={domain} role={role} roleDetails={roleDetails} members={members} justificationRequired={true} />
        );
        const reviewTableNoSettings = getByTestId('review-table');

        expect(reviewTableNoSettings).toMatchSnapshot();
    });
});
