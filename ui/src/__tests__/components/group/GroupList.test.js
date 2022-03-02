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
import GroupList from '../../../components/group/GroupList';
import API from '../../../api';

describe('GroupList', () => {
    it('should render', () => {
        let api = API();
        let domain = 'athenz';
        let _csrf = '_csrfToken';
        let users = [];
        let groups = [];

        let headerDetails = {
            userData: {
                userLink: {
                    title: 'User Link',
                    url: '',
                    target: '_blank',
                },
            },
        };

        const { getByTestId } = render(
            <GroupList
                api={api}
                domain={domain}
                groups={groups}
                users={users}
                _csrf={_csrf}
                isDomainAuditEnabled={true}
                userProfileLink={headerDetails.userData.userLink}
            />
        );
        const grouplist = getByTestId('grouplist');

        expect(grouplist).toMatchSnapshot();
    });
});
