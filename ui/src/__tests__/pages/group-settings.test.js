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
import SettingPage from '../../pages/settings';

describe('GroupSettingPage', () => {
    it('should render', () => {
        let group = 'groupName';
        let domains = [];
        domains.push({ name: 'athens' });
        domains.push({ name: 'athens.ci' });
        let query = {
            domain: 'dom',
        };
        let domainDetails = {
            modified: '2020-02-12T21:44:37.792Z',
        };
        let groupDetails = {
            modified: '2020-02-12T21:44:37.792Z',
            memberExpiryDays: '60',
            serviceExpiryDays: '50',
        };
        let headerDetails = {
            headerLinks: [
                {
                    title: 'Website',
                    url: 'http://www.athenz.io',
                    target: '_blank',
                },
            ],
            userData: {
                userLink: {
                    title: 'User Link',
                    url: '',
                    target: '_blank',
                },
            },
        };
        const { getByTestId } = render(
            <SettingPage
                domains={domains}
                req='req'
                userId='userid'
                query={query}
                reload={false}
                domainDetails={domainDetails}
                roleDetails={groupDetails}
                role={group}
                domain='dom'
                domainResult={[]}
                headerDetails={headerDetails}
            />
        );
        const settingPage = getByTestId('setting');
        expect(settingPage).toMatchSnapshot();
    });
});
