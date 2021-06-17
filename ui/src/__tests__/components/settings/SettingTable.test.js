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
import SettingTable from '../../../components/settings/SettingTable';
import API from '../../../api';

describe('SettingTable', () => {
    it('should render setting table', () => {
        let domain= 'domain';
        let role = 'roleName';
        const roleDetails = {
            reviewEnabled: true,
            selfServe: false,
            memberExpiryDays: 3,
            serviceExpiryDays: 3,
            tokenExpiryMins: 15,
            certExpiryMins: 15,
        }

        const { getByTestId } = render(
            <SettingTable api={API()} category={'role'} domain={domain} collection={role} collectionDetails={roleDetails} justificationRequired={true} userAuthorityAttributes={[]} />
        );
        const settingTable = getByTestId('setting-table');

        expect(settingTable).toMatchSnapshot();
    });
});
