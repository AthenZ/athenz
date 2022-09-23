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
import SettingRow from '../../../components/settings/SettingRow';
import { colors } from '../../../components/denali/styles';

describe('SettingRow', () => {
    it('should render switch type setting row', () => {
        let domain = 'domain';
        let role = 'roleName';
        const roleDetails = {
            reviewEnabled: true,
            selfServe: false,
            memberExpiryDays: 3,
            serviceExpiryDays: 3,
            tokenExpiryMins: 15,
            certExpiryMins: 15,
        };
        const { getByTestId } = render(
            <table>
                <tbody>
                    <SettingRow
                        roleDetails={roleDetails}
                        domain={domain}
                        role={role}
                        name='test'
                        label='Test'
                        type='switch'
                        desc='desc for testing'
                        value={true}
                        justificationRequired={true}
                    />
                </tbody>
            </table>
        );

        const settingRow = getByTestId('setting-row');

        expect(settingRow).toMatchSnapshot();
    });
    it('should render input type setting row', () => {
        let domain = 'domain';
        let role = 'roleName';
        const roleDetails = {
            reviewEnabled: true,
            selfServe: false,
            memberExpiryDays: 3,
            serviceExpiryDays: 3,
            tokenExpiryMins: 15,
            certExpiryMins: 15,
        };
        const { getByTestId } = render(
            <table>
                <tbody>
                    <SettingRow
                        roleDetails={roleDetails}
                        domain={domain}
                        role={role}
                        name='test'
                        label='Test'
                        type='input'
                        desc='desc for testing'
                        value={'15'}
                        justificationRequired={true}
                    />
                </tbody>
            </table>
        );

        const settingRow = getByTestId('setting-row');

        expect(settingRow).toMatchSnapshot();
    });
});
