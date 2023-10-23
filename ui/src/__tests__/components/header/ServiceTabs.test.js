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
import { render, fireEvent } from '@testing-library/react';
import ServiceTabs from '../../../components/header/ServiceTabs';

describe('Service Tabs', () => {
    it('should render with feature flag turned on', () => {
        const api = {
            getStatus() {
                return new Promise((resolve, reject) => {
                    resolve([]);
                });
            },
        };

        let domain = 'home.mujibur';
        let service = 'openstack';
        const { getByTestId } = render(
            <ServiceTabs
                domain={domain}
                service={service}
                selectedName='dynamic'
                api={api}
                featureFlag={true}
            />
        );
        const tabs = getByTestId('tabgroup');
        const tab = tabs.querySelectorAll('.denali-tab');
        fireEvent.click(tab[0]);
        fireEvent.click(tab[1]);
        expect(tabs).toMatchSnapshot();
    });

    it('should render only one tab without feature flag', () => {
        const api = {
            getStatus() {
                return new Promise((resolve, reject) => {
                    resolve([]);
                });
            },
        };

        let domain = 'home.jtsang01';
        let service = 'openstack';
        const { getByTestId } = render(
            <ServiceTabs
                domain={domain}
                service={service}
                selectedName='dynamic'
                api={api}
                featureFlag={false}
            />
        );
        const tabs = getByTestId('tabgroup');
        const tab = tabs.querySelectorAll('.denali-tab');
        fireEvent.click(tab[0]);
        expect(tabs).toMatchSnapshot();
    });
});
