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
import { fireEvent, screen } from '@testing-library/react';
import InstanceList from '../../../components/service/InstanceList';
import {
    buildServicesForState,
    getStateWithServices,
    renderWithRedux,
} from '../../../tests_utils/ComponentsTestUtils';
import { serviceDelimiter } from '../../../redux/config';

describe('InstanceList', () => {
    it('should render for static', () => {
        let domain = 'athenz';
        let _csrf = '_csrfToken';
        let instanceDetails = [
            {
                domainName: 'test',
                serviceName: 'testService',
                type: 'SERVICE_SUBNET',
                name: '10.0.0.0/8',
                updateTime: '2023-09-27T22:16:55.326Z',
            },
            {
                domainName: 'test',
                serviceName: 'testService',
                type: 'SERVICE_SUBNET',
                name: '10.255.255.0/31',
                updateTime: '2023-09-27T23:29:59.326Z',
            },
            {
                domainName: 'test',
                serviceName: 'testService',
                type: 'SERVICE_SUBNET',
                name: '10.255.255.0/8',
                updateTime: '2023-09-27T23:29:42.864Z',
            },
            {
                domainName: 'test',
                serviceName: 'testService',
                type: 'EXTERNAL_APPLIANCE',
                name: '12.12.12.12/12',
                updateTime: '2023-09-27T22:18:23.458Z',
            },
            {
                domainName: 'test',
                serviceName: 'testService',
                type: 'EXTERNAL_APPLIANCE',
                name: '255.255.0.0',
                updateTime: '2023-09-27T22:18:02.661Z',
            },
            {
                domainName: 'test',
                serviceName: 'testService',
                type: 'ENTERPRISE_APPLIANCE',
                name: 'pesmacro::randomstringbulabula1010',
                updateTime: '2023-09-27T22:19:00.714Z',
            },
        ];
        let service = 'testService';

        let serviceFullName = `${domain}${serviceDelimiter}${service.toLowerCase()}`;
        const servicesForState = buildServicesForState({
            [serviceFullName]: {
                name: serviceFullName,
                staticInstances: { workLoadData: instanceDetails },
            },
        });
        const { getByTestId } = renderWithRedux(
            <InstanceList
                category={'static'}
                domain={domain}
                _csrf={_csrf}
                instances={instanceDetails}
                service={service}
            />,
            getStateWithServices(servicesForState)
        );
        const instanceList = getByTestId('instancelist');

        expect(screen.getByPlaceholderText('Search')).toBeInTheDocument();
        fireEvent.change(screen.getByPlaceholderText('Search'), {
            target: { value: '10' },
        });

        expect(instanceList).toMatchSnapshot();
    });

    it('should render for dynamic', () => {
        let domain = 'athenz';
        let service = 'testService';
        let _csrf = '_csrfToken';
        let instanceDetails = [
            {
                domainName: null,
                serviceName: null,
                uuid: 'zms3',
                ipAddresses: ['74.6.35.54'],
                hostname: 'NA',
                provider: 'sys.openstack.openstack-classic',
                updateTime: '2021-04-09T19:32:17.000Z',
                certExpiryTime: '1970-01-01T00:00:00.000z',
            },
        ];

        let serviceFullName = `${domain}${serviceDelimiter}${service.toLowerCase()}`;
        const servicesForState = buildServicesForState({
            [serviceFullName]: {
                name: serviceFullName,
                dynamicInstances: { workLoadData: instanceDetails },
            },
        });
        const { getByTestId } = renderWithRedux(
            <InstanceList
                category={'dynamic'}
                domain={domain}
                _csrf={_csrf}
                instances={instanceDetails}
                service={service}
            />,
            getStateWithServices(servicesForState)
        );
        const instanceList = getByTestId('instancelist');

        expect(screen.getByPlaceholderText('Search')).toBeInTheDocument();
        fireEvent.change(screen.getByPlaceholderText('Select an option'), {
            target: { value: 'Instance' },
        });

        fireEvent.change(screen.getByPlaceholderText('Search'), {
            target: { value: '74.6.35.54' },
        });

        expect(instanceList).toMatchSnapshot();
    });
});
