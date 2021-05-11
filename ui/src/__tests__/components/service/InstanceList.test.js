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
import { render, fireEvent, screen } from '@testing-library/react';
import InstanceList from "../../../components/service/InstanceList";
import API from "../../../api";

describe('InstanceList', () => {
    it('should render for static', () => {
        let api = API();
        let domain = 'athenz';
        let _csrf = '_csrfToken';
        let instanceDetails = [];
        let service = 'testService';

        const { getByTestId } = render(
            <InstanceList
                category={'static'}
                api={api}
                domain={domain}
                _csrf={_csrf}
                instances={instanceDetails}
                service={service}
            />);
        const instanceList = getByTestId('instancelist');

        expect(instanceList).toMatchSnapshot();
    });

    it('should render for dynamic', () => {
        let api = API();
        let domain = 'athenz';
        let _csrf = '_csrfToken';
        let instanceDetails = [
            {
                "domainName": null,
                "serviceName": null,
                "uuid": "zms3",
                "ipAddresses": ['74.6.35.54'],
                "hostname": "NA",
                "provider": "sys.openstack.openstack-classic",
                "updateTime": "2021-04-09T19:32:17.000Z",
                "certExpiryTime": "1970-01-01T00:00:00.000z"
            }
        ];
        let service = 'testService';

        const { getByTestId } = render(
            <InstanceList
                category={'dynamic'}
                api={api}
                domain={domain}
                _csrf={_csrf}
                instances={instanceDetails}
                service={service}
            />);
        const instanceList = getByTestId('instancelist');

        expect(
            screen.getByPlaceholderText('Search')
        ).toBeInTheDocument();
        fireEvent.change(
            screen.getByPlaceholderText("Select an option"),
            {
                target: { value: "Instance"},
            }
        );

        fireEvent.change(
            screen.getByPlaceholderText('Search'),
            {
                target: { value: '74.6.35.54' },
            }
        );

        expect(instanceList).toMatchSnapshot();
    });

});
