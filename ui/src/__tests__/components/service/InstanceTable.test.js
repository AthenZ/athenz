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
import InstanceTable from '../../../components/service/InstanceTable';
import API from '../../../api';

describe('InstanceTable', () => {
    it('should render', () => {
        let domain = "test.domain";
        let _csrf = '_csrfToken';
        let api = API();
        let instances = [{
            "domainName": null,
            "serviceName": null,
            "uuid": "host1",
            "ipAddresses": [
                "host1"
            ],
            "provider": "aws",
            "updateTime": "2021-03-28T21:38:27.070Z"
        }];
        const { getByTestId } = render(
            <InstanceTable
                instances={instances}
                api={api}
                domain={domain}
                _csrf={_csrf}
                category={'dynamic'}
            />
        );
        const instanceTable = getByTestId('instancetable');

        expect(instanceTable).toMatchSnapshot();
    });
});
