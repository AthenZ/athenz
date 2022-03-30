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
import ServiceDependency from '../../../components/visibility/ServiceDependency';

describe('ServiceDependency', () => {
    it('should render', () => {
        let dependency1 = {
            service: 'somedomain.some_provider_service',
            resourceGroups: [
                'some_provider_service.tenant.home.someuser.res_group.test_res_grp1.writers',
                'some_provider_service.tenant.home.someuser.res_group.test_res_grp1.readers',
                'some_provider_service.tenant.home.someuser.res_group.other_group.writers',
            ],
        };
        const { getByTestId } = render(
            <ServiceDependency
                key={dependency1.service}
                dependency={dependency1}
            />
        );
        const dependenciestable = getByTestId('dependency-sgroup-table');

        expect(dependenciestable).toMatchSnapshot();
    });
});
