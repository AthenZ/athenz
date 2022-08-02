/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */
import React from 'react';
import VisibilityList from '../../../components/visibility/VisibilityList';
import {
    getStateWithServiceDependencies,
    buildServiceDependencies,
    renderWithRedux,
} from '../../../tests_utils/ComponentsTestUtils';

describe('VisibilityList', () => {
    it('should render', () => {
        let domain = 'domain';
        let serviceDependencies = [];
        let dependency1 = {
            service: 'somedomain.some_provider_service',
            resourceGroups: [
                'some_provider_service.tenant.home.someuser.res_group.test_res_grp1.writers',
                'some_provider_service.tenant.home.someuser.res_group.test_res_grp1.readers',
                'some_provider_service.tenant.home.someuser.res_group.other_group.writers',
            ],
        };
        let dependency2 = {
            service: 'somedomain.other_provider_service',
        };

        serviceDependencies.push(dependency1);
        serviceDependencies.push(dependency2);
        const { getByTestId } = renderWithRedux(
            <VisibilityList key={'dependencyVisibilityList'} domain={domain} />,
            getStateWithServiceDependencies(
                buildServiceDependencies(serviceDependencies)
            )
        );
        const visibilitySection = getByTestId('visibilitySection');

        expect(visibilitySection).toMatchSnapshot();
    });
});
