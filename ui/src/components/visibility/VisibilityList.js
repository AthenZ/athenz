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
import styled from '@emotion/styled';
import ButtonGroup from '../denali/ButtonGroup';
import ServiceDependenciesTable from './ServiceDependenciesTable';

const VisibilitySectionDiv = styled.div`
    margin: 20px;
`;

export default class VisibilityList extends React.Component {
    render() {
        return (
            <VisibilitySectionDiv data-testid='visibilitySection'>
                <ServiceDependenciesTable
                    key={'dependenciesView'}
                    data-testid='dependenciestable'
                    serviceDependencies={this.props.serviceDependencies || []}
                />
            </VisibilitySectionDiv>
        );
    }
}
