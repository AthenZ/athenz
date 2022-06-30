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
import AuthHistory from './AuthHistory';
import ServiceDependenciesTable from './ServiceDependenciesTable';
import ButtonGroup from '../denali/ButtonGroup';

const VisibilitySectionDiv = styled.div`
    margin: 20px;
`;

const SliderDiv = styled.div`
    vertical-align: middle;
`;

export default class VisibilityList extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            selectedView: 'dependencies',
        };
        this.changeVisibility = this.changeVisibility.bind(this);
    }

    changeVisibility() {
        let selected = this.state.selectedView;
        if (selected == 'dependencies') {
            selected = 'auth';
        } else {
            selected = 'dependencies';
        }
        this.setState({
            selectedView: selected,
            successMessage: '',
        });
    }

    render() {
        const viewButtons = [
            { id: 'dependencies', name: 'dependencies', label: 'Dependencies' },
            { id: 'auth', name: 'auth', label: 'Access History' },
        ];
        return (
            <VisibilitySectionDiv data-testid='visibilitySection'>
                <SliderDiv>
                    <ButtonGroup
                        buttons={viewButtons}
                        selectedName={this.state.selectedView}
                        onClick={this.changeVisibility}
                    />
                </SliderDiv>
                {this.state.selectedView == 'dependencies' ? (
                    <ServiceDependenciesTable
                        key={'dependenciesView'}
                        data-testid='dependenciestable'
                        serviceDependencies={
                            this.props.serviceDependencies || []
                        }
                    />
                ) : (
                    <AuthHistory
                        key={'authHistoryView'}
                        data-testid='authHistoryGraph'
                        data={this.props.authHistory || {}}
                        api={this.props.api}
                        domain={this.props.domain}
                        _csrf={this.props._csrf}
                    />
                )}
            </VisibilitySectionDiv>
        );
    }
}
