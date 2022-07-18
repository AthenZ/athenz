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

import { Handle } from 'react-flow-renderer';
import styled from '@emotion/styled';
import { SERVICE_NAME_LABEL } from '../constants/constants';
import PrimaryServiceDetails from './PrimaryServiceDetails';

const StyledOuterDiv = styled.div`
    display: flex;
    flex-direction: column;
    background: rgb(255, 255, 255);
    border: 1px solid rgb(213, 213, 213);
    border-radius: 4px;
    min-width: 300px;
`;

const StyledLabelNameDiv = styled.div`
    display: flex;
    flex-direction: column;
    padding: 10px;
`;

const StyledServiceNameDiv = styled.div`
    color: rgb(0, 109, 251);
    font-size: small;
`;

const StyledLabelDiv = styled.div`
    font-size: x-small;
    color: rgb(96, 96, 96);
    text-transform: uppercase;
`;

const StyledIODiv = styled.div`
    position: relative;
    padding: 8px 16px;
    flex-grow: 1;
`;

export default class CustomPrimaryServiceNode extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.state = {
            data: props.data,
        };
    }

    shouldComponentUpdate(nextProps, nextState, nextContext) {
        if (_.isEqual(nextProps.data, this.state.data)) {
            return false;
        }
        return true;
    }

    componentDidUpdate(prevProps, prevState, snapshot) {
        if (prevState.data !== this.props.data) {
            this.setState({
                data: this.props.data,
            });
        }
    }

    render() {
        let contentHandle = this.state.data.data.map((rule) => {
            if (rule['category'] === 'inbound') {
                return (
                    <StyledIODiv key={'i-' + rule['assertionIdx']}>
                        <PrimaryServiceDetails
                            data={rule}
                            domain={this.state.data['domain']}
                            api={this.state.data['api']}
                            _csrf={this.state.data['_csrf']}
                            onUpdateSuccess={this.state.data.onSubmit}
                        />
                        <Handle
                            type='target'
                            position='left'
                            id={rule['assertionIdx'] + '_' + rule['category']}
                        />
                    </StyledIODiv>
                );
            }

            if (rule['category'] === 'outbound') {
                return (
                    <StyledIODiv key={'i-' + rule['assertionIdx']}>
                        <PrimaryServiceDetails
                            data={rule}
                            domain={this.state.data['domain']}
                            api={this.state.data['api']}
                            _csrf={this.state.data['_csrf']}
                            onUpdateSuccess={this.state.data.onSubmit}
                        />
                        <Handle
                            type='source'
                            position='right'
                            id={rule['assertionIdx'] + '_' + rule['category']}
                        />
                    </StyledIODiv>
                );
            }
        });

        return (
            <StyledOuterDiv>
                <StyledLabelNameDiv>
                    <StyledLabelDiv>{SERVICE_NAME_LABEL}</StyledLabelDiv>
                    <StyledServiceNameDiv>
                        {this.state.data.name}
                    </StyledServiceNameDiv>
                </StyledLabelNameDiv>
                {contentHandle}
            </StyledOuterDiv>
        );
    }
}
