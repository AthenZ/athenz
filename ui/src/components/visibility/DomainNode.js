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
import { DOMAIN_NAME_LABEL } from '../constants/constants';
import { Handle } from 'react-flow-renderer';

const StyledDiv = styled.div`
    display: flex;
    flex-direction: column;
    background: rgb(255, 255, 255);
    border: 1px solid rgb(213, 213, 213);
    border-radius: 4px;
`;

const StyledLabelNameDiv = styled.div`
    display: flex;
    flex-direction: column;
    padding: 10px;
`;

const StyledServiceNameDiv = styled.div`
    color: #303030;
    font-size: small;
`;

const StyledLabelDiv = styled.div`
    font-size: x-small;
    color: rgb(96, 96, 96);
`;

export default class DomainNode extends React.Component {
    constructor(props) {
        super(props);
    }

    shouldComponentUpdate(nextProps, nextState, nextContext) {
        if (_.isEqual(nextProps.data, this.props.data)) {
            return false;
        }
        return true;
    }

    render() {
        const { data } = this.props;

        let label = DOMAIN_NAME_LABEL;

        let handles = [];
        let numHandles = data['data'].length;
        for (let i = 0; i < numHandles; i++) {
            let handle =
                data['category'] == 'inbound' ? (
                    <div key={'i-inbound-handle'}>
                        <Handle
                            type='target'
                            position={data['direction']}
                            id={'inbound-handle' + i}
                        />
                    </div>
                ) : (
                    <div key={'i-outbound-handle'}>
                        <Handle
                            type='source'
                            position={data['direction']}
                            id={'outbound-handle' + i}
                        />
                    </div>
                );
            handles.push(handle);
        }

        return (
            <StyledDiv category={data['category']}>
                <StyledLabelNameDiv>
                    <StyledLabelDiv>{label}</StyledLabelDiv>
                    <StyledServiceNameDiv>{data.domain}</StyledServiceNameDiv>
                </StyledLabelNameDiv>
                {handles}
            </StyledDiv>
        );
    }
}
