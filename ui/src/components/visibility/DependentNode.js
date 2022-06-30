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
import { css } from '@emotion/react';
import {
    DESTINATION_DOMAIN_LABEL,
    DESTINATION_NAME_LABEL,
    PRINCIPAL_REQUESTING_ACCESS,
    SOURCE_NAME_LABEL,
} from '../constants/constants';

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

const StyledContentHandleDiv = styled.div`
    background: rgb(248, 248, 248);
    border-radius: 3px;
    position: relative;
    padding: 8px 8px;
    flex-grow: 1;
    margin: 0px 10px 10px 10px;
    min-width: 180px;
`;

const TimestampLabelDiv = styled.div`
    font-size: x-small;
    color: rgb(96, 96, 96);
    text-transform: uppercase;
`;

const TimestampDiv = styled.div`
    color: rgb(48, 48, 48);
    font-size: small;
`;

const StyledLeftHandle = styled(Handle)`
    left: -15px;
    margin: auto;
    top: 0%;
`;

const StyledRightHandle = styled(Handle)`
    right: -15px;
    margin: auto;
    top: 0%;
`;

export default class DependentNode extends React.Component {
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
        let contentHandle;
        if (data['category'] === 'inbound') {
            contentHandle = (
                <StyledDiv category={data['category']}>
                    <StyledLabelNameDiv>
                        <StyledLabelDiv>
                            {DESTINATION_DOMAIN_LABEL}
                        </StyledLabelDiv>
                        <StyledServiceNameDiv>
                            {data.uriDomain}
                        </StyledServiceNameDiv>
                    </StyledLabelNameDiv>
                    <StyledLabelNameDiv>
                        <StyledLabelDiv>
                            {PRINCIPAL_REQUESTING_ACCESS}
                        </StyledLabelDiv>
                        <StyledServiceNameDiv>
                            {data.principalDomain + '.' + data.principalName}
                        </StyledServiceNameDiv>
                    </StyledLabelNameDiv>
                    <StyledContentHandleDiv key={'i-' + data['domain']}>
                        <TimestampLabelDiv>
                            {'Last Timestamp'}
                        </TimestampLabelDiv>
                        <TimestampDiv>{data['timestamp']}</TimestampDiv>
                        <StyledLeftHandle
                            type='target'
                            position='left'
                            id='outbound'
                        />
                    </StyledContentHandleDiv>
                </StyledDiv>
            );
        } else if (data['category'] === 'outbound') {
            contentHandle = (
                <StyledDiv category={data['category']}>
                    <StyledLabelNameDiv>
                        <StyledLabelDiv>
                            {PRINCIPAL_REQUESTING_ACCESS}
                        </StyledLabelDiv>
                        <StyledServiceNameDiv>
                            {data.principalDomain + '.' + data.principalName}
                        </StyledServiceNameDiv>
                    </StyledLabelNameDiv>
                    <StyledContentHandleDiv key={'i-' + data['domain']}>
                        <TimestampLabelDiv>
                            {'Last Timestamp'}
                        </TimestampLabelDiv>
                        <TimestampDiv>{data['timestamp']}</TimestampDiv>
                        <StyledRightHandle
                            type='source'
                            position='right'
                            id='inbound'
                        />
                    </StyledContentHandleDiv>
                </StyledDiv>
            );
        }

        return contentHandle;
    }
}
