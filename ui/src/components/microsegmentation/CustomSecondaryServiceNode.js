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
    DESTINATION_NAME_LABEL,
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
    color: rgb(0, 109, 251);
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

const PortLabelDiv = styled.div`
    font-size: x-small;
    color: rgb(96, 96, 96);
    text-transform: uppercase;
`;

const PortDiv = styled.div`
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

export default class CustomSecondaryServiceNode extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
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
        let label;
        if (data['category'] === 'inbound') {
            label = DESTINATION_NAME_LABEL;
            contentHandle = (
                <StyledContentHandleDiv key={'i-' + data['assertionIdx']}>
                    <PortLabelDiv>{'Destination Port(s)'}</PortLabelDiv>
                    <PortDiv>{data['source_port']}</PortDiv>
                    <StyledLeftHandle
                        type='target'
                        position='left'
                        id='outbound'
                    />
                </StyledContentHandleDiv>
            );
        } else if (data['category'] === 'outbound') {
            label = SOURCE_NAME_LABEL;
            contentHandle = (
                <StyledContentHandleDiv key={'i-' + data['assertionIdx']}>
                    <PortLabelDiv>{'Source Port(s)'}</PortLabelDiv>
                    <PortDiv>{data['source_port']}</PortDiv>
                    <StyledRightHandle
                        type='source'
                        position='right'
                        id='inbound'
                    />
                </StyledContentHandleDiv>
            );
        }

        return (
            <StyledDiv category={data['category']}>
                <StyledLabelNameDiv>
                    <StyledLabelDiv>{label}</StyledLabelDiv>
                    <StyledServiceNameDiv>{data.name}</StyledServiceNameDiv>
                </StyledLabelNameDiv>
                {contentHandle}
            </StyledDiv>
        );
    }
}
