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
import DateUtils from '../utils/DateUtils';
import { withRouter } from 'next/router';
import { css, keyframes } from '@emotion/react';

const TDStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
`;

const TrStyled = styled.tr`
    box-sizing: border-box;
    margin-top: 10px;
    box-shadow: 0 1px 4px #d9d9d9;
    border: 1px solid #fff;
    -webkit-border-image: none;
    border-image: none;
    -webkit-border-image: initial;
    border-image: initial;
    padding: 5px 0 5px 15px;
    ${(props) =>
        props.isSuccess &&
        css`
            animation: ${colorTransition} 3s ease;
        `}
`;

const colorTransition = keyframes`
        0% {
            background-color: rgba(21, 192, 70, 0.20);
        }
        100% {
            background-color: transparent;
        }
`;

class InstanceRow extends React.Component {
    constructor(props) {
        super(props);
        this.api = this.props.api;
        this.state = {
            key: this.props.details.uuid + this.props.details.ipAddresses[0],
        };
        this.localDate = new DateUtils();
    }

    render() {
        let rows = [];
        let left = 'left';
        let center = 'center';
        let color = this.props.color;

        let details = this.props.details;
        details.ipAddresses.forEach((ipAddress, idx) => {
            rows.push(
                <TrStyled key={this.state.key + idx} data-testid='instance-row'>
                    <TDStyled color={color} align={left}>
                        {ipAddress}
                    </TDStyled>
                    {this.props.category === 'dynamic' && (
                        <TDStyled color={color} align={left}>
                            {details.hostname}
                        </TDStyled>
                    )}
                    {this.props.category === 'dynamic' && (
                        <TDStyled color={color} align={left}>
                            {details.provider}
                        </TDStyled>
                    )}
                    {this.props.category === 'dynamic' && (
                        <TDStyled color={color} align={left}>
                            {this.localDate.getLocalDate(
                                details.certExpiryTime,
                                'UTC',
                                'UTC'
                            )}
                        </TDStyled>
                    )}
                    {this.props.category === 'dynamic' && (
                        <TDStyled color={color} align={left}>
                            {this.localDate.getLocalDate(
                                details.updateTime,
                                'UTC',
                                'UTC'
                            )}
                        </TDStyled>
                    )}
                    {this.props.category === 'static' && (
                        <TDStyled color={color} align={center}>
                            {'ips'}
                        </TDStyled>
                    )}
                    {this.props.category === 'static' && (
                        <TDStyled color={color} align={center}>
                            {this.localDate.getLocalDate(
                                details.updateTime,
                                'UTC',
                                'UTC'
                            )}
                        </TDStyled>
                    )}
                </TrStyled>
            );
        });

        return rows;
    }
}
export default withRouter(InstanceRow);
