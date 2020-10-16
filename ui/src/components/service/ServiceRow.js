/*
 * Copyright 2020 Verizon Media
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
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import PublicKeyTable from '../service/PublicKeyTable';
import ProviderTable from '../service/ProviderTable';
import DateUtils from '../utils/DateUtils';
import RequestUtils from '../utils/RequestUtils';
import { keyframes, css } from '@emotion/core';

const TdStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
`;

const colorTransition = keyframes`
        0% {
            background-color: rgba(21, 192, 70, 0.20);
        }
        100% {
            background-color: transparent;
        }
`;

const TrStyled = styled.tr`
    ${(props) =>
        props.isSuccess === true &&
        css`
            animation: ${colorTransition} 3s ease;
        `}
`;

export default class ServiceRow extends React.Component {
    constructor(props) {
        super(props);
        this.api = this.props.api;
        this.togglePublicKeys = this.togglePublicKeys.bind(this);
        this.toggleProviders = this.toggleProviders.bind(this);
        this.state = {
            provider: null,
        };
        this.localDate = new DateUtils();
    }

    togglePublicKeys() {
        if (this.state.serviceDetails) {
            this.setState({
                serviceDetails: null,
            });
        } else {
            this.api
                .getService(this.props.domainName, this.props.serviceName)
                .then((detail) => {
                    this.setState({
                        serviceDetails: detail,
                    });
                })
                .catch((err) => {
                    this.setState({
                        serviceDetails: {
                            errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                        },
                    });
                });
        }
    }

    toggleProviders() {
        if (this.state.provider) {
            this.setState({
                provider: null,
            });
        } else {
            this.api
                .getProvider(this.props.domainName, this.props.serviceName)
                .then((data) => {
                    this.setState({
                        provider: { provider: data.provider },
                        allProviders: data.allProviders,
                    });
                })
                .catch((err) => {
                    this.setState({
                        provider: {
                            errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                        },
                    });
                });
        }
    }

    render() {
        const left = 'left';
        const center = 'center';
        const color = this.props.color;
        let row = [];
        const serviceName = this.props.serviceName;
        const newService = this.props.newService;
        row.push(
            <TrStyled
                key={serviceName}
                data-testid='service-row'
                isSuccess={newService}
            >
                <TdStyled color={color} align={left}>
                    {serviceName}
                </TdStyled>
                <TdStyled color={color} align={left}>
                    {this.localDate.getLocalDate(
                        this.props.modified,
                        'UTC',
                        'UTC'
                    )}
                </TdStyled>
                <TdStyled color={color} align={center}>
                    <Icon
                        icon={'key'}
                        onClick={this.togglePublicKeys}
                        color={colors.icons}
                        isLink
                        size={'1.25em'}
                        verticalAlign={'text-bottom'}
                    />
                </TdStyled>
                <TdStyled color={color} align={center}>
                    <Icon
                        icon={'cloud'}
                        onClick={this.toggleProviders}
                        color={colors.icons}
                        isLink
                        size={'1.25em'}
                        verticalAlign={'text-bottom'}
                    />
                </TdStyled>
                <TdStyled color={color} align={center}>
                    <Icon
                        icon={'trash'}
                        onClick={this.props.onClickDeleteService}
                        color={colors.icons}
                        isLink
                        size={'1.25em'}
                        verticalAlign={'text-bottom'}
                    />
                </TdStyled>
            </TrStyled>
        );

        if (this.state.serviceDetails) {
            row.push(
                <tr key={this.props.domainName + serviceName}>
                    <PublicKeyTable
                        color={this.props.color}
                        serviceDetails={this.state.serviceDetails}
                        service={serviceName}
                        domain={this.props.domainName}
                        api={this.api}
                        _csrf={this.props._csrf}
                    />
                </tr>
            );
        }

        if (this.state.provider) {
            row.push(
                <tr key={serviceName + this.state.provider}>
                    <ProviderTable
                        color={this.props.color}
                        provider={this.state.provider}
                        api={this.api}
                        _csrf={this.props._csrf}
                        key={serviceName + this.state.provider}
                        allProviders={this.state.allProviders}
                        service={serviceName}
                        domain={this.props.domainName}
                    />
                </tr>
            );
        }
        return row;
    }
}
