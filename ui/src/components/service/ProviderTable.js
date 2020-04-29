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
import { colors } from '../denali/styles';
import Icon from '../denali/icons/Icon';
import Button from '../denali/Button';
import Color from '../denali/Color';
import RequestUtils from '../utils/RequestUtils';

const ProvideTable = styled.table`
    display: table;
    border-collapse: separate;
    border-spacing: 2px;
    border-color: ${colors.grey600};
`;

const TableHeadStyled = styled.th`
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    font-size: 0.8rem;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    text-align: left;
    padding: 5px 0 5px 15px;
    word-break: break-all;
`;

const TableHeadStyledRight = styled.th`
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    font-size: 0.8rem;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    text-align: left;
    padding: 5px 0 5px 15px;
    word-break: break-all;
    border-right: none;
`;

const TdStyled = styled.td`
    padding: 20px;
    text-align: left;
    vertical-align: middle;
    word-break: break-all;
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    display: table-cell;
    background-color: ${(props) => props.color};
`;

const TheadStyled = styled.thead`
    display: table-header-group;
`;

const ProviderTd = styled.td`
    text-align: left;
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
`;

const AllowTd = styled.td`
    text-align: left;
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
    border-right: none;
`;

const AllowDiv = styled.div`
    margin-left: 30px;
`;

export default class ProviderTable extends React.Component {
    constructor(props) {
        super(props);
        this.api = this.props.api;
        this.state = {
            provider: this.props.provider.provider,
            errorMessage: this.props.provider.errorMessage,
        };
    }

    onAllow(provider) {
        this.api
            .allowProviderTemplate(
                this.props.domain,
                this.props.service,
                provider,
                this.props._csrf
            )
            .then(() => {
                let currentProvider = this.state.provider;
                currentProvider[provider] = 'allow';
                this.setState({ provider: currentProvider });
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    render() {
        let providerContent = [];
        if (this.state.errorMessage) {
            return (
                <TdStyled colSpan={7} color={this.props.color}>
                    <Color name={'red600'}>
                        Failed to fetch template details.
                    </Color>
                </TdStyled>
            );
        } else {
            providerContent = this.props.allProviders.map((provider) => {
                if (this.state.provider[provider.id] === 'allow') {
                    return (
                        <tr key={provider.id}>
                            <ProviderTd>{provider.name}</ProviderTd>
                            <AllowTd colSpan={5}>
                                <AllowDiv>
                                    <Icon
                                        icon={'checkmark'}
                                        color={colors.black}
                                        size={'1.25em'}
                                        verticalAlign={'text-bottom'}
                                    />
                                </AllowDiv>
                            </AllowTd>
                        </tr>
                    );
                } else if (this.state.provider[provider.id] === 'not') {
                    let onAllow = this.onAllow.bind(this, provider.id);
                    return (
                        <tr key={provider.id}>
                            <ProviderTd>{provider.name}</ProviderTd>
                            <AllowTd colSpan={5}>
                                <Button onClick={onAllow}>Allow</Button>
                            </AllowTd>
                        </tr>
                    );
                }
            });
        }

        return (
            <TdStyled
                colSpan={7}
                color={this.props.color}
                data-testid='provider-table'
            >
                {this.state.errorMessage && (
                    <div>
                        <Color name={'red600'}>{this.state.errorMessage}</Color>
                    </div>
                )}
                <ProvideTable>
                    <TheadStyled>
                        <tr>
                            <TableHeadStyled>Provider</TableHeadStyled>
                            <TableHeadStyledRight>Status</TableHeadStyledRight>
                        </tr>
                    </TheadStyled>
                    <tbody>{providerContent}</tbody>
                </ProvideTable>
            </TdStyled>
        );
    }
}
