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
import { colors } from '../denali/styles';
import Icon from '../denali/icons/Icon';
import Button from '../denali/Button';
import Color from '../denali/Color';
import RequestUtils from '../utils/RequestUtils';
import {
    selectAllProviders,
    selectProvider,
} from '../../redux/selectors/services';
import { allowProviderTemplate } from '../../redux/thunks/services';
import { connect } from 'react-redux';

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
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    text-align: left;
    padding: 5px 0 5px 15px;
    word-break: break-all;
    border-right: none;
`;

const TableHeadStyledError = styled.th`
    padding-bottom: 5px;
    padding: 5px 0 5px 15px;
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

const ErrorTd = styled.td`
    text-align: left;
    padding: 5px 0 5px 15px;
    vertical-align: middle;
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

class ProviderTable extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            providerWithError: null,
            errorMessage: null,
        };
    }

    onAllow(provider) {
        this.props
            .allowProviderTemplate(
                this.props.domain,
                this.props.service,
                provider,
                this.props._csrf
            )
            .then((data) => {
                this.setState({ providerWithError: '' });
            })
            .catch((err) => {
                this.setState({
                    providerWithError: provider,
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    render() {
        let providerContent = [];
        providerContent = this.props.allProviders.map((provider) => {
            return (
                <tr key={provider.id}>
                    <ProviderTd>{provider.name}</ProviderTd>
                    <AllowTd colSpan={5}>
                        {this.props.provider[provider.id] === 'allow' ? (
                            <AllowDiv>
                                <Icon
                                    icon={'checkmark'}
                                    color={colors.black}
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </AllowDiv>
                        ) : (
                            <Button
                                onClick={this.onAllow.bind(this, provider.id)}
                            >
                                Allow
                            </Button>
                        )}
                    </AllowTd>
                    <ErrorTd>
                        <Color name={'red600'}>
                            {provider.id === this.state.providerWithError
                                ? this.state.errorMessage
                                : ''}
                        </Color>
                    </ErrorTd>
                </tr>
            );
        });

        return (
            <TdStyled
                colSpan={8}
                color={this.props.color}
                data-testid='provider-table'
            >
                <ProvideTable>
                    <TheadStyled>
                        <tr>
                            <TableHeadStyled>Provider</TableHeadStyled>
                            <TableHeadStyledRight>Status</TableHeadStyledRight>
                            {this.state.errorMessage ? (
                                <TableHeadStyledError></TableHeadStyledError>
                            ) : (
                                ''
                            )}
                        </tr>
                    </TheadStyled>
                    <tbody>{providerContent}</tbody>
                </ProvideTable>
            </TdStyled>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        provider: selectProvider(state, props.domain, props.service),
        allProviders: selectAllProviders(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    allowProviderTemplate: (domainName, serviceName, providerId, _csrf) =>
        dispatch(
            allowProviderTemplate(domainName, serviceName, providerId, _csrf)
        ),
});

export default connect(mapStateToProps, mapDispatchToProps)(ProviderTable);
