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
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import DateUtils from '../utils/DateUtils';
import { css, keyframes } from '@emotion/react';
import { withRouter } from 'next/router';
import PublicKeyTable from './PublicKeyTable';
import { selectProvider } from '../../redux/selectors/services';
import { deleteService, getProvider } from '../../redux/thunks/services';
import { connect } from 'react-redux';
import ProviderTable from './ProviderTable';

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

class ServiceRow extends React.Component {
    constructor(props) {
        super(props);
        this.togglePublicKeys = this.togglePublicKeys.bind(this);
        this.toggleProviders = this.toggleProviders.bind(this);
        this.toggleInstances = this.toggleInstances.bind(this);
        this.clickTag = this.clickTag.bind(this);
        this.clickMicrosegmentation = this.clickMicrosegmentation.bind(this);
        this.state = {
            provider: null,
            publicKeys: false,
            providers: false,
        };
        this.localDate = new DateUtils();
    }

    toggleInstances() {
        let domain = this.props.domainName;
        let service = this.props.serviceName;
        this.props.router.push(
            `/domain/${domain}/service/${service}/instance/dynamic`,
            `/domain/${domain}/service/${service}/instance/dynamic`
        );
    }

    clickTag() {
        this.props.router.push(
            `/domain/${this.props.domainName}/service/${this.props.serviceName}/tags`,
            `/domain/${this.props.domainName}/service/${this.props.serviceName}/tags`
        );
    }

    clickMicrosegmentation() {
        this.props.router.push(
            `/domain/${this.props.domainName}/service/${this.props.serviceName}/microsegmentation`,
            `/domain/${this.props.domainName}/service/${this.props.serviceName}/microsegmentation`
        );
    }

    togglePublicKeys() {
        this.setState({
            publicKeys: !this.state.publicKeys,
        });
    }

    toggleProviders() {
        this.props
            .getProvider(this.props.domainName, this.props.serviceName)
            .then(() => {
                this.setState({
                    providers: !this.state.providers,
                });
            });
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
                        this.props.timeZone,
                        this.props.timeZone
                    )}
                </TdStyled>
                {this.props.featureFlag ? (
                    <TdStyled color={color} align={center}>
                        <Icon
                            icon={'data-source'}
                            onClick={this.toggleInstances}
                            color={colors.icons}
                            isLink
                            size={'1.25em'}
                            verticalAlign={'text-bottom'}
                        />
                    </TdStyled>
                ) : null}
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
                        icon={'tag'}
                        onClick={this.clickTag}
                        color={colors.icons}
                        isLink
                        size={'1.25em'}
                        verticalAlign={'text-bottom'}
                    />
                </TdStyled>
                <TdStyled color={color} align={center}>
                    <Icon
                        icon={'list-check'}
                        onClick={this.clickMicrosegmentation}
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

        if (this.state.publicKeys) {
            row.push(
                <tr key={this.props.domainName + serviceName}>
                    <PublicKeyTable
                        color={this.props.color}
                        service={serviceName}
                        domain={this.props.domainName}
                        _csrf={this.props._csrf}
                    />
                </tr>
            );
        }

        if (this.state.providers) {
            row.push(
                <tr key={serviceName + this.state.provider}>
                    <ProviderTable
                        color={this.props.color}
                        provider={this.state.provider}
                        _csrf={this.props._csrf}
                        service={serviceName}
                        domain={this.props.domainName}
                    />
                </tr>
            );
        }
        return row;
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        provider: selectProvider(state, props.domainName, props.serviceName),
    };
};

const mapDispatchToProps = (dispatch) => ({
    deleteService: (serviceName, _csrf, onSuccess, onFail) =>
        dispatch(deleteService(serviceName, _csrf, onSuccess, onFail)),
    getProvider: (domainName, serviceName) =>
        dispatch(getProvider(domainName, serviceName)),
});

export default connect(
    mapStateToProps,
    mapDispatchToProps
)(withRouter(ServiceRow));
