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
import DeleteModal from '../modal/DeleteModal';
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import Menu from '../denali/Menu/Menu';
import RequestUtils from '../utils/RequestUtils';
import { deleteInstance } from '../../redux/thunks/services';
import { connect } from 'react-redux';
import {
    SERVICE_TYPE_DYNAMIC,
    SERVICE_TYPE_STATIC,
} from '../constants/constants';

const TDStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
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

const DivIpStyled = styled.div`
    display: flex;
    flex-direction: column;
    padding-bottom: 10px;
`;

const MenuDiv = styled.div`
    padding: 5px 10px;
    background-color: black;
    color: white;
    font-size: 12px;
`;

class InstanceRow extends React.Component {
    constructor(props) {
        super(props);
        this.onSubmitDelete = this.onSubmitDelete.bind(this);
        this.onClickDeleteCancel = this.onClickDeleteCancel.bind(this);
        this.saveJustification = this.saveJustification.bind(this);
        this.state = {
            key:
                this.props.category === SERVICE_TYPE_DYNAMIC
                    ? this.props.details.hostname + this.props.details.uuid
                    : this.props.details.name,
            showDelete: false,
            deleteJustification: '',
            errorMessage: null,
        };
        this.localDate = new DateUtils();
    }

    saveJustification(val) {
        this.setState({ deleteJustification: val });
    }

    onClickDelete() {
        this.setState({
            showDelete: true,
        });
    }

    onSubmitDelete(provider, domain, service, instanceId) {
        if (
            this.props.justificationRequired &&
            (this.state.deleteJustification === undefined ||
                this.state.deleteJustification.trim() === '')
        ) {
            this.setState({
                errorMessage: 'Justification is required to delete an instance',
            });
            return;
        }

        this.props
            .deleteInstance(
                this.props.category,
                provider,
                domain,
                service,
                instanceId,
                this.state.deleteJustification
                    ? this.state.deleteJustification
                    : 'deleted using Athenz UI',
                this.props._csrf
            )
            .then(() => {
                this.setState({
                    showDelete: false,
                    deleteJustification: null,
                    errorMessage: null,
                });
                this.props.onUpdateSuccess(
                    this.props.category === SERVICE_TYPE_DYNAMIC
                        ? `Successfully deleted instance for host ${this.props.details.hostname}`
                        : `Successfully deleted instance ${this.props.details.name}`
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    onClickDeleteCancel() {
        this.setState({
            showDelete: false,
            errorMessage: null,
        });
    }

    render() {
        let rows = [];
        let left = 'left';
        let center = 'center';
        let color = this.props.color;
        let details = this.props.details;
        let ipAddresses = details.ipAddresses
            ? []
            : details.name
            ? details.name.toUpperCase()
            : ['N/A'];
        let clickDelete = this.onClickDelete.bind(this);
        let isDynamic = this.props.category === SERVICE_TYPE_DYNAMIC;
        let isStatic = this.props.category === SERVICE_TYPE_STATIC;

        let submitDelete = this.onSubmitDelete.bind(
            this,
            details.provider,
            this.props.domain,
            this.props.service,
            isDynamic ? details.uuid : details.name
        );
        let clickDeleteCancel = this.onClickDeleteCancel.bind(this);

        details.ipAddresses?.forEach((ipAddress, idx) => {
            ipAddresses.push(
                <DivIpStyled key={this.state.key + ipAddress}>
                    {ipAddress}
                </DivIpStyled>
            );
        });
        rows.push(
            <TrStyled key={this.state.key} data-testid='instance-row'>
                <TDStyled color={color} align={left}>
                    {ipAddresses}
                </TDStyled>
                {isDynamic && (
                    <TDStyled color={color} align={left}>
                        {details.hostname}
                    </TDStyled>
                )}
                {isDynamic && (
                    <TDStyled color={color} align={left}>
                        {details.provider}
                    </TDStyled>
                )}
                {isDynamic && (
                    <TDStyled color={color} align={left}>
                        {details.uuid}
                    </TDStyled>
                )}
                {isDynamic && (
                    <TDStyled color={color} align={left}>
                        {this.localDate.getLocalDate(
                            details.certExpiryTime,
                            this.props.timeZone,
                            this.props.timeZone
                        )}
                    </TDStyled>
                )}
                {isDynamic && (
                    <TDStyled color={color} align={left}>
                        {this.localDate.getLocalDate(
                            details.updateTime,
                            this.props.timeZone,
                            this.props.timeZone
                        )}
                    </TDStyled>
                )}
                {isStatic && (
                    <TDStyled color={color} align={left}>
                        {details.type}
                    </TDStyled>
                )}
                {isStatic && (
                    <TDStyled color={color} align={left}>
                        {this.localDate.getLocalDate(
                            details.updateTime,
                            this.props.timeZone,
                            this.props.timeZone
                        )}
                    </TDStyled>
                )}
                <TDStyled color={color} align={center}>
                    <Menu
                        placement='bottom-start'
                        trigger={
                            <span>
                                <Icon
                                    icon={'trash'}
                                    onClick={clickDelete}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </span>
                        }
                    >
                        <MenuDiv>Delete</MenuDiv>
                    </Menu>
                </TDStyled>
            </TrStyled>
        );

        if (this.state.showDelete) {
            rows.push(
                <DeleteModal
                    name={
                        isDynamic
                            ? this.props.details.hostname
                            : this.props.details.name
                    }
                    isOpen={this.state.showDelete}
                    cancel={clickDeleteCancel}
                    submit={submitDelete}
                    key={
                        isDynamic
                            ? this.props.details.hostname +
                              this.props.details.uuid +
                              '-delete'
                            : this.props.details.name + '-delete'
                    }
                    showJustification={this.props.justificationRequired}
                    message={
                        isDynamic
                            ? 'Are you sure you want to permanently delete the host record '
                            : 'Are you sure you want to permanently delete the instance record '
                    }
                    onJustification={this.saveJustification}
                    errorMessage={this.state.errorMessage}
                />
            );
        }

        return rows;
    }
}
const mapDispatchToProps = (dispatch) => ({
    deleteInstance: (
        category,
        provider,
        domain,
        service,
        uuid,
        deleteJustification,
        _csrf
    ) =>
        dispatch(
            deleteInstance(
                category,
                provider,
                domain,
                service,
                uuid,
                deleteJustification,
                _csrf
            )
        ),
});

export default connect(null, mapDispatchToProps)(withRouter(InstanceRow));
