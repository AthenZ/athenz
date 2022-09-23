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
import ServiceKeyUtils from '../utils/ServiceKeyUtils';
import Color from '../denali/Color';
import Alert from '../denali/Alert';
import DeleteModal from '../modal/DeleteModal';
import { MODAL_TIME_OUT } from '../constants/constants';
import RequestUtils from '../utils/RequestUtils';
import { css, keyframes } from '@emotion/react';
import { deleteKey } from '../../redux/thunks/services';
import { connect } from 'react-redux';
import {
    selectServiceDescription,
    selectServicePublicKeys,
} from '../../redux/selectors/services';
import AddKey from './AddKey';

const HeaderDiv = styled.div`
    display: flex;
    justify-content: space-between;
    border-bottom: 2px solid ${colors.grey500};
    flex-flow: row nowrap;
`;

const ContentDetail = styled.div`
    margin-bottom: 20px;
`;

const DetailDiv = styled.div`
    font-size: 16px;
    font-weight: 600;
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

const DescriptionDiv = styled.div`
    align-items: center;
    display: flex;
    flex-flow: row wrap;
    justify-content: flex-start;
`;

const DescriptionSpan = styled.span`
    width: 150px;
    font-weight: 400;
    padding: 10px 0 10px 0;
`;

const PublicKeyDiv = styled.div`
    border-bottom: 1px solid ${colors.grey500};
    display: flex;
    flex-flow: row wrap;
    padding: 15px 0;
    ${(props) =>
        props.isSuccess === true &&
        css`
            animation: ${colorTransition} 3s ease;
        `}
`;

const KeyLabelDiv = styled.div`
    color: ${colors.black};
    font-weight: 600;
    flex: 1 1 100%;
    margin-bottom: 5px;
`;

const KeyContentDiv = styled.div`
    color: ${colors.black};
    flex: 1 1;
    margin-left: 15px;
    white-space: pre-line;
    word-break: break-all;
    font-family: 'Droid Sans Mono', monospace;
`;

const IconDiv = styled.div`
    flex: 0 0 120px;
    text-align: center;
`;

const StyledAnchor = styled.a`
    color: #3570f4;
    text-decoration: none;
    cursor: pointer;
`;

const colorTransition = keyframes`
        0% {
            background-color: rgba(21, 192, 70, 0.20);
        }
        100% {
            background-color: transparent;
        }
`;

class PublicKeyTable extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            // desc: this.props.serviceDetails.description,
            // pubKeys: this.props.serviceDetails.publicKeys,
            // errorMessage: this.props.serviceDetails.errorMessage,
        };
        this.toggleAddKey = this.toggleAddKey.bind(this);
        this.reloadKeys = this.reloadKeys.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.onSubmitDeleteKey = this.onSubmitDeleteKey.bind(this);
        this.onCancelDeleteKey = this.onCancelDeleteKey.bind(this);
    }

    toggleAddKey() {
        this.setState({
            showAddKey: !this.state.showAddKey,
        });
    }

    reloadKeys(successMessage, showSuccess) {
        this.setState({
            showAddKey: null,
            successMessage,
            showSuccess,
            showDelete: false,
        });
        // this is to close the success alert
        setTimeout(
            () =>
                this.setState({
                    showSuccess: false,
                    successMessage: '',
                }),
            MODAL_TIME_OUT
        );
    }

    closeModal() {
        this.setState({ showSuccess: false });
    }

    onClickDeleteKey(keyId) {
        this.setState({
            showDelete: true,
            deleteKeyId: keyId,
            errorMessage: null,
        });
    }

    onSubmitDeleteKey() {
        this.props
            .deleteKey(
                this.props.domain,
                this.props.service,
                this.state.deleteKeyId,
                this.props._csrf
            )
            .then(() => {
                this.reloadKeys(
                    `Successfully deleted key id ${this.state.deleteKeyId} from service ${this.props.service}`,
                    true
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    onCancelDeleteKey() {
        this.setState({
            showDelete: false,
            deleteKeyId: null,
        });
    }

    render() {
        if (this.state.errorMessage) {
            return (
                <TdStyled colSpan={7} color={this.props.color}>
                    <Color name={'red600'}>Failed to fetch PublicKeys.</Color>
                </TdStyled>
            );
        }

        let description = null;
        let publicKeys = [];

        if (this.props.desc) {
            description = (
                <DescriptionDiv>
                    <DescriptionSpan>Description</DescriptionSpan>
                    <span>{this.props.desc}</span>
                </DescriptionDiv>
            );
        }
        const keys = this.props.pubKeys;
        keys.map((key) => {
            let onClickDeleteKey = this.onClickDeleteKey.bind(this, key.id);
            let newKey =
                key.id + '-' + this.props.service === this.state.successMessage;
            const formattedKey = ServiceKeyUtils.y64Decode(key.key);
            publicKeys.push(
                <PublicKeyDiv
                    key={this.props.service + key.id}
                    isSuccess={newKey}
                >
                    <KeyLabelDiv>Public Key Version: {key.id}</KeyLabelDiv>
                    <KeyContentDiv>{formattedKey}</KeyContentDiv>
                    <IconDiv>
                        <Icon
                            icon={'trash'}
                            onClick={onClickDeleteKey}
                            color={colors.icons}
                            isLink
                            size={'1.25em'}
                            verticalAlign={'text-bottom'}
                        />
                    </IconDiv>
                </PublicKeyDiv>
            );
        });

        let addKey = this.state.showAddKey ? (
            <AddKey
                showAddKey={this.state.showAddKey}
                cancel={this.toggleAddKey}
                onSubmit={this.reloadKeys}
                domain={this.props.domain}
                service={this.props.service}
                _csrf={this.props._csrf}
            />
        ) : (
            ''
        );

        return (
            <TdStyled
                colSpan={7}
                color={this.props.color}
                data-testid='public-key-table'
            >
                <HeaderDiv>
                    <DetailDiv>Details</DetailDiv>
                </HeaderDiv>
                <ContentDetail>{description}</ContentDetail>
                <HeaderDiv>
                    <DetailDiv>Public keys ({publicKeys.length})</DetailDiv>
                    <StyledAnchor onClick={this.toggleAddKey}>
                        Add Key
                    </StyledAnchor>
                </HeaderDiv>
                {addKey}
                <ContentDetail>{publicKeys}</ContentDetail>
                {this.state.showSuccess ? (
                    <Alert
                        isOpen={this.state.showSuccess}
                        title={this.state.successMessage}
                        onClose={this.closeModal}
                        type='success'
                    />
                ) : null}
                {this.state.showDelete ? (
                    <DeleteModal
                        name={this.state.deleteKeyId}
                        isOpen={this.state.showDelete}
                        cancel={this.onCancelDeleteKey}
                        submit={this.onSubmitDeleteKey}
                        errorMessage={this.state.errorMessage}
                        message={
                            'Are you sure you want to permanently delete the key id '
                        }
                    />
                ) : null}
            </TdStyled>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        pubKeys: selectServicePublicKeys(state, props.domain, props.service),
        desc: selectServiceDescription(state, props.domain, props.service),
    };
};

const mapDispatchToProps = (dispatch) => ({
    deleteKey: (domainName, serviceName, deleteKeyId, _csrf) =>
        dispatch(deleteKey(domainName, serviceName, deleteKeyId, _csrf)),
});

export default connect(mapStateToProps, mapDispatchToProps)(PublicKeyTable);
