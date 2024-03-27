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
import Button from '../denali/Button';
import Modal from '../denali/Modal';
import Color from '../denali/Color';
import InputDropdown from '../denali/InputDropdown';
import RequestUtils from '../utils/RequestUtils';

const StyledModal = styled(Modal)`
    width: 600px;
`;

const ButtonDiv = styled.div`
    text-align: center;
`;

const ModifiedButton = styled(Button)`
    min-width: 8.5em;
    min-height: 1em;
`;

const ContentDiv = styled.div`
    flex: 1 1;
    margin-right: 10px;
`;

const StyledInputDropDown = styled(InputDropdown)`
    width: 500px;
    padding: 0px 0px 20px 0px;
`;

export default class AddEnvironmentModal extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.onSubmit = this.onSubmit.bind(this);
        this.inputDropdownChanged = this.inputDropdownChanged.bind(this);

        this.state = {
            environmentName: this.props.environmentName,
            errorMessage: this.props.errorMessage,
        };
    }

    inputDropdownChanged(evt) {
        let value = evt ? evt.value : '';
        this.setState({
            environmentName: value,
            errorMessage: '',
        });
    }

    onSubmit() {
        if (
            !this.state.environmentName ||
            this.state.environmentName.trim() === ''
        ) {
            this.setState({
                errorMessage: 'Environment is required for Update.',
            });
            return;
        }
        let meta = {
            environment: this.props.environment,
        };
        meta.environment = this.state.environmentName;
        let domainName = this.props.domain;
        let auditMsg = `Updating Environment for domain ${this.props.domain}`;
        let csrf = this.props.csrf;
        this.api
            .putMeta(domainName, domainName, meta, auditMsg, csrf, 'domain')
            .then(() => {
                this.setState({
                    showModal: false,
                });
                this.props.onEnvironmentUpdateSuccessCb(
                    this.state.environmentName
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    render() {
        return (
            <StyledModal
                isOpen={this.props.isOpen}
                noanim={true}
                onClose={this.props.cancel}
                title={'Select ' + this.props.title}
            >
                {this.state.errorMessage && (
                    <Color name={'red600'}>{this.state.errorMessage}</Color>
                )}
                <ContentDiv>
                    <StyledInputDropDown
                        fluid
                        name='input-drop'
                        options={this.props.dropDownOptions}
                        placeholder={'Select ' + this.props.title}
                        filterable
                        onChange={this.inputDropdownChanged}
                        valuesWidth='500px'
                        defaultSelectedValue={this.state.environmentName}
                    />
                </ContentDiv>
                {this.props.errorMessage && (
                    <Color name={'red600'}>{this.props.errorMessage}</Color>
                )}
                <ButtonDiv>
                    <ModifiedButton
                        primary
                        onClick={this.onSubmit}
                        data-testid={this.props.title + '-modal-update'}
                    >
                        Submit
                    </ModifiedButton>
                    <ModifiedButton
                        secondary
                        onClick={this.props.cancel}
                        data-testid={this.props.title + '-modal-cancel'}
                    >
                        Cancel
                    </ModifiedButton>
                </ButtonDiv>
            </StyledModal>
        );
    }
}
