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
import Input from '../denali/Input';
import InputDropdown from '../denali/InputDropdown';
import CheckBox from '../denali/CheckBox';

const StyledModal = styled(Modal)`
    width: 600px;
`;

const MessageDiv = styled.div`
    width: 500px;
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

const ButtonDiv = styled.div`
    text-align: center;
`;

const ModifiedButton = styled(Button)`
    min-width: 8.5em;
    min-height: 1em;
`;

const StyledInput = styled(Input)`
    width: 500px;
    padding: 0px 0px 20px 0px;
`;

const ContentDiv = styled.div`
    flex: 1 1;
    margin-right: 10px;
`;

const StyledInputDropDown = styled(InputDropdown)`
    width: 500px;
    padding: 0px 0px 20px 0px;
`;

const StyledCheckbox = styled.div`
    padding: 0px 0px 20px 0px;
`;

export default class BusinessServiceModal extends React.Component {
    constructor(props) {
        super(props);
        this.onJustification = this.onJustification.bind(this);
        this.businessServiceChanged = this.businessServiceChanged.bind(this);

        // If selected service isn't part of user's business services, add it
        let bServiceName = this.props.businessServiceName;
        let validBServicesUser = props.validBusinessServices.map((x) => x);
        if (bServiceName) {
            let bServiceOnlyId = bServiceName.substring(
                0,
                bServiceName.indexOf(':')
            );
            let bServiceOnlyName = bServiceName.substring(
                bServiceName.indexOf(':') + 1
            );
            var index = validBServicesUser.findIndex(
                (x) => x.value == bServiceOnlyId
            );
            if (index === -1) {
                validBServicesUser.push({
                    value: bServiceOnlyId,
                    name: bServiceOnlyName,
                });
            }
        }

        this.state = {
            validBusinessServices: validBServicesUser,
            onlyAccountValuesChecked: true,
            selectedBservice: bServiceName
                ? bServiceName.substring(0, bServiceName.indexOf(':'))
                : '',
            errorMessage: this.props.errorMessage,
        };
    }

    onJustification(evt) {
        this.props.onJustification(evt.target.value && evt.target.value.trim());
    }
    businessServiceChanged(evt) {
        let value = evt ? evt.value : '';
        if (value) {
            let name = evt ? evt.name : '';
            this.props.onBusinessService(value + ':' + name);
        } else {
            this.props.onBusinessService('');
        }
    }

    render() {
        return (
            <StyledModal
                isOpen={this.props.isOpen}
                noanim={true}
                onClose={this.props.cancel}
                title={'Select Business Service'}
            >
                {this.state.errorMessage && (
                    <Color name={'red600'}>{this.state.errorMessage}</Color>
                )}
                <StyledCheckbox>
                    <CheckBox
                        checked={this.state.onlyAccountValuesChecked}
                        name='checkbox-show-all-bservices'
                        id='checkbox-show-all-bservices'
                        label='Only show business services associated with my account'
                        onChange={() => {
                            let newChecked =
                                !this.state.onlyAccountValuesChecked;
                            let newValidBusinessServices = [];
                            if (newChecked) {
                                newValidBusinessServices =
                                    this.props.validBusinessServices;
                            } else {
                                newValidBusinessServices =
                                    this.props.validBusinessServicesAll;
                            }
                            this.setState({
                                onlyAccountValuesChecked: newChecked,
                                validBusinessServices: newValidBusinessServices,
                            });
                        }}
                    />
                </StyledCheckbox>
                <ContentDiv>
                    <StyledInputDropDown
                        fluid
                        name='business-service-drop'
                        options={this.state.validBusinessServices}
                        placeholder='Select Business Service'
                        filterable
                        onChange={this.businessServiceChanged}
                        valuesWidth='500px'
                        defaultSelectedValue={this.state.selectedBservice}
                    />
                </ContentDiv>
                {this.props.showJustification && (
                    <MessageDiv>
                        <StyledInput
                            id='justification'
                            name='justification'
                            onChange={this.onJustification}
                            autoComplete={'off'}
                            placeholder='Justification for this action'
                        />
                    </MessageDiv>
                )}
                {this.props.errorMessage && (
                    <Color name={'red600'}>{this.props.errorMessage}</Color>
                )}
                <ButtonDiv>
                    <ModifiedButton
                        primary
                        onClick={this.props.submit}
                        data-testid={'business-service-modal-update'}
                    >
                        Submit
                    </ModifiedButton>
                    <ModifiedButton
                        secondary
                        onClick={this.props.cancel}
                        data-testid={'business-service-modal-cancel'}
                    >
                        Cancel
                    </ModifiedButton>
                </ButtonDiv>
            </StyledModal>
        );
    }
}
