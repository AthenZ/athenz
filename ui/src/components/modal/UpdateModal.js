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
import FlatPicker from '../flatpicker/FlatPicker';
import { colors } from '../denali/styles';

const StyledModal = styled(Modal)`
    width: 600px;
`;

const MessageDiv = styled.div`
    text-align: center;
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    padding-bottom: 15px;
`;

const ButtonDiv = styled.div`
    text-align: center;
`;

const ModifiedButton = styled(Button)`
    min-width: 8.5em;
    min-height: 1em;
`;

const StyledJustification = styled(Input)`
    width: 300px;
    margin: 5px;
    margin-left: 15px;
`;

const FlatPickrInputDiv = styled.div`
    & > div input {
        position: relative;
        font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
        background-color: ${(props) =>
            props.disabled ? colors.grey500 : 'rgba(53, 112, 244, 0.05)'};
        box-shadow: none;
        color: rgb(48, 48, 48);
        min-width: 50px;
        text-align: left;
        border-width: 2px;
        border-style: solid;
        border-color: transparent;
        border-image: initial;
        border-radius: 2px;
        flex: 1 0 auto;
        margin: 10px;
        margin-top: 5px;
        outline: none;
        padding: 0.6em 12px;
        transition: background-color 0.2s ease-in-out 0s,
            color 0.2s ease-in-out 0s, border 0.2s ease-in-out 0s;
        width: 10em;
    }
`;

export default class UpdateModal extends React.Component {
    constructor(props) {
        super(props);
        this.onJustification = this.onJustification.bind(this);
    }

    onJustification(evt) {
        this.props.onJustification(evt.target.value && evt.target.value.trim());
    }
    render() {
        return (
            <StyledModal
                isOpen={this.props.isOpen}
                noanim={true}
                onClose={this.props.cancel}
                title={'This update is permanent'}
            >
                {this.props.showPicker && (
                    <FlatPickrInputDiv>
                        <FlatPicker
                            onChange={(date) => {
                                this.props.onDateChange(date);
                            }}
                            value={this.props.value}
                            placeholder={this.props.placeholder}
                            id='editMember'
                            clear={this.props.placeholder}
                        />
                    </FlatPickrInputDiv>
                )}
                <MessageDiv data-testid='update-modal-message'>
                    {this.props.message}
                    <b>{this.props.name}</b> ?
                </MessageDiv>
                {this.props.showJustification && (
                    <MessageDiv>
                        <StyledJustification
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
                        onClick={this.props.submit}
                        data-testid={'update-modal-update'}
                    >
                        Submit
                    </ModifiedButton>
                    <ModifiedButton
                        secondary
                        onClick={this.props.cancel}
                        data-testid={'update-modal-cancel'}
                    >
                        Cancel
                    </ModifiedButton>
                </ButtonDiv>
            </StyledModal>
        );
    }
}
