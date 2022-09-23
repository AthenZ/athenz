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

const StyledInput = styled(Input)`
    width: 300px;
    margin: 5px;
    margin-left: 15px;
`;

export default class DeleteModal extends React.Component {
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
                title={'This deletion is permanent'}
            >
                <MessageDiv data-testid='delete-modal-message'>
                    {this.props.message}
                    <b>{this.props.name}</b> ?
                </MessageDiv>
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
                {this.props.showDomainInput && (
                    <MessageDiv>
                        <StyledInput
                            id='domain'
                            name='domain'
                            onChange={(evt) =>
                                this.props.domainNameProvided(
                                    evt.target.value && evt.target.value.trim()
                                )
                            }
                            autoComplete={'off'}
                            placeholder='Enter the domain name to delete'
                        />
                    </MessageDiv>
                )}
                {this.props.errorMessage && (
                    <Color name={'red600'}>{this.props.errorMessage}</Color>
                )}
                <ButtonDiv>
                    <ModifiedButton
                        danger
                        onClick={this.props.submit}
                        data-testid={'delete-modal-delete'}
                    >
                        Delete
                    </ModifiedButton>
                    <ModifiedButton
                        secondary
                        onClick={this.props.cancel}
                        data-testid={'delete-modal-cancel'}
                    >
                        Cancel
                    </ModifiedButton>
                </ButtonDiv>
            </StyledModal>
        );
    }
}
