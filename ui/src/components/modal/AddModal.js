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
import Button from '../denali/Button';
import Modal from '../denali/Modal';
import Color from '../denali/Color';

const MessageDiv = styled.div`
    text-align: left;
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    padding-bottom: 15px;
    max-height: ${(props) => props.height};
    overflow-y: scroll;
`;

const ButtonDiv = styled.div`
    text-align: center;
`;

const ModifiedButton = styled(Button)`
    min-width: 8.5em;
    min-height: 1em;
`;

const StyledAddModal = styled(Modal)`
    width: ${(props) => props.width};
    height: ${(props) => props.height};
`;

export default class AddModal extends React.Component {
    render() {
        let width = '805px';
        let height = 'auto';
        let modalHeight = this.props.modalHeight
            ? this.props.modalHeight
            : 'auto';
        if (this.props.width) {
            width = this.props.width;
        }
        if (this.props.bodyMaxHeight) {
            height = this.props.bodyMaxHeight;
        }
        return (
            <StyledAddModal
                isOpen={this.props.isOpen}
                noanim={true}
                onClose={this.props.cancel}
                title={this.props.title}
                width={width}
                height={modalHeight}
            >
                {this.props.header != null && this.props.header && (
                    <MessageDiv data-testid='add-modal-message'>
                        This update requires you to enter the following
                        parameters
                    </MessageDiv>
                )}
                <MessageDiv data-testid='add-modal-message' height={height}>
                    {this.props.sections}
                </MessageDiv>
                {this.props.errorMessage && (
                    <Color name={'red600'}>{this.props.errorMessage}</Color>
                )}
                <ButtonDiv>
                    <ModifiedButton onClick={this.props.submit}>
                        Submit
                    </ModifiedButton>
                    <ModifiedButton secondary onClick={this.props.cancel}>
                        Cancel
                    </ModifiedButton>
                </ButtonDiv>
            </StyledAddModal>
        );
    }
}
