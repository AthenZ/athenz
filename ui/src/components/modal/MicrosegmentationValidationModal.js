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
import Loader from '../denali/Loader';

const MessageDiv = styled.div`
    text-align: left;
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    padding-bottom: 15px;
    height: ${(props) => props.height};
    overflow-y: ${(props) => props.overflowY};
`;

const ButtonDiv = styled.div`
    text-align: center;
`;

const ModifiedButton = styled(Button)`
    min-width: 8.5em;
    min-height: 1em;
`;

const StyledModal = styled(Modal)`
    width: ${(props) => props.width};
    height: ${(props) => props.height};
`;

const StyledLoaderSpan = styled.span`
    margin-left: 10px;
`;

export default class MicrosegmentationValidationModal extends React.Component {
    render() {
        let width = '805px';
        let height = 'auto';
        let overflowY = 'scroll';
        let modalHeight = this.props.modalHeight
            ? this.props.modalHeight
            : 'auto';
        if (this.props.width) {
            width = this.props.width;
        }
        if (this.props.bodyHeight) {
            height = this.props.bodyHeight;
        }
        if (this.props.overflowY) {
            overflowY = this.props.overflowY;
        }
        return (
            <StyledModal
                isOpen={this.props.isOpen}
                noanim={true}
                onClose={this.props.cancel}
                title={this.props.title}
                width={width}
                height={modalHeight}
            >
                <MessageDiv
                    data-testid='validation-modal-message'
                    height={height}
                    overflowY={overflowY}
                >
                    {this.props.sections}
                </MessageDiv>
                <ButtonDiv>
                    <ModifiedButton
                        onClick={this.props.editPolicy}
                        disabled={this.props.saving === 'saving'}
                    >
                        Edit Policy
                    </ModifiedButton>
                    <ModifiedButton
                        secondary
                        onClick={(event) => this.props.submit(event, true)}
                    >
                        Create Policy
                        <StyledLoaderSpan>
                            {this.props.saving === 'saving' && (
                                <Loader size={'15px'} color={'#ffffff'} />
                            )}
                        </StyledLoaderSpan>
                    </ModifiedButton>
                </ButtonDiv>
            </StyledModal>
        );
    }
}
