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
import Input from '../denali/Input';
import { colors } from '../denali/styles';
import { resourceKey } from './selfServiceUtils';

const StyledModal = styled(Modal)`
    width: 600px;
`;

const MessageDiv = styled.div`
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    padding-bottom: 12px;
    text-align: center;
`;

const ResourceList = styled.div`
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding-bottom: 16px;
`;

const ResourceName = styled.div`
    color: ${colors.grey800};
    font: 600 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    text-align: center;
`;

const ButtonDiv = styled.div`
    text-align: center;
`;

const StyledInput = styled(Input)`
    margin: 5px 5px 5px 15px;
    width: 300px;
`;

export default class LeaveResourceModal extends React.Component {
    constructor(props) {
        super(props);
        this.state = { justification: '' };
        this.onJustification = this.onJustification.bind(this);
        this.onSubmit = this.onSubmit.bind(this);
    }

    onJustification(evt) {
        this.setState({ justification: evt.target.value });
    }

    onSubmit() {
        this.props.onSubmit(this.state.justification.trim());
    }

    render() {
        const items = this.props.items ?? [];
        if (!items.length) {
            return null;
        }
        const isCancel = this.props.mode === 'cancel';
        const title = isCancel
            ? 'Withdraw this request'
            : 'This removal is permanent';
        const actionLabel = isCancel ? 'Withdraw' : 'Leave';
        const message =
            isCancel && items.length === 1
                ? 'Are you sure you want to cancel your request for '
                : items.length === 1
                ? 'Are you sure you want to remove yourself from '
                : `Are you sure you want to remove yourself from these ${items.length} memberships?`;
        return (
            <StyledModal
                isOpen={this.props.isOpen}
                noanim={true}
                onClose={this.props.onCancel}
                title={title}
            >
                {items.length === 1 ? (
                    <MessageDiv data-testid='leave-modal-message'>
                        {message}
                        <b>{resourceKey(items[0])}</b> ?
                    </MessageDiv>
                ) : (
                    <>
                        <MessageDiv data-testid='leave-modal-message'>
                            {message}
                        </MessageDiv>
                        <ResourceList>
                            {items.map((item) => (
                                <ResourceName key={resourceKey(item)}>
                                    {resourceKey(item)}
                                </ResourceName>
                            ))}
                        </ResourceList>
                    </>
                )}
                {!isCancel && (
                    <MessageDiv>
                        <StyledInput
                            id='self-serve-leave-justification'
                            name='justification'
                            onChange={this.onJustification}
                            autoComplete='off'
                            placeholder='Justification for this action'
                        />
                    </MessageDiv>
                )}
                {this.props.errorMessage && (
                    <MessageDiv>{this.props.errorMessage}</MessageDiv>
                )}
                <ButtonDiv>
                    <Button
                        danger={!isCancel}
                        onClick={this.onSubmit}
                        data-testid='leave-modal-submit'
                    >
                        {actionLabel}
                    </Button>
                    <Button secondary onClick={this.props.onCancel}>
                        Cancel
                    </Button>
                </ButtonDiv>
            </StyledModal>
        );
    }
}
