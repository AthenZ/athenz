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
import Input from '../denali/Input';
import InputLabel from '../denali/InputLabel';
import Switch from '../denali/Switch';
import AddModal from '../modal/AddModal';
import SnapshotErrorMessage from './SnapshotErrorMessage';
import { colors } from '../denali/styles';
import { SNAPSHOT_NAME_REGEX } from '../constants/constants';

const SectionsDiv = styled.div`
    width: 100%;
    text-align: left;
`;

const SectionDiv = styled.div`
    align-items: flex-start;
    display: flex;
    flex-flow: row nowrap;
    padding: 10px 30px;
`;

const StyledInputLabel = styled(InputLabel)`
    flex-basis: 32%;
    font-weight: 600;
    line-height: 36px;
`;

const ContentDiv = styled.div`
    flex-basis: 68%;
`;

const StyledInput = styled(Input)`
    width: 100%;
`;

const HintDiv = styled.div`
    padding: 0 30px 10px;
    color: ${colors.grey700};
`;

/**
 * Modal to create a transport policy snapshot for a service.
 * Calls props.onSubmit(snapshotMetadata) after MSD confirms the create.
 */
export default class AddSnapshotModal extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.state = {
            name: '',
            active: false,
            errorMessage: null,
            error: null,
            saving: 'todo',
        };
        this.inputChanged = this.inputChanged.bind(this);
        this.toggleActive = this.toggleActive.bind(this);
        this.onSubmit = this.onSubmit.bind(this);
    }

    inputChanged(evt) {
        this.setState({
            name: evt.target.value,
            errorMessage: null,
            error: null,
        });
    }

    toggleActive() {
        this.setState({ active: !this.state.active });
    }

    onSubmit() {
        const name = (this.state.name || '').trim();
        if (!name) {
            this.setState({ errorMessage: 'Snapshot name is required.' });
            return;
        }
        if (!new RegExp(SNAPSHOT_NAME_REGEX).test(name)) {
            this.setState({
                errorMessage:
                    'Snapshot name may contain letters, digits, "_" and "-", with "." as a separator.',
            });
            return;
        }
        const { domain, service, _csrf } = this.props;
        const active = this.state.active;
        this.setState({ saving: 'saving', errorMessage: null, error: null });
        this.api
            .createSnapshot(domain, service, name, active, _csrf)
            .then((data) => {
                this.setState({ saving: 'done' });
                this.props.onSubmit(data || { name, active });
            })
            .catch((err) => {
                this.setState({ saving: 'todo', error: err });
            });
    }

    render() {
        const sections = (
            <SectionsDiv data-testid='add-snapshot-modal'>
                <SectionDiv>
                    <StyledInputLabel htmlFor='snapshot-name'>
                        Snapshot Name
                    </StyledInputLabel>
                    <ContentDiv>
                        <StyledInput
                            id='snapshot-name'
                            name='snapshot-name'
                            value={this.state.name}
                            onChange={this.inputChanged}
                            autoComplete={'off'}
                            placeholder='Enter snapshot name'
                            fluid
                        />
                    </ContentDiv>
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel htmlFor='snapshot-active'>
                        Active
                    </StyledInputLabel>
                    <ContentDiv>
                        <Switch
                            id='snapshot-active'
                            name='snapshot-active'
                            checked={this.state.active}
                            onChange={this.toggleActive}
                        />
                    </ContentDiv>
                </SectionDiv>
                <HintDiv>
                    A snapshot captures the current inbound and outbound
                    transport policies of this service.
                </HintDiv>
            </SectionsDiv>
        );
        return (
            <AddModal
                isOpen={this.props.isOpen}
                cancel={this.props.onCancel}
                submit={this.onSubmit}
                title={`Add snapshot for ${this.props.domain}.${this.props.service}`}
                errorMessage={
                    this.state.errorMessage ||
                    (this.state.error ? (
                        <SnapshotErrorMessage
                            err={this.state.error}
                            action='create'
                            guideLink={this.props.guideLink}
                        />
                    ) : null)
                }
                saving={this.state.saving}
                sections={sections}
                width={'600px'}
            />
        );
    }
}
