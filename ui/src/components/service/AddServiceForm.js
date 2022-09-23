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
import InputLabel from '../denali/InputLabel';
import Input from '../denali/Input';
import { colors } from '../denali/styles';
import AddKeyForm from './AddKeyForm';

const SectionsDiv = styled.div`
    width: 100%;
    text-align: left;
    background-color: ${colors.white};
`;

const SectionDiv = styled.div`
    align-items: flex-start;
    display: flex;
    flex-flow: row nowrap;
    padding: 10px 30px;
`;

const ContentDiv = styled.div`
    flex: 1 1;
    margin-right: 10px;
`;

const StyledInputLabel = styled(InputLabel)`
    flex: 0 0 100px;
    margin-right: 2%;
`;

const NoteDiv = styled.div`
    flex: 0 0 100px;
    margin-right: 2%;
    font-size: 14px;
    font-weight: 600;
    color: ${colors.black};
    line-height: 36px;
    white-space: nowrap;
`;

const NoteDescriptionDiv = styled.div`
    width: 500px;
`;

const StyledInput = styled(Input)`
    width: 500px;
`;

const StyledAnchor = styled.a`
    color: #3570f4;
    text-decoration: none;
    cursor: pointer;
`;

export default class AddServiceForm extends React.Component {
    constructor(props) {
        super(props);
        this.state = {};
        this.keyChanged = this.keyChanged.bind(this);
    }

    inputChanged(key, evt) {
        this.setState({ [key]: evt.target.value });
        this.props.onChange(key, evt.target.value);
    }

    keyChanged(key, value) {
        this.setState({ [key]: value });
        this.props.onChange(key, value);
    }

    render() {
        let descriptionChanged = this.inputChanged.bind(this, 'description');
        let serviceNameChanged = this.inputChanged.bind(this, 'name');
        return (
            <SectionsDiv autoComplete={'off'} data-testid='add-service-form'>
                <SectionDiv>
                    <StyledInputLabel htmlFor='service-name'>
                        Service Name
                    </StyledInputLabel>
                    <ContentDiv>
                        <StyledInput
                            id='service-name'
                            name='service-name'
                            value={this.state.name ? this.state.name : ''}
                            onChange={serviceNameChanged}
                        />
                    </ContentDiv>
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel htmlFor='description'>
                        Description
                    </StyledInputLabel>
                    <ContentDiv>
                        <StyledInput
                            id='description'
                            name='description'
                            value={
                                this.state.description
                                    ? this.state.description
                                    : ''
                            }
                            onChange={descriptionChanged}
                        />
                    </ContentDiv>
                </SectionDiv>
                <SectionDiv>
                    <NoteDiv>NOTE</NoteDiv>
                    <ContentDiv>
                        <NoteDescriptionDiv>
                            {
                                this.props.pageConfig.servicePageConfig
                                    .keyCreationMessage
                            }{' '}
                            Generate a
                            <StyledAnchor
                                onClick={() =>
                                    window.open(
                                        this.props.pageConfig.servicePageConfig
                                            .keyCreationLink.url,
                                        this.props.pageConfig.servicePageConfig
                                            .keyCreationLink.target
                                    )
                                }
                            >
                                {' '}
                                key pair{' '}
                            </StyledAnchor>
                            and add the public key below ONLY if you are not
                            utilizing those.
                        </NoteDescriptionDiv>
                    </ContentDiv>
                </SectionDiv>
                <AddKeyForm onChange={this.keyChanged} />
            </SectionsDiv>
        );
    }
}
