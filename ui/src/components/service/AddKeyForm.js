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
import TextArea from '../denali/TextArea';

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

const StyledInput = styled(Input)`
    width: 500px;
`;

const StyledTextArea = styled(TextArea)`
    & > textarea {
        resize: vertical;
    }
`;

export default class AddKeyForm extends React.Component {
    constructor(props) {
        super(props);
        this.state = {};
    }

    inputChanged(key, evt) {
        this.setState({ [key]: evt.target.value });
        this.props.onChange(key, evt.target.value);
    }

    render() {
        let keyIdChanged = this.inputChanged.bind(this, 'keyId');
        let keyValueChanged = this.inputChanged.bind(this, 'keyValue');
        let rows = [];
        rows.push(
            <SectionDiv key={'key-id'} data-testid='add-key-id'>
                <StyledInputLabel htmlFor='key-id'>
                    Public Key Id
                </StyledInputLabel>
                <ContentDiv>
                    <StyledInput
                        id='key-id'
                        name='key-id'
                        value={this.state.keyId ? this.state.keyId : ''}
                        onChange={keyIdChanged}
                    />
                </ContentDiv>
            </SectionDiv>
        );
        rows.push(
            <SectionDiv key={'key-value'} data-testid='add-key-value'>
                <StyledInputLabel htmlFor='key-value'>
                    Key Value
                </StyledInputLabel>
                <ContentDiv>
                    <StyledTextArea
                        id='key-value'
                        name='key-value'
                        value={this.state.keyValue}
                        onChange={keyValueChanged}
                        width={'500px'}
                    />
                </ContentDiv>
            </SectionDiv>
        );
        return rows;
    }
}
