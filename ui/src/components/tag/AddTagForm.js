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
import Button from '../denali/Button';
import Tag from '../denali/Tag';
import AppUtils from '../utils/AppUtils';

const SectionsDiv = styled.div`
    width: 780px;
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
    float: left;
    font-size: 14px;
    font-weight: 700;
    width: 17%;
`;

const StyledInputLabelPadding = styled(InputLabel)`
    float: left;
    font-size: 14px;
    font-weight: 700;
    width: 17%;
    padding-top: 5px;
`;

const StyledInput = styled(Input)`
    width: 500px;
`;

const AddTagValueDiv = styled.div`
    display: flex;
    flex-wrap: wrap;
`;

const StyledInputTag = styled(Input)`
    margin-top: 5px;
    flex: 60%;
`;

const ButtonDiv = styled.div`
    margin-left: 10px;
    flex: 35%;
`;

const StyledButton = styled(Button)`
    width: 125px;
`;

const StyledIncludedValuesDiv = styled.div`
    width: 65%;
`;

const StyledTagColor = styled(Tag)`
    color: #d5d5d5;
    &:hover {
        background: #ffffff;
    }
    font-size: 14px;
    height: 28px;
    line-height: 14px;
    margin: 5px 15px 5px 0;
    padding: 6px 8px 7px 10px;
    background: rgba(53, 112, 244, 0.08);
`;

const StyledAnchor = styled.a`
    text-decoration: none;
`;

const StyledAnchorActiveInline = { color: colors.linkActive };

export default class AddTagForm extends React.Component {
    constructor(props) {
        super(props);
        AppUtils.bindClassMethods(this);
        if (props.editedTagKey && props.editedTagValues) {
            this.state = {
                newTagValue: '',
                tagName: props.editedTagKey,
                tagValues: props.editedTagValues,
            };
        } else {
            this.state = {
                newTagValue: '',
                tagName: '',
                tagValues: [],
            };
        }
    }

    inputChanged(key, evt) {
        let value = '';
        if (evt.target) {
            value = evt.target.value;
        } else {
            value = evt ? evt : '';
        }
        this.setState({ [key]: value }, () =>
            this.props.onUpdate(
                this.state.tagName,
                this.state.newTagValue,
                this.state.tagValues
            )
        );
    }

    addTagValue() {
        let name = this.state.newTagValue;
        let tagValues = AppUtils.deepClone(this.state.tagValues);

        if (!name) {
            return;
        }
        let names = (name || '')
            .replace(/[\r\n\s]+/g, ',')
            .split(',')
            .map((n) => n.trim())
            .filter((n) => n);

        for (let i = 0; i < names.length; i++) {
            if (tagValues.indexOf(names[i]) === -1) {
                tagValues.push(names[i]);
            }
        }

        this.setState(
            {
                tagValues,
                newTagValue: '',
            },
            () =>
                this.props.onUpdate(
                    this.state.tagName,
                    this.state.newTagValue,
                    this.state.tagValues
                )
        );
    }

    removeValue(idx) {
        let tagValues = AppUtils.deepClone(this.state.tagValues);
        tagValues.splice(idx, 1);
        this.setState({ tagValues }, () =>
            this.props.onUpdate(
                this.state.tagName,
                this.state.newTagValue,
                this.state.tagValues
            )
        );
    }

    render() {
        let tagValues = this.state.tagValues
            ? this.state.tagValues.map((val, idx) => {
                  return (
                      <StyledTagColor
                          key={val}
                          onClickRemove={() => this.removeValue(idx)}
                      >
                          <StyledAnchor style={StyledAnchorActiveInline}>
                              {' '}
                              {val}{' '}
                          </StyledAnchor>
                      </StyledTagColor>
                  );
              })
            : '';

        return (
            <SectionsDiv autoComplete={'off'} data-testid='add-tag-form'>
                <SectionDiv>
                    <StyledInputLabel htmlFor='tag-name'>
                        Tag Name
                    </StyledInputLabel>
                    <ContentDiv>
                        <StyledInput
                            id='tag-name'
                            name='tag-name'
                            placeholder='Enter New Tag Name'
                            value={this.state.tagName}
                            onChange={(evt) =>
                                this.inputChanged('tagName', evt)
                            }
                            readOnly={this.props.editMode}
                        />
                    </ContentDiv>
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabelPadding htmlFor='description'>
                        Tag Value(s)
                    </StyledInputLabelPadding>
                    <ContentDiv>
                        <AddTagValueDiv>
                            <StyledInputTag
                                id='tag-val'
                                name='tag-val'
                                placeholder='Enter New Tag Value'
                                value={this.state.newTagValue}
                                onChange={(evt) =>
                                    this.inputChanged('newTagValue', evt)
                                }
                            />
                            <ButtonDiv>
                                <StyledButton
                                    secondary
                                    size={'small'}
                                    onClick={this.addTagValue}
                                >
                                    Add
                                </StyledButton>
                            </ButtonDiv>
                        </AddTagValueDiv>
                    </ContentDiv>
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel />
                    <StyledIncludedValuesDiv>
                        {tagValues}
                    </StyledIncludedValuesDiv>
                </SectionDiv>
            </SectionsDiv>
        );
    }
}
