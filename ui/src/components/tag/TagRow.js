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
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import Menu from '../denali/Menu/Menu';
import Tag from '../denali/Tag';
import { css, keyframes } from '@emotion/react';

const TdStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
`;

const MenuDiv = styled.div`
    padding: 5px 10px;
    background-color: black;
    color: white;
    font-size: 12px;
`;

const colorTransition = keyframes`
        0% {
            background-color: rgba(21, 192, 70, 0.20);
        }
        100% {
            background-color: transparent;
        }
`;

const TrStyled = styled.tr`
    ${(props) =>
        props.isSuccess === true &&
        css`
            animation: ${colorTransition} 3s ease;
        `}
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

export default class TagRow extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            applyTag: false,
            showSuccess: false,
        };
    }

    onClickDeleteTagValue(key, val) {
        this.props.onClickDeleteTagValue(key, val);
    }

    onClickEditTag(tagKey, tagValues) {
        this.props.onClickEditTag(tagKey, tagValues);
    }

    render() {
        const left = 'left';
        const center = 'center';
        const color = this.props.color;
        const tagValues = this.props.tagValues;
        const tagKey = this.props.tagKey;
        return (
            <TrStyled
                data-testid='tag-row'
                isSuccess={this.props.updatedTagKey}
            >
                <TdStyled color={color} align={left}>
                    {tagKey}
                </TdStyled>

                <TdStyled color={color} align={left}>
                    {tagValues.list.map((val) => {
                        return (
                            <StyledTagColor
                                key={val}
                                onClickRemove={() =>
                                    this.onClickDeleteTagValue(tagKey, val)
                                }
                            >
                                <StyledAnchor style={StyledAnchorActiveInline}>
                                    {' '}
                                    {val}{' '}
                                </StyledAnchor>
                            </StyledTagColor>
                        );
                    })}
                </TdStyled>

                <TdStyled color={color} align={center}>
                    <Menu
                        placement='bottom-start'
                        trigger={
                            <span>
                                <Icon
                                    icon={'edit'}
                                    onClick={() =>
                                        this.onClickEditTag(
                                            tagKey,
                                            tagValues.list
                                        )
                                    }
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </span>
                        }
                    >
                        <MenuDiv>Edit Tag</MenuDiv>
                    </Menu>
                </TdStyled>

                <TdStyled color={color} align={center}>
                    <Menu
                        placement='bottom-start'
                        trigger={
                            <span>
                                <Icon
                                    icon={'trash'}
                                    onClick={this.props.onClickDeleteTag}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </span>
                        }
                    >
                        <MenuDiv>Delete Tag</MenuDiv>
                    </Menu>
                </TdStyled>
            </TrStyled>
        );
    }
}
