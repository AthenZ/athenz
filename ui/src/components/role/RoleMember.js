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
import Tag from '../denali/Tag';
import styled from '@emotion/styled';
import DateUtils from '../utils/DateUtils';
import Menu from '../denali/Menu/Menu';
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';

const StyledTag = styled(Tag)`
    background: rgba(53, 112, 244, 0.08);
    color: #d5d5d5;
    &:hover {
        background: #ffffff;
    }
    font-size: 14px;
    height: 28px;
    line-height: 14px;
    margin: 5px 15px 5px 0;
    padding: 7px 8px 7px 10px;
`;
const StyledTagFullNameExpiry = styled.span`
    font-size: 11px;
`;

const MenuDiv = styled.div`
    padding: 5px 10px;
    background-color: black;
    color: white;
    font-size: 12px;
`;

const StyledAnchor = styled.a`
    text-decoration: none;
    cursor: pointer;
`;

const StyledAnchorActiveInline = { color: colors.linkActive };
const StyledTagFullNameExpiryActiveInline = { color: colors.black };

export default class RoleMember extends React.Component {
    constructor(props) {
        super(props);
        this.onClickRemove = this.onClickRemove.bind(this);
        this.onClickPendingRemove = this.onClickPendingRemove.bind(this);
        this.localDate = new DateUtils();
        this.state = {};
    }

    onClickRemove() {
        this.props.onClickRemove(this.props.item.memberName);
    }

    onClickPendingRemove() {
        this.props.onClickPendingRemove(this.props.item.memberName);
    }

    render() {
        let exp = this.props.item.expiration;
        if (exp) {
            exp = this.localDate.getLocalDate(exp, 'UTC', 'UTC');
        }
        let review = this.props.item.reviewReminder;
        if (review) {
            review = this.localDate.getLocalDate(review, 'UTC', 'UTC');
        }

        let fullName = '';
        let shortId = this.props.item.memberName.startsWith('user.')
            ? this.props.item.memberName.substr(
                  5,
                  this.props.item.memberName.length
              )
            : this.props.item.memberName;
        if (this.props.item.memberFullName) {
            fullName = (
                <StyledTagFullNameExpiry
                    style={
                        this.props.item.systemDisabled
                            ? {}
                            : StyledTagFullNameExpiryActiveInline
                    }
                >
                    ({this.props.item.memberFullName})
                </StyledTagFullNameExpiry>
            );
        }
        if (!this.props.item.approved) {
            return (
                <StyledTag
                    onClick={this.props.onClick}
                    onClickRemove={this.onClickPendingRemove}
                    noanim={this.props.noanim}
                    disabled={this.props.item.systemDisabled}
                >
                    <StyledAnchor
                        style={
                            this.props.item.systemDisabled
                                ? {}
                                : StyledAnchorActiveInline
                        }
                        onClick={() =>
                            window.open(
                                this.props.userProfileLink.url,
                                this.props.userProfileLink.target
                            )
                        }
                    >
                        {' '}
                        {review && (
                            <StyledTagFullNameExpiry
                                style={
                                    this.props.item.systemDisabled
                                        ? {}
                                        : StyledTagFullNameExpiryActiveInline
                                }
                            >
                                <Menu
                                    placement='bottom-start'
                                    trigger={
                                        <span>
                                            <Icon
                                                enableTitle={false}
                                                icon={'assignment-priority'}
                                                color={colors.icons}
                                                isLink
                                                size={'1.25em'}
                                                verticalAlign={'text-bottom'}
                                            />
                                        </span>
                                    }
                                >
                                    <MenuDiv>{'Reminder: ' + review}</MenuDiv>
                                </Menu>
                            </StyledTagFullNameExpiry>
                        )}
                        {this.props.item.memberName}{' '}
                    </StyledAnchor>
                    {fullName}
                    {exp && (
                        <StyledTagFullNameExpiry
                            style={
                                this.props.item.systemDisabled
                                    ? {}
                                    : StyledTagFullNameExpiryActiveInline
                            }
                        >
                            {' | '}
                            {exp}
                        </StyledTagFullNameExpiry>
                    )}
                </StyledTag>
            );
        } else {
            return (
                <Tag
                    data-testid={'role-member'}
                    onClick={this.props.onClick}
                    onClickRemove={this.onClickRemove}
                    noanim={this.props.noanim}
                    disabled={this.props.item.systemDisabled}
                >
                    <StyledAnchor
                        style={
                            this.props.item.systemDisabled
                                ? {}
                                : StyledAnchorActiveInline
                        }
                        onClick={() =>
                            window.open(
                                this.props.userProfileLink.url,
                                this.props.userProfileLink.target
                            )
                        }
                    >
                        {' '}
                        {review && (
                            <StyledTagFullNameExpiry
                                style={
                                    this.props.item.systemDisabled
                                        ? {}
                                        : StyledTagFullNameExpiryActiveInline
                                }
                            >
                                <Menu
                                    placement='bottom-start'
                                    trigger={
                                        <span>
                                            <Icon
                                                enableTitle={false}
                                                icon={'assignment-priority'}
                                                color={colors.icons}
                                                isLink
                                                size={'1.25em'}
                                                verticalAlign={'text-bottom'}
                                            />
                                        </span>
                                    }
                                >
                                    <MenuDiv>{'Reminder: ' + review}</MenuDiv>
                                </Menu>
                            </StyledTagFullNameExpiry>
                        )}
                        {this.props.item.memberName}{' '}
                    </StyledAnchor>
                    {fullName}
                    {exp && (
                        <StyledTagFullNameExpiry
                            style={
                                this.props.item.systemDisabled
                                    ? {}
                                    : StyledTagFullNameExpiryActiveInline
                            }
                        >
                            {' | '}
                            {exp}
                        </StyledTagFullNameExpiry>
                    )}
                </Tag>
            );
        }
    }
}
