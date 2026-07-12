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
 * See the License for the specific language governing permissions and limitations
 * under the License.
 */
import React from 'react';
import styled from '@emotion/styled';
import { connect } from 'react-redux';
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import {
    selectResourceOwnershipGuideLink,
    selectResourceOwnershipUi,
    selectZmsUrl,
} from '../../redux/selectors/domains';
import { resolveZmsCliUrl } from '../utils/url';
import {
    getCliSuggestionBody,
    getCliSuggestionEmergencyHeading,
    getCliSuggestionGuideFooter,
} from '../utils/resourceOwnershipUi';

const Wrap = styled.div`
    text-align: left;
    margin: 12px 0;
    padding: 0 16px;
    box-sizing: border-box;
    font: 300 13px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

const BodyText = styled.div`
    line-height: 1.45;
    margin-bottom: 10px;
`;

const CommandBox = styled.div`
    display: flex;
    align-items: stretch;
    background: ${colors.grey200};
    border-radius: 2px;
    margin: 8px 0 12px;
    overflow: hidden;
    border: 1px solid ${colors.grey500};
`;

const CommandPre = styled.pre`
    flex: 1;
    min-width: 0;
    margin: 0;
    padding: 10px 8px 10px 10px;
    white-space: pre-wrap;
    word-break: break-all;
    font-family: Menlo, Monaco, Consolas, monospace;
    font-size: 12px;
    background: transparent;
`;

const CopyHitArea = styled.button`
    flex-shrink: 0;
    border: none;
    border-left: 1px solid ${colors.grey500};
    background: ${colors.grey200};
    padding: 6px 10px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    color: ${colors.grey700};
    &:hover {
        background: ${colors.grey400};
    }
    &:focus {
        outline: 2px solid ${colors.blue400};
        outline-offset: -2px;
    }
`;

const GuideLink = styled.a`
    color: ${colors.linkActive};
    text-decoration: none;
    &:hover {
        text-decoration: underline;
    }
`;

export class ResourceOwnershipCliSuggestion extends React.Component {
    constructor(props) {
        super(props);
        this.copy = this.copy.bind(this);
        this.state = { copied: false };
        this.copiedTimer = null;
    }

    clearCopiedTimer() {
        if (this.copiedTimer) {
            clearTimeout(this.copiedTimer);
            this.copiedTimer = null;
        }
    }

    copy() {
        const cmd = resolveResourceOwnershipCliCommand(
            this.props.command,
            this.props.zmsUrl
        );
        if (!cmd) {
            return;
        }
        this.clearCopiedTimer();
        navigator.clipboard
            .writeText(cmd)
            .then(() => {
                this.setState({ copied: true });
                this.copiedTimer = setTimeout(() => {
                    this.copiedTimer = null;
                    this.setState({ copied: false });
                }, 2000);
            })
            .catch(() => {
                // Clipboard unavailable or denied; command remains selectable in <pre>
            });
    }

    componentWillUnmount() {
        this.clearCopiedTimer();
    }

    render() {
        const command = resolveResourceOwnershipCliCommand(
            this.props.command,
            this.props.zmsUrl
        );
        if (!command) {
            return null;
        }
        const guide = this.props.resourceOwnershipGuideLink || {};
        const guideLabel = guide.title || 'resource-ownership-guide';
        const guideTarget = guide.target || '_blank';
        const ui = this.props.resourceOwnershipUi;
        const bodyText = getCliSuggestionBody(ui);
        const emergencyHeading = getCliSuggestionEmergencyHeading(ui);
        const guideFooter = getCliSuggestionGuideFooter(ui);

        return (
            <Wrap data-testid='resource-ownership-cli-suggestion'>
                <BodyText>{bodyText}</BodyText>
                <BodyText>{emergencyHeading}</BodyText>
                <CommandBox>
                    <CommandPre>{command}</CommandPre>
                    <CopyHitArea
                        type='button'
                        onClick={this.copy}
                        data-testid='resource-ownership-cli-copy'
                        title={this.state.copied ? 'Copied' : 'Copy command'}
                        aria-label={
                            this.state.copied ? 'Copied' : 'Copy command'
                        }
                    >
                        {this.state.copied ? (
                            <Icon
                                icon='check'
                                size='1.15em'
                                color={colors.grey700}
                                enableTitle={false}
                                isLink={false}
                            />
                        ) : (
                            <Icon
                                icon='duplicate'
                                size='1.15em'
                                viewBoxWidth='48'
                                viewBoxHeight='48'
                                color={colors.grey700}
                                enableTitle={false}
                                isLink={false}
                            />
                        )}
                    </CopyHitArea>
                </CommandBox>
                <BodyText>
                    {guideFooter}{' '}
                    {guide.url ? (
                        <GuideLink
                            href={guide.url}
                            target={guideTarget}
                            rel='noopener noreferrer'
                        >
                            {guideLabel}
                        </GuideLink>
                    ) : (
                        guideLabel
                    )}
                    .
                </BodyText>
            </Wrap>
        );
    }
}

const mapStateToProps = (state, ownProps) => ({
    zmsUrl: selectZmsUrl(state),
    resourceOwnershipGuideLink:
        ownProps.resourceOwnershipGuideLink !== undefined
            ? ownProps.resourceOwnershipGuideLink
            : selectResourceOwnershipGuideLink(state),
    resourceOwnershipUi:
        ownProps.resourceOwnershipUi !== undefined
            ? ownProps.resourceOwnershipUi
            : selectResourceOwnershipUi(state),
});

/** Materialize zms-cli text from a deferred builder and runtime/header ZMS URL. */
export function resolveResourceOwnershipCliCommand(command, zmsUrl) {
    if (typeof command !== 'function') {
        return null;
    }
    return command(resolveZmsCliUrl(zmsUrl));
}

export default connect(mapStateToProps)(ResourceOwnershipCliSuggestion);
