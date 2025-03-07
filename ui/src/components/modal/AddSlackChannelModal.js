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
import { connect } from 'react-redux';
import AddModal from '../modal/AddModal';
import styled from '@emotion/styled';
import InputLabel from '../denali/InputLabel';
import { colors } from '../denali/styles';
import { selectAllUsers } from '../../redux/selectors/user';
import RequestUtils from '../utils/RequestUtils';
import Input from '../denali/Input';
import RegexUtils from '../utils/RegexUtils';

const SectionsDiv = styled.div`
    width: 760px;
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
    display: flex;
    flex-flow: row nowrap;
`;

const StyledInputLabel = styled(InputLabel)`
    flex-basis: 32%;
    font-weight: 600;
    line-height: 36px;
`;

const StyledInput = styled(Input)`
    flex-basis: 80%;
`;

class AddSlackChannelModal extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.onSubmit = this.onSubmit.bind(this);
        let slackChannelName =
            this.props.slackChannelName === 'add'
                ? ''
                : this.props.slackChannelName;
        this.state = {
            showModal: this.props.isOpen,
            slackChannelName: slackChannelName,
        };
    }

    onSubmit() {
        if (!!this.state.slackChannelName) {
            if (
                !RegexUtils.validate(
                    this.state.slackChannelName,
                    /^[a-z0-9-_]{1}[a-z0-9-_]{0,79}$/
                )
            ) {
                this.setState({
                    errorMessage:
                        'Slack channel name is invalid. It should be between 1-80 characters long and can only contain lowercase letters, numbers, hyphens and underscores.',
                });
                return;
            }
        }

        let meta = {
            slackChannel: this.state.slackChannelName,
        };
        let domainName = this.props.domain;
        let auditMsg = `Updating Slack channel ${this.state.slackChannelName} for domain ${this.props.domain}`;
        let csrf = this.props.csrf;
        this.api
            .putMeta(domainName, domainName, meta, auditMsg, csrf, 'domain')
            .then(() => {
                this.setState({
                    showModal: false,
                });
                this.props.onSlackChannelUpdateSuccessCb(
                    this.state.slackChannelName
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    inputChanged(key, evt) {
        let value = '';
        if (evt.target) {
            value = evt.target.value;
        } else {
            value = evt ? evt : '';
        }
        this.setState({ [key]: value });
    }

    render() {
        let memberLabel = 'Slack Channel Name';
        let title =
            'Update slack channel to receive notifications for ' +
            this.props.domain;
        let sections = (
            <SectionsDiv
                autoComplete={'off'}
                data-testid='add-slack-channel-form'
            >
                <SectionDiv>
                    <StyledInputLabel htmlFor='member-name'>
                        {memberLabel}
                    </StyledInputLabel>
                    <ContentDiv>
                        <StyledInput
                            id='slack-channel-input'
                            name='slack-channel-input'
                            value={this.state.slackChannelName}
                            onChange={this.inputChanged.bind(
                                this,
                                'slackChannelName'
                            )}
                            autoComplete={'off'}
                            placeholder={'sample-channel'}
                        />
                    </ContentDiv>
                </SectionDiv>
            </SectionsDiv>
        );

        return (
            <div data-testid='add-slack-channel'>
                <AddModal
                    isOpen={this.state.showModal}
                    cancel={this.props.onCancel}
                    submit={this.onSubmit}
                    title={title}
                    errorMessage={this.state.errorMessage}
                    sections={sections}
                    overflowY={'none'}
                />
            </div>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        userList: selectAllUsers(state),
    };
};
const mapDispatchToProps = (dispatch) => ({});
export default connect(
    mapStateToProps,
    mapDispatchToProps
)(AddSlackChannelModal);
