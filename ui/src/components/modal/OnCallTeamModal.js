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

class OnCallTeamModal extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.onSubmit = this.onSubmit.bind(this);
        let onCallTeamName =
            this.props.onCallTeamName === 'add'
                ? ''
                : this.props.onCallTeamName || '';
        this.state = {
            showModal: this.props.isOpen,
            onCallTeamName: onCallTeamName,
        };
    }

    onSubmit() {
        let meta = {
            onCall: this.state.onCallTeamName || '',
        };
        let domainName = this.props.domain;
        let auditMsg = `Updated using athenz ui`;
        let csrf = this.props.csrf;
        this.api
            .putMeta(domainName, domainName, meta, auditMsg, csrf, 'domain')
            .then(() => {
                this.setState({
                    showModal: false,
                });
                this.props.onUpdateOnCallTeamSuccessCb(
                    this.state.onCallTeamName
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
        let title = 'Update on call team name for ' + this.props.domain;
        let sections = (
            <SectionsDiv autoComplete={'off'} data-testid='add-on-call-form'>
                <SectionDiv>
                    <StyledInputLabel htmlFor='member-name'>
                        On Call Team Name
                    </StyledInputLabel>
                    <ContentDiv>
                        <StyledInput
                            id='on-call-team-input'
                            name='on-call-team-input'
                            value={this.state.onCallTeamName}
                            onChange={this.inputChanged.bind(
                                this,
                                'onCallTeamName'
                            )}
                            autoComplete={'off'}
                            placeholder={
                                'on call team responsible for this domain'
                            }
                        />
                    </ContentDiv>
                </SectionDiv>
            </SectionsDiv>
        );

        return (
            <div data-testid='add-on-call-team'>
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
export default connect(mapStateToProps, mapDispatchToProps)(OnCallTeamModal);
