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
import MemberUtils from '../utils/MemberUtils';
import styled from '@emotion/styled';
import InputLabel from '../denali/InputLabel';
import InputDropdown from '../denali/InputDropdown';
import { colors } from '../denali/styles';
import { selectAllUsers } from '../../redux/selectors/user';
import { USER_DOMAIN } from '../constants/constants';
import RequestUtils from '../utils/RequestUtils';

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
    flex-basis: 20%;
    font-weight: 600;
    line-height: 36px;
`;

const StyledInput = styled(InputDropdown)`
    flex-basis: 80%;
`;

class AddPoc extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.onSubmit = this.onSubmit.bind(this);
        this.userSearch = this.userSearch.bind(this);
        this.state = {
            showModal: this.props.isOpen,
            showAddPoc: false,
            pocName: '',
        };
    }

    onSubmit() {
        if (!this.state.pocName || this.state.pocName.trim() === '') {
            this.setState({
                errorMessage: 'Point of Contact is required for Update.',
            });
            return;
        }
        let meta = {
            contacts: this.props.contacts,
        };
        meta.contacts[this.props.contactType] = this.state.pocName;
        let domainName = this.props.domain;
        let auditMsg = `Updating Point of Contact ${this.state.pocName} for domain ${this.props.domain}`;
        let csrf = this.props.csrf;
        this.api
            .putMeta(domainName, domainName, meta, auditMsg, csrf, 'domain')
            .then(() => {
                this.setState({
                    showModal: false,
                });
                this.props.onPocUpdateSuccessCb(
                    this.props.contactType,
                    this.state.pocName
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    userSearch(part) {
        return MemberUtils.userSearch(part, this.props.userList);
    }

    render() {
        let memberLabel = 'Point of Contact';
        let title = 'Update Point of Contact for ' + this.props.domain;
        if (this.props.contactType === 'security-owner') {
            memberLabel = 'Security Point of Contact';
            title = 'Update Security Point of Contact for ' + this.props.domain;
        }
        let sections = (
            <SectionsDiv autoComplete={'off'} data-testid='add-poc-form'>
                <SectionDiv>
                    <StyledInputLabel htmlFor='member-name'>
                        {memberLabel}
                    </StyledInputLabel>
                    <ContentDiv>
                        <StyledInput
                            fluid={true}
                            id='poc-name'
                            name='poc-name'
                            itemToString={(i) => (i === null ? '' : i.value)}
                            asyncSearchFunc={this.userSearch}
                            onChange={(evt) =>
                                this.setState({
                                    ['pocName']: evt ? evt.value : '',
                                })
                            }
                            placeholder={`${USER_DOMAIN}.<shortid>`}
                        />
                    </ContentDiv>
                </SectionDiv>
            </SectionsDiv>
        );

        return (
            <div data-testid='add-poc'>
                <AddModal
                    isOpen={this.state.showModal}
                    cancel={this.props.onCancel}
                    submit={this.onSubmit}
                    title={title}
                    errorMessage={this.state.errorMessage}
                    sections={sections}
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
export default connect(mapStateToProps, mapDispatchToProps)(AddPoc);
