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
import Input from '../denali/Input';
import InputLabel from '../denali/InputLabel';
import styled from '@emotion/styled';
import { colors } from '../denali/styles';
import RequestUtils from '../utils/RequestUtils';
import AddModal from '../modal/AddModal';
import { makeRolesExpires } from '../../redux/actions/roles';
import { makePoliciesExpires } from '../../redux/actions/policies';
import { connect } from 'react-redux';

const SectionDiv = styled.div`
    align-items: flex-start;
    display: flex;
    flex-flow: row nowrap;
    padding: 10px 10px;
`;

const StyledInputLabel = styled(InputLabel)`
    float: left;
    font-size: 14px;
    font-weight: 700;
    width: 100px;
    height: 34px;
`;

const StyledInput = styled(Input)`
    width: 230px;
    height: 34px;
    font-size: 14px;
`;

const ContentDiv = styled.div`
    flex: 1 1;
    margin-right: 10px;
`;

const SectionsDiv = styled.div`
    width: auto;
    text-align: left;
    background-color: ${colors.white};
`;

export default class ApplyTemplate extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.initialKeywordsLoad = this.initialKeywordsLoad.bind(this);
        this.onSubmit = this.onSubmit.bind(this);
        this.reloadTemplatePageOnSubmit =
            this.reloadTemplatePageOnSubmit.bind(this);
        this.state = {
            keywordsList: [],
        };
    }

    componentDidMount() {
        this.initialKeywordsLoad();
    }

    initialKeywordsLoad(button) {
        this.setState({
            keywordsList: this.props.keywords.replace(/_/g, '').split(','),
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

    reloadTemplatePageOnSubmit(templateName) {
        this.props.reloadTemplatePage(
            `Successfully updated template ${templateName}`
        );
        this.props.onCancel();
    }

    constructParams(domain, template, keywordsList) {
        let params = [];
        keywordsList.forEach((value, name) => {
            params.push({ name: name, value: value });
        });
        let parameters = {
            name: domain,
            domainTemplate: { templateNames: [template], params },
        };
        return parameters;
    }

    onSubmit() {
        let service = this.state.service;
        let keywordsMap = new Map();
        let keywordsList = this.state.keywordsList;
        let count = 0;

        keywordsList.forEach((item, index) => {
            let inputItem = this.state[item];
            if (
                !inputItem ||
                inputItem === undefined ||
                inputItem === '' ||
                (inputItem && inputItem.trim() === '') ||
                (inputItem && inputItem === undefined)
            ) {
                return;
            } else {
                keywordsMap.set(item, inputItem.trim());
                this.setState({
                    errorMessage: null,
                });
                count++;
            }
        });

        if (count === keywordsList.length) {
            let params = this.constructParams(
                this.props.domain,
                this.props.templateName,
                keywordsMap
            );
            this.applyTemplateApi(params, this.props._csrf);
        } else {
            this.setState({
                errorMessage: 'Please fill all fields.',
            });
        }
    }

    applyTemplateApi(params, csrf) {
        this.api
            .updateTemplate(params, csrf)
            .then(() => {
                this.reloadTemplatePageOnSubmit(this.props.templateName);
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    render() {
        const rows = this.state.keywordsList.map((item, i) => {
            item = item.replace(/_/g, '');
            return (
                <SectionsDiv
                    key={i}
                    autoComplete={'off'}
                    data-testid='add-service-form'
                >
                    <SectionDiv key={i}>
                        <StyledInputLabel htmlFor='service-name'>
                            {item}
                        </StyledInputLabel>
                        <ContentDiv>
                            <StyledInput
                                id={item + i}
                                name={item}
                                value={this.state.item}
                                placeholder={'Enter ' + item}
                                onChange={this.inputChanged.bind(this, item)}
                            />
                        </ContentDiv>
                    </SectionDiv>
                </SectionsDiv>
            );
        });

        return (
            <AddModal
                isOpen={this.props.showApplyTemplate}
                cancel={this.props.onCancel}
                submit={this.onSubmit}
                title={this.props.title}
                errorMessage={this.state.errorMessage}
                sections={rows}
                header={true}
            />
        );
    }
}
