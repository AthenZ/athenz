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
import DateUtils from '../utils/DateUtils';
import Menu from '../denali/Menu/Menu';
import TemplateDescription from './TemplateDescription';
import Button from '../denali/Button';
import ApplyTemplate from './ApplyTemplate';
import RequestUtils from '../utils/RequestUtils';

const TdStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
`;

export default class TemplateRow extends React.Component {
    constructor(props) {
        super(props);
        this.toggleDescription = this.toggleDescription.bind(this);
        this.toggleApplyTemplateNoKeyword =
            this.toggleApplyTemplateNoKeyword.bind(this);
        this.toggleApplyTemplate = this.toggleApplyTemplate.bind(this);
        this.onCancelUpdateTemplate = this.onCancelUpdateTemplate.bind(this);
        this.reloadTemplates = this.reloadTemplates.bind(this);
        this.state = {
            templateDesc: '',
            applyTemplate: false,
            showSuccess: false,
        };
    }

    toggleDescription() {
        if (this.state.description) {
            this.setState({ description: null });
        } else {
            this.setState({
                description: this.props.templateDesc,
            });
        }
    }

    toggleApplyTemplate() {
        this.setState({
            showUpdate: true,
            errorMessage: null,
        });
    }

    toggleApplyTemplateNoKeyword() {
        let params = {
            name: this.props.domain,
            domainTemplate: { templateNames: [this.props.templateName] },
        };
        this.props.api
            .updateTemplate(params, this.props._csrf)
            .then(() => {
                this.reloadTemplates();
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
                this.props.showError(RequestUtils.xhrErrorCheckHelper(err));
            });
    }

    reloadTemplates() {
        this.props.onsubmit(
            `Successfully updated template ${this.props.templateName}`
        );
    }

    closeModal() {
        this.setState({ successService: null });
    }

    onCancelUpdateTemplate() {
        this.setState({
            showUpdate: false,
            deleteServiceName: null,
        });
    }

    render() {
        const left = 'left';
        const center = 'center';
        const color = this.props.color;
        const currentVersion = this.props.currentVersion;
        const latestVersion = this.props.latestVersion;
        const keywordsToReplace = this.props.keywordsToReplace;
        let buttonText = 'Update';
        if (currentVersion == 'N/A') {
            buttonText = 'Onboard';
        }
        let row = [];
        const templateName = this.props.templateName;

        let applyTemplate = this.state.showUpdate ? (
            <ApplyTemplate
                api={this.props.api}
                domain={this.props.domain}
                onSubmit={this.onClickUpdateTemplate}
                onCancel={this.onCancelUpdateTemplate}
                _csrf={this.props._csrf}
                showApplyTemplate={this.state.showUpdate}
                keywords={keywordsToReplace}
                templateName={templateName}
                reloadTemplatePage={this.reloadTemplates}
                title={
                    this.props.currentVersion
                        ? 'Update Template'
                        : 'Onboard Template'
                }
            />
        ) : (
            ''
        );

        row.push(
            <tr key={templateName} data-testid='template-row'>
                <TdStyled color={color} align={left}>
                    {templateName}
                </TdStyled>
                <TdStyled color={color} align={center}>
                    <span>
                        <Icon
                            icon={'information-circle'}
                            onClick={this.toggleDescription}
                            color={colors.icons}
                            isLink
                            size={'1.25em'}
                            verticalAlign={'text-bottom'}
                        />
                    </span>
                </TdStyled>
                <TdStyled color={color} align={center}>
                    {currentVersion}
                </TdStyled>
                <TdStyled color={color} align={center}>
                    {latestVersion}
                </TdStyled>
                <TdStyled color={color} align={center}>
                    {this.props.timestamp}
                </TdStyled>
                <TdStyled color={color} align={center}>
                    <Button
                        secondary={
                            currentVersion == 'N/A' ||
                            currentVersion == latestVersion
                                ? true
                                : false
                        }
                        onClick={
                            !keywordsToReplace
                                ? this.toggleApplyTemplateNoKeyword
                                : this.toggleApplyTemplate
                        }
                        size={'small'}
                        type={'submit'}
                    >
                        {buttonText}
                    </Button>
                    {applyTemplate}
                </TdStyled>
            </tr>
        );

        if (this.state.description) {
            row.push(
                <tr key={templateName + this.props.templateDesc}>
                    <TemplateDescription
                        color={this.props.color}
                        description={this.state.description}
                        api={this.api}
                    />
                </tr>
            );
        }
        return row;
    }
}
