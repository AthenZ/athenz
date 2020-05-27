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
import {fireEvent, render, waitForElement} from '@testing-library/react';
import TemplateRow from '../../../components/template/TemplateRow';
import { colors } from '../../../components/denali/styles';

describe('TemplateRow', () => {
    function onClickUpdateTemplate() {
        return false;
    }

    function returnTemplateName(){
        return "aws";
    }

    it('should render', () => {
        const color = colors.row;
        const currentVersion = 0;
        const latestVersion = 1;
        const keywordsToReplace = "";
        const { getByTestId } = render(
            <table>
                <tbody>
                <TemplateRow currentVersion={currentVersion}
                             latestVersion={latestVersion}
                             keywordsToReplace={keywordsToReplace}
                             color={color} />
                </tbody>
            </table>
        );
        const templateRow = getByTestId('template-row');
        expect(templateRow).toMatchSnapshot();
    });

    it('should render without pop up', () => {
        const color = colors.row;
        const currentVersion = 2;
        const latestVersion = 2;
        const keywordsToReplace = "";
        const templateDescription = "testing template description";
        const { getByTestId } = render(
            <table>
                <tbody>
                <TemplateRow currentVersion={currentVersion}
                             latestVersion={latestVersion}
                             keywordsToReplace={keywordsToReplace}
                             color={color}
                             description={templateDescription}/>
                </tbody>
            </table>
        );
        const templateRow = getByTestId('template-row');
        expect(templateRow).toMatchSnapshot();
    });

    it('should render with description', async () => {
        const color = colors.row;
        const currentVersion = 2;
        const latestVersion = 2;
        const keywordsToReplace = "";
        const templateDescription = "testing template description";
        const { getByText, getByTitle,  getByTestId,  } = render(
            <table>
                <tbody>
                <TemplateRow currentVersion={currentVersion} latestVersion={latestVersion} keywordsToReplace={keywordsToReplace} color={color} description={templateDescription}/>
                </tbody>
            </table>
        );
        const templateRow = getByTestId('template-row');
        console.log("getBytext..", getByText('Update'));
        console.log("getbytitle..", getByTitle('information-circle'));

        await waitForElement(() =>
            fireEvent.click(getByTitle('information-circle'))
        );

        expect(
            await waitForElement(() => getByTestId('template-row'))
        ).toMatchSnapshot();
    });


    it('should cancel the pop up', async () => {
        const color = colors.row;
        const currentVersion = 2;
        const latestVersion = 2;
        const keywordsToReplace = "";
        // const message="";
        // const templateDesc= '';
        // const applyTemplate=true;
        // const  showSuccess= true;
        const templateDescription = "testing template description";
        const templateName= 'aws';
        const domain= 'testdom';
        // let state = {
        //     templateDesc: '',
        //     applyTemplate: false,
        //     showSuccess: false,
        //     };

        let params = {
            name: domain,
            domainTemplate: { templateNames: [templateName] },
        };

        let toReturn = //{
            //"metaData": [
            [{
                "templateName": "aws",
                "description": "AWS access template",
                "currentVersion": 4,
                "latestVersion": 1,
                "timestamp": "2020-04-28T00:00:00.000Z",
                "autoUpdate": false
            }];

        const api = {
            updateTemplate: function(params, csrf) {
                return new Promise((resolve, reject) => {
                    resolve(toReturn); reject("error");
                });
            },
        };

        const { getByText, getByTitle,  getByTestId,  } = render(
            <table>
                <tbody>
                <TemplateRow currentVersion={currentVersion}
                             latestVersion={latestVersion}
                             keywordsToReplace={keywordsToReplace}
                             color={color}
                             description={templateDescription}
                             api={api}
                             errorMessage={null}
                             //showUpdate={true}
                             templateName={templateName}
                             templateDesc={templateDescription}
                    //_csrf={this.props._csrf}
                    //key={templateName}
                            onClickUpdateTemplate={onClickUpdateTemplate()}
                             domain={domain}
                             //data={toReturn}
                             onsubmit={returnTemplateName()}
                             onCancel={onClickUpdateTemplate()}

                />
                </tbody>
            </table>
        );
        const templateRow = getByTestId('template-row');

        // await waitForElement(() =>
        //     fireEvent.click(getByText('Update'))
        // );
        //
        // await waitForElement(() =>
        //     fireEvent.click(getByText('Cancel'))
        // );

        expect(
            await waitForElement(() => getByTestId('template-row'))
        ).toMatchSnapshot();
    });
});
