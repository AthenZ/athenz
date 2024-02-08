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
import { colors } from '../denali/styles';
import Button from '../denali/Button';
import InputDropdown from '../denali/InputDropdown';
import FlatPicker from '../flatpicker/FlatPicker';
import NameUtils from '../utils/NameUtils';
import Alert from '../denali/Alert';
import Menu from '../denali/Menu/Menu';
import { MODAL_TIME_OUT } from '../constants/constants';
import DateUtils from '../utils/DateUtils';
import { connect } from 'react-redux';
import { selectRoles } from '../../redux/selectors/roles';
import { getDomainHistory } from '../../redux/thunks/domain';
import { selectHistoryRows } from '../../redux/selectors/domainData';
import { selectTimeZone } from '../../redux/selectors/domains';
import { selectIsLoading } from '../../redux/selectors/loading';
import { ReduxPageLoader } from '../denali/ReduxPageLoader';

const HistorySectionDiv = styled.div`
    margin: 20px;
`;

const HistoryTable = styled.table`
    width: 100%;
    border-spacing: 0;
    display: table;
    border-collapse: separate;
    border-color: grey;
    table-layout: fixed;
    padding-top: 20px;
`;

const TableHeadStyled = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid #d5d5d5;
    color: #9a9a9a;
    font-weight: 600;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 15px;
    word-break: break-all;
`;

const TDStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
`;

const HistoryFilterDiv = styled.div`
    display: grid;
    grid-template-columns: 40% 15% 15% 15% 15%;
    grid-gap: 10px;
`;

const HistoryFilterTitleDiv = styled.div`
    font-weight: bold;
`;

const FlatPickrInputDiv = styled.div`
    & > div input {
        position: relative;
        font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
        background-color: rgba(53, 112, 244, 0.05);
        box-shadow: none;
        color: rgb(48, 48, 48);
        height: 16px;
        min-width: 50px;
        text-align: left;
        border-width: 2px;
        border-style: solid;
        border-color: transparent;
        border-image: initial;
        border-radius: 2px;
        flex: 1 0 auto;
        margin: 0px;
        margin-top: 5px;
        outline: none;
        padding: 0.6em 12px;
        transition: background-color 0.2s ease-in-out 0s,
            color 0.2s ease-in-out 0s, border 0.2s ease-in-out 0s;
        width: 80%;
    }
`;

const RolesDropdown = styled(InputDropdown)`
    margin-top: 5px;
`;

const MenuDiv = styled.div`
    padding: 5px 10px;
    background-color: black;
    color: white;
    font-size: 12px;
`;

class HistoryList extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            selectedRole: { name: 'ALL', value: 'ALL' },
            startDate: this.getDefaultStartDate(props.startDate),
            endDate: props.endDate ? new Date(props.endDate) : new Date(),
            showSuccess: false,
        };
        this.exportToCSV = this.exportToCSV.bind(this);
        this.submitHistoryFilter = this.submitHistoryFilter.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.onRoleChange = this.onRoleChange.bind(this);
        this.dateUtils = new DateUtils();
    }

    closeModal() {
        this.setState({ showSuccess: null });
    }

    exportToCSV() {
        let result = '';
        const columnDelimiter = ',',
            lineDelimiter = '\n';
        result +=
            'ACTION,ENTITY,EXECUTED BY,MODIFIED DATE,DETAILS,AUDIT REFERENCE';
        result += lineDelimiter;

        this.props.historyrows.forEach((item) => {
            result +=
                item.action +
                columnDelimiter +
                item.whatEntity +
                columnDelimiter +
                item.who +
                columnDelimiter +
                item.when +
                columnDelimiter +
                item.details +
                columnDelimiter +
                item.why;
            result += lineDelimiter;
        });

        // Download CSV file
        this.downloadCSV(result, this.props.domain + '-audit-history.csv');
    }

    downloadCSV(csv, filename) {
        let csvFile;
        let downloadLink;
        // CSV file
        csvFile = new Blob([csv], { type: 'text/csv' });
        // Download link
        downloadLink = document.createElement('a');
        // File name
        downloadLink.download = filename;
        // Create a link to the file
        downloadLink.href = window.URL.createObjectURL(csvFile);
        // Hide download link
        downloadLink.style.display = 'none';

        // Add the link to DOM
        document.body.appendChild(downloadLink);

        // Click download link
        downloadLink.click();
    }

    getDefaultStartDate(startDate) {
        let date = startDate ? new Date(startDate) : new Date();
        date.setMonth(date.getMonth() - 3);
        return date;
    }

    getMinDate() {
        let date = new Date();
        date.setMonth(date.getMonth() - 15);
        return date;
    }

    submitHistoryFilter() {
        if (
            this.dateUtils.uxDatetimeToRDLTimestamp(this.state.endDate) <
            this.dateUtils.uxDatetimeToRDLTimestamp(this.state.startDate)
        ) {
            let successMsg = `End Date should not be lesser than Start Date`;
            let alertType = 'danger';
            this.setState({
                showSuccess: true,
                successMessage: successMsg,
                alertType: alertType,
            });
            // this is to close the success alert
            setTimeout(
                () =>
                    this.setState({
                        showSuccess: false,
                    }),
                MODAL_TIME_OUT
            );
            return;
        }
        this.props
            .getHistory(
                this.props.domain,
                this.state.startDate,
                this.state.endDate,
                this.props._csrf,
                this.state.selectedRole.value
            )
            .then((data) => {
                let successMsg = `Filtered history records for role ${this.state.selectedRole.value} below. `;
                let alertType = 'success';
                if (data.length === 0) {
                    successMsg = `No history records for role ${this.state.selectedRole.value} found. `;
                    alertType = 'warning';
                }
                this.setState({
                    list: data,
                    showSuccess: true,
                    successMessage: successMsg,
                    alertType: alertType,
                });
                // this is to close the success alert
                setTimeout(
                    () =>
                        this.setState({
                            showSuccess: false,
                        }),
                    MODAL_TIME_OUT
                );
            });
    }

    onRoleChange(selected) {
        if (selected) {
            this.setState({ selectedRole: selected });
        } else {
            this.setState({ selectedRole: { name: 'ALL', value: 'ALL' } });
        }
    }

    render() {
        const left = 'left';
        const rows = this.props.historyrows.map((item, i) => {
            let color = '';
            if (i % 2 === 0) {
                color = colors.row;
            }
            return (
                <tr key={item.epoch}>
                    <TDStyled color={color} align={left}>
                        {item.action}
                    </TDStyled>
                    <TDStyled color={color} align={left}>
                        {item.whatEntity}
                    </TDStyled>
                    <TDStyled color={color} align={left}>
                        <Menu
                            placement='bottom-start'
                            trigger={
                                <span>
                                    {item.whoFull ? item.whoFull : item.who}
                                </span>
                            }
                        >
                            <MenuDiv>{item.who}</MenuDiv>
                        </Menu>
                    </TDStyled>
                    <TDStyled color={color} align={left}>
                        {this.dateUtils.getLocalDate(
                            item.when,
                            this.props.timeZone,
                            this.props.timeZone
                        )}
                    </TDStyled>
                    <TDStyled color={color} align={left}>
                        {item.details}
                    </TDStyled>
                    <TDStyled color={color} align={left}>
                        {item.why}
                    </TDStyled>
                </tr>
            );
        });
        const rolesOptions = this.props.roles.map((item, i) => {
            let roleName = NameUtils.getShortName(':role.', item.name);
            return { name: roleName, value: roleName };
        });
        rolesOptions.push({ name: 'ALL', value: 'ALL' });
        return this.props.isLoading.length !== 0 ? (
            <ReduxPageLoader message={'Loading history'} />
        ) : (
            <HistorySectionDiv data-testid='history-list'>
                <HistoryFilterDiv>
                    <div />
                    <HistoryFilterTitleDiv>
                        Filter by Role
                    </HistoryFilterTitleDiv>
                    <HistoryFilterTitleDiv>Start Date</HistoryFilterTitleDiv>
                    <HistoryFilterTitleDiv>End Date</HistoryFilterTitleDiv>
                    <div />
                    <div>
                        <Button onClick={this.exportToCSV}>
                            Export to CSV
                        </Button>
                    </div>
                    <div>
                        <RolesDropdown
                            fluid
                            id={'roles-dd'}
                            name='roles'
                            options={rolesOptions}
                            placeholder='Type to search Role'
                            filterable
                            onChange={this.onRoleChange}
                        />
                    </div>
                    <FlatPickrInputDiv>
                        <FlatPicker
                            onChange={(startDate) => {
                                this.setState({ startDate });
                            }}
                            minDate={this.getMinDate()}
                            maxDate={new Date()}
                            placeholder={'Start Date (Optional)'}
                            value={this.state.startDate}
                            clear={this.state.startDate}
                            nomargin={true}
                            id='startDate'
                            shouldNotClear={true}
                        />
                    </FlatPickrInputDiv>
                    <FlatPickrInputDiv>
                        <FlatPicker
                            onChange={(endDate) => {
                                this.setState({ endDate });
                            }}
                            minDate={this.getMinDate()}
                            maxDate={new Date()}
                            placeholder={'End Date (Optional)'}
                            value={this.state.endDate}
                            clear={this.state.endDate}
                            nomargin={true}
                            id='endDate'
                            shouldNotClear={true}
                        />
                    </FlatPickrInputDiv>
                    <div>
                        <Button secondary onClick={this.submitHistoryFilter}>
                            Submit
                        </Button>
                    </div>
                </HistoryFilterDiv>
                <HistoryTable>
                    <thead>
                        <tr>
                            <TableHeadStyled align={left}>
                                ACTION
                            </TableHeadStyled>
                            <TableHeadStyled align={left}>
                                ENTITY
                            </TableHeadStyled>
                            <TableHeadStyled align={left}>
                                EXECUTED BY
                            </TableHeadStyled>
                            <TableHeadStyled align={left}>
                                MODIFIED DATE
                            </TableHeadStyled>
                            <TableHeadStyled align={left}>
                                DETAILS
                            </TableHeadStyled>
                            <TableHeadStyled align={left}>
                                JUSTIFICATION
                            </TableHeadStyled>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </HistoryTable>
                {this.state.showSuccess ? (
                    <Alert
                        isOpen={this.state.showSuccess}
                        title={this.state.successMessage}
                        type={this.state.alertType}
                        onClose={this.closeModal}
                    />
                ) : null}
            </HistorySectionDiv>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        isLoading: selectIsLoading(state),
        roles: selectRoles(state),
        historyrows: selectHistoryRows(state),
        timeZone: selectTimeZone(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getHistory: (domainName, startDate, endDate, _csrf, roleName) =>
        dispatch(getDomainHistory(domainName, startDate, endDate, _csrf, roleName)),
});

export default connect(mapStateToProps, mapDispatchToProps)(HistoryList);
