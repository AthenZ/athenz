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
import Icon from '../denali/icons/Icon';
import Button from '../denali/Button';
import Switch from '../denali/Switch';
import Alert from '../denali/Alert';
import Loader from '../denali/Loader';
import DeleteModal from '../modal/DeleteModal';
import AddSnapshotModal from './AddSnapshotModal';
import SnapshotDetails from './SnapshotDetails';
import SnapshotErrorMessage from './SnapshotErrorMessage';
import DateUtils from '../utils/DateUtils';
import RequestUtils from '../utils/RequestUtils';
import { MODAL_TIME_OUT } from '../constants/constants';

const SectionDiv = styled.div`
    margin: 20px;
    clear: both;
`;

const HeaderDiv = styled.div`
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 10px;
`;

const TitleDiv = styled.div`
    font-size: 14px;
    font-weight: 600;
`;

const ActionsDiv = styled.div`
    display: flex;
    align-items: center;
`;

const GuideLink = styled.a`
    margin-right: 15px;
    color: ${colors.link};
    text-decoration: none;
`;

const StyleTable = styled.table`
    width: 100%;
    border-spacing: 0;
    display: table;
    border-collapse: separate;
    border-color: grey;
    box-sizing: border-box;
    box-shadow: 0 1px 4px #d9d9d9;
    border: 1px solid #fff;
`;

const TableHeadStyled = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    font-size: 0.8rem;
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

const DetailsTDStyled = styled.td`
    padding: 0;
`;

const ErrorDiv = styled.div`
    color: ${colors.red600};
    padding: 10px 0;
`;

const EmptyDiv = styled.div`
    padding: 10px 0;
`;

const sortByCreatedDesc = (list) =>
    [...list].sort((a, b) =>
        (b.createdTime || '').localeCompare(a.createdTime || '')
    );

/**
 * Lists the transport policy snapshots of one service, with a detail view per
 * snapshot, and lets the user create and delete snapshots. Data comes from MSD
 * through the `snapshots` fetchr service and lives in component state.
 */
export default class SnapshotList extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.dateUtils = new DateUtils();
        this.state = {
            snapshots: [],
            loaded: false,
            loadError: null,
            expanded: {},
            showAdd: false,
            deleteTarget: null,
            forceDelete: false,
            deleteErrorMessage: null,
            deleteError: null,
            successMessage: null,
            updating: null,
            updateError: null,
        };
        this.loadSnapshots = this.loadSnapshots.bind(this);
        this.toggleAdd = this.toggleAdd.bind(this);
        this.onAddSuccess = this.onAddSuccess.bind(this);
        this.onSubmitDelete = this.onSubmitDelete.bind(this);
        this.onCancelDelete = this.onCancelDelete.bind(this);
        this.closeSuccess = this.closeSuccess.bind(this);
    }

    componentDidMount() {
        this.mounted = true;
        this.loadSnapshots();
    }

    componentWillUnmount() {
        this.mounted = false;
    }

    loadSnapshots() {
        const { domain, service } = this.props;
        return this.api
            .getSnapshots(domain, service)
            .then((data) => {
                if (this.mounted) {
                    this.setState({
                        snapshots: sortByCreatedDesc(
                            (data && data.snapshots) || []
                        ),
                        loaded: true,
                        loadError: null,
                    });
                }
            })
            .catch((err) => {
                if (this.mounted) {
                    this.setState({
                        loaded: true,
                        loadError: err,
                    });
                }
            });
    }

    toggleExpand(name) {
        const expanded = { ...this.state.expanded };
        expanded[name] = !expanded[name];
        this.setState({ expanded });
    }

    toggleAdd() {
        this.setState({ showAdd: !this.state.showAdd });
    }

    onAddSuccess(snapshot) {
        this.setState({
            showAdd: false,
            successMessage: `Snapshot ${snapshot.name} created`,
        });
        this.loadSnapshots();
    }

    onToggleActive(snapshot) {
        const { domain, service, _csrf } = this.props;
        const active = !snapshot.active;
        this.setState({ updating: snapshot.name, updateError: null });
        this.api
            .updateSnapshot(domain, service, snapshot.name, active, _csrf)
            .then(() => {
                if (this.mounted) {
                    this.setState({
                        updating: null,
                        successMessage: `Snapshot ${snapshot.name} marked ${
                            active ? 'active' : 'inactive'
                        }`,
                    });
                    this.loadSnapshots();
                }
            })
            .catch((err) => {
                if (this.mounted) {
                    this.setState({
                        updating: null,
                        updateError: err,
                    });
                }
            });
    }

    onClickDelete(name) {
        this.setState({
            deleteTarget: name,
            forceDelete: false,
            deleteErrorMessage: null,
            deleteError: null,
        });
    }

    onCancelDelete() {
        this.setState({
            deleteTarget: null,
            forceDelete: false,
            deleteErrorMessage: null,
            deleteError: null,
        });
    }

    onSubmitDelete() {
        const { domain, service, _csrf } = this.props;
        const { deleteTarget, forceDelete } = this.state;
        this.api
            .deleteSnapshot(domain, service, deleteTarget, forceDelete, _csrf)
            .then(() => {
                this.setState({
                    deleteTarget: null,
                    forceDelete: false,
                    deleteErrorMessage: null,
                    deleteError: null,
                    successMessage: `Snapshot ${deleteTarget} deleted`,
                });
                this.loadSnapshots();
            })
            .catch((err) => {
                if (err && err.statusCode === 409 && !forceDelete) {
                    // MSD refuses to delete an active snapshot without force;
                    // ask the user to confirm again with force enabled
                    this.setState({
                        forceDelete: true,
                        deleteError: null,
                        deleteErrorMessage:
                            (err.body && err.body.message) ||
                            RequestUtils.xhrErrorCheckHelper(err),
                    });
                } else if (err && err.statusCode === 404) {
                    this.setState({
                        deleteTarget: null,
                        forceDelete: false,
                        deleteErrorMessage: null,
                        deleteError: null,
                    });
                    this.loadSnapshots();
                } else {
                    this.setState({ deleteError: err });
                }
            });
    }

    closeSuccess() {
        this.setState({ successMessage: null });
    }

    formatTime(timestamp) {
        return timestamp
            ? this.dateUtils.getLocalDate(timestamp, 'UTC', 'UTC')
            : '-';
    }

    renderRows() {
        const { domain, service } = this.props;
        const left = 'left';
        const center = 'center';
        const rows = [];
        this.state.snapshots.forEach((snapshot, i) => {
            const color = i % 2 === 0 ? colors.row : '';
            const isExpanded = !!this.state.expanded[snapshot.name];
            rows.push(
                <tr
                    key={snapshot.name}
                    data-testid={`snapshot-row-${snapshot.name}`}
                >
                    <TDStyled color={color} align={left}>
                        {snapshot.name}
                    </TDStyled>
                    <TDStyled color={color} align={left}>
                        <Switch
                            name={`snapshot-active-${snapshot.name}`}
                            checked={!!snapshot.active}
                            labelOn='Active'
                            labelOff='Inactive'
                            disabled={this.state.updating === snapshot.name}
                            onChange={() => this.onToggleActive(snapshot)}
                        />
                    </TDStyled>
                    <TDStyled color={color} align={left}>
                        {this.formatTime(snapshot.createdTime)}
                    </TDStyled>
                    <TDStyled color={color} align={left}>
                        {this.formatTime(snapshot.modified)}
                    </TDStyled>
                    <TDStyled color={color} align={center}>
                        <Icon
                            icon={
                                isExpanded
                                    ? 'arrowhead-up-circle-solid'
                                    : 'arrowhead-down-circle'
                            }
                            onClick={() => this.toggleExpand(snapshot.name)}
                            color={colors.icons}
                            isLink
                            size={'1.25em'}
                            verticalAlign={'text-bottom'}
                            enableTitle
                            title={isExpanded ? 'Hide details' : 'View details'}
                            data-testid={`snapshot-view-${snapshot.name}`}
                        />
                    </TDStyled>
                    <TDStyled color={color} align={center}>
                        <Icon
                            icon={'trash'}
                            onClick={() => this.onClickDelete(snapshot.name)}
                            color={colors.icons}
                            isLink
                            size={'1.25em'}
                            verticalAlign={'text-bottom'}
                            enableTitle
                            title={'Delete snapshot'}
                            data-testid={`snapshot-delete-${snapshot.name}`}
                        />
                    </TDStyled>
                </tr>
            );
            if (isExpanded) {
                rows.push(
                    <tr key={`${snapshot.name}-details`}>
                        <DetailsTDStyled colSpan={6}>
                            <SnapshotDetails
                                api={this.api}
                                domain={domain}
                                service={service}
                                snapshotName={snapshot.name}
                            />
                        </DetailsTDStyled>
                    </tr>
                );
            }
        });
        return rows;
    }

    renderTable() {
        const { pageFeatureFlag } = this.props;
        const guideLink = pageFeatureFlag && pageFeatureFlag.snapshotsGuideLink;
        const left = 'left';
        const center = 'center';
        if (!this.state.loaded) {
            return (
                <EmptyDiv>
                    <Loader size={'1em'} verticalAlign={'middle'} /> Loading
                    snapshots
                </EmptyDiv>
            );
        }
        if (this.state.loadError) {
            return (
                <ErrorDiv data-testid='snapshot-list-error'>
                    <SnapshotErrorMessage
                        err={this.state.loadError}
                        action='view'
                        guideLink={guideLink}
                    />
                </ErrorDiv>
            );
        }
        if (this.state.snapshots.length === 0) {
            return (
                <EmptyDiv data-testid='snapshot-list-empty'>
                    No snapshots. Use the Add Snapshot button to capture the
                    current transport policies of this service.
                </EmptyDiv>
            );
        }
        return (
            <StyleTable data-testid='snapshot-table'>
                <thead>
                    <tr>
                        <TableHeadStyled align={left}>Name</TableHeadStyled>
                        <TableHeadStyled align={left}>Status</TableHeadStyled>
                        <TableHeadStyled align={left}>Created</TableHeadStyled>
                        <TableHeadStyled align={left}>Modified</TableHeadStyled>
                        <TableHeadStyled align={center}>
                            Details
                        </TableHeadStyled>
                        <TableHeadStyled align={center}>Delete</TableHeadStyled>
                    </tr>
                </thead>
                <tbody>{this.renderRows()}</tbody>
            </StyleTable>
        );
    }

    render() {
        const { domain, service, _csrf, pageFeatureFlag } = this.props;
        const guideLink = pageFeatureFlag && pageFeatureFlag.snapshotsGuideLink;
        const count =
            this.state.loaded && !this.state.loadError
                ? ` (${this.state.snapshots.length})`
                : '';
        const { deleteTarget, forceDelete, deleteErrorMessage, deleteError } =
            this.state;
        return (
            <SectionDiv data-testid='snapshot-list'>
                <HeaderDiv>
                    <TitleDiv>{`Snapshots${count}`}</TitleDiv>
                    <ActionsDiv>
                        {guideLink ? (
                            <GuideLink
                                href={guideLink}
                                target='_blank'
                                rel='noopener noreferrer'
                            >
                                Guide
                            </GuideLink>
                        ) : null}
                        <Button secondary onClick={this.toggleAdd}>
                            Add Snapshot
                        </Button>
                    </ActionsDiv>
                </HeaderDiv>
                {this.state.updateError && (
                    <ErrorDiv data-testid='snapshot-update-error'>
                        <SnapshotErrorMessage
                            err={this.state.updateError}
                            action='update'
                            guideLink={guideLink}
                        />
                    </ErrorDiv>
                )}
                {this.renderTable()}
                {this.state.showAdd && (
                    <AddSnapshotModal
                        api={this.api}
                        domain={domain}
                        service={service}
                        _csrf={_csrf}
                        guideLink={guideLink}
                        isOpen={this.state.showAdd}
                        onCancel={this.toggleAdd}
                        onSubmit={this.onAddSuccess}
                    />
                )}
                {deleteTarget && (
                    <DeleteModal
                        isOpen={true}
                        name={deleteTarget}
                        message={
                            forceDelete
                                ? `${deleteErrorMessage}. Force delete snapshot `
                                : 'Are you sure you want to permanently delete the snapshot '
                        }
                        submitLabel={forceDelete ? 'Force delete' : 'Delete'}
                        errorMessage={
                            !forceDelete && deleteError ? (
                                <SnapshotErrorMessage
                                    err={deleteError}
                                    action='delete'
                                    guideLink={guideLink}
                                />
                            ) : null
                        }
                        cancel={this.onCancelDelete}
                        submit={this.onSubmitDelete}
                    />
                )}
                {this.state.successMessage && (
                    <Alert
                        isOpen={true}
                        title={this.state.successMessage}
                        onClose={this.closeSuccess}
                        type='success'
                        duration={MODAL_TIME_OUT}
                    />
                )}
            </SectionDiv>
        );
    }
}
