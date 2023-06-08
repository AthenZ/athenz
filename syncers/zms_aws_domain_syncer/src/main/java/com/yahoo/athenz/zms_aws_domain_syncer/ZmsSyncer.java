/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.zms_aws_domain_syncer;

import com.fasterxml.jackson.core.StreamReadConstraints;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.JWSDomain;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.*;

public class ZmsSyncer {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZmsSyncer.class);

    // current version of the state file
    static final String DOM_STATE_FILE   = "/domain_state.json";
    static final String RUN_STATE_FILE   = "/run_state.json";

    // these fields are used in the domain_state file
    static final String STATE_VERS_FIELD = "1";
    static final String DOM_STATES_FIELD = "domainStates";
    static final String VERSION_FIELD    = "version";
    static final String LAST_MOD_NO_DATE = "0";

    // these fields are used in the run_state file
    static final String RUN_STATUS_FIELD  = "run-status"; // value is a number, 0 means success
    static final String RUN_MESSAGE_FIELD = "run-message"; // value is a string explaining the run_status
    static final String RUN_TIME_FIELD    = "run-time"; // value is a string that is date-time in UTC
    static final String NUM_DOMS_UPLOADED_FIELD      = "number-domains-uploaded"; // value is a number
    static final String NUM_DOMS_REFRESHED_FIELD     = "number-domains-refreshed"; // value is a number
    static final String NUM_DOMS_NOT_UPLOADED_FIELD  = "number-domains-not-uploaded"; // value is a number
    static final String NUM_DOMS_UPLOAD_FAILED_FIELD = "number-domain-upload-failures"; // value is a number
    static final String NUM_DOMS_DELETED_FIELD       = "number-domain-deleted"; //  value is a number
    static final String NUM_DOMS_DELETE_FAILED_FIELD = "number-domain-deleted-failures"; // value is a number

    static final String RUNS_STATUS_SUCCESS_MSG = "Success";
    static final String RUNS_STATUS_FAIL_MSG    = "Failed";

    private int numDomainsUploaded       = 0;
    private int numDomainsNotUploaded    = 0;
    private int numDomainsUploadFailed   = 0;
    private int numDomainsDeleted        = 0;
    private int numDomainsDeletedFailed  = 0;
    private int numDomainsRefreshed      = 0;
    private boolean loadStateSuccess     = false;

    private final AwsSyncer awsSyncer;
    private final ZmsReader zmsReader;
    private final StateFileBuilder stateFileBuilder;
    private List<DomainState> processedDomains = null;

    public ZmsSyncer() throws Exception {
        setupJsonParserLimits();
        awsSyncer = new AwsSyncer();
        zmsReader = new ZmsReader();
        stateFileBuilder = new StateFileBuilder();
    }

    public ZmsSyncer(AwsSyncer awsSyncer, ZmsReader zmsReader, StateFileBuilder stateFileBuilder) {
        this.awsSyncer = awsSyncer;
        this.zmsReader = zmsReader;
        this.stateFileBuilder = stateFileBuilder;
    }

    void setupJsonParserLimits() {

        int maxNestingDepth = Integer.parseInt(Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_JSON_MAX_NESTING_DEPTH));
        int maxNumberLength = Integer.parseInt(Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_JSON_MAX_NUMBER_LENGTH));
        int maxStringLength = Integer.parseInt(Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_JSON_MAX_STRING_LENGTH));

        final StreamReadConstraints streamReadConstraints = StreamReadConstraints.builder()
                .maxNestingDepth(maxNestingDepth)
                .maxNumberLength(maxNumberLength)
                .maxStringLength(maxStringLength).build();
        StreamReadConstraints.overrideDefaultStreamReadConstraints(streamReadConstraints);
    }

    public boolean processDomains() throws Exception {
        if (!Config.getInstance().isConfigSuccessful()) {
            LOGGER.error("configuration is incorrect. Please check log file for errors");
            throw new Exception("bad configuration");
        }
        Map<String, DomainState> stateMap = loadState();
        if (stateMap == null || stateMap.isEmpty()) {
            stateMap = stateFileBuilder.buildStateMap();
        }
        loadStateSuccess = (stateMap != null && !stateMap.isEmpty());
        boolean sdRet = syncDomains(stateMap);
        boolean ssRet = saveDomainsState();
        boolean srRet = saveRunState(null);
        return sdRet && ssRet && srRet;
    }

    public boolean getLoadState() {
        return loadStateSuccess;
    }

    public int getNumDomainsUploaded() {
        return numDomainsUploaded;
    }

    public int getNumDomainsRefreshed() {
        return numDomainsRefreshed;
    }

    void setNumDomainsRefreshed(int count) {
        numDomainsRefreshed = count;
    }

    public int getNumDomainsNotUploaded() {
        return numDomainsNotUploaded;
    }

    public int getNumDomainsUploadFailed() {
        return numDomainsUploadFailed;
    }

    public int getNumDomainsDeleted() {
        return numDomainsDeleted;
    }

    public int getNumDomainsDeletedFailed() {
        return numDomainsDeletedFailed;
    }

    DomainState uploadDomain(final String domainName) {

        // create a new stateObj to return, update the modified field
        // set the "modified" field to "0" if failed, else set it to value from ZMS

        DomainState stateObj = new DomainState();
        stateObj.setDomain(domainName);
        JWSDomain jwsDomain;
        String modified;
        try {
            jwsDomain = zmsReader.getDomain(domainName);
            if (jwsDomain == null) {
                throw new Exception("zms failed to return domain object: " + domainName);
            }
            DomainData domainData = zmsReader.getDomainData(jwsDomain);
            modified = domainData.getModified().toString();
        } catch (Exception exc) {
            LOGGER.error("failed to read zms data for domain: {}", domainName, exc);
            stateObj.setModified(LAST_MOD_NO_DATE);
            ++numDomainsUploadFailed;
            return stateObj;
        }

        try {
            awsSyncer.uploadDomain(domainName, JSON.string(jwsDomain));
            ++numDomainsUploaded;
        } catch (Exception exc) {
            LOGGER.error("cloud sync error domain: {}", domainName, exc);
            modified = LAST_MOD_NO_DATE;
            ++numDomainsUploadFailed;
        }
        
        stateObj.setModified(modified);
        stateObj.setFetchTime(System.currentTimeMillis() / 1000);
        return stateObj;
    }

    DomainState deleteDomain(final String domName) {

        // delete the domain from S3 - if success, return null, else return state obj
        // with "modified" = "0"
        LOGGER.info("delete cloud domain: {}", domName);
        try {
            awsSyncer.deleteDomain(domName);
            ++numDomainsDeleted;
        } catch (Exception ex) {
            LOGGER.error("error deleting cloud domain: {}", domName, ex);
            ++numDomainsDeletedFailed;
            DomainState state = new DomainState();
            state.setDomain(domName);
            state.setModified(LAST_MOD_NO_DATE);
            return state;
        }
        return null;
    }

    Map<String, DomainState> loadState() {

        // load the state file

        try {
            String stateFileName = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_STATE_PATH) + DOM_STATE_FILE;
            Map<String, DomainState> stateMap = new HashMap<>(400);
            SyncerDomainStates domainStates = Config.getInstance().parseSyncerDomainStates(stateFileName);
            if (domainStates == null) {
                LOGGER.error("unable to parse domain state file: {}", stateFileName);
                return new HashMap<>();
            }

            ArrayList<DomainState> list = domainStates.getDomainStates();
            LOGGER.debug("got domain list from state file: num elements: {}", list.size());
            for (DomainState domState : list) {
                stateMap.put(domState.getDomain(), domState);
            }
            return stateMap;
        } catch (Exception ex) {
            LOGGER.error("load state file failure", ex);
            return new HashMap<>();
        }
    }

    boolean syncDomains(final Map<String, DomainState> stateMap) throws Exception {

        // fetch how many domains we're going to refresh every time
        // if the domain hasn't been fetched for the configured amount
        // of seconds in the past

        int domainRefreshCountLimit = Integer.parseInt(Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_DOMAIN_REFRESH_COUNT));
        int domainRefreshTimeout = Integer.parseInt(Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_DOMAIN_REFRESH_TIMEOUT));

        // get domain list

        Set<String> latestZmsDomSet = new HashSet<>();
        boolean retStatus = true;
        try {
            List<SignedDomain> sdList = zmsReader.getDomainList();
            if (sdList == null || sdList.size() == 0) {
                throw new Exception("no zms domain list");
            }
            
            // Compare the modified timestamp in state file to the zms domain modified timestamp, if not same
            // then it needs to be read from zms and pushed to S3. If the state file doesn't contain entry for
            // the domain, it was newly added domain, so read it from zms and push it to S3. If successful,
            // update the state file with the zms modified timestamp
            
            LOGGER.info("got domain list from zms: num elements: {}", sdList.size());
            processedDomains = new ArrayList<>(sdList.size());

            long now = System.currentTimeMillis() / 1000;
            for (SignedDomain sDom : sdList) {

                DomainData domainData = sDom.getDomain();
                final String domainName = domainData.getName();
                final String domainModifiedTime  = domainData.getModified().toString();
                LOGGER.debug("domain: {}, list-modified: {}", domainName, domainModifiedTime);
                latestZmsDomSet.add(domainName);

                DomainState domainState = stateMap.get(domainName);
                boolean uploadDom = domainState == null || !domainModifiedTime.equals(domainState.getModified());
                boolean refreshDom = shouldRefreshDomain(domainState, now, domainRefreshCountLimit, domainRefreshTimeout);
                if (uploadDom || refreshDom) {
                    domainState = uploadDomain(domainName);
                    // add the updated domain state
                    processedDomains.add(domainState);
                    // check if we failed to upload this domain
                    if (domainState.getModified().equals(LAST_MOD_NO_DATE)) {
                        retStatus = false;
                    }
                    if (refreshDom) {
                        ++numDomainsRefreshed;
                    }
                } else {
                    // add the old domain state
                    processedDomains.add(domainState);
                    ++numDomainsNotUploaded;
                    LOGGER.debug("no change so no upload of domain: {}", domainName);
                }
            }
        } catch (Exception ex) {
            LOGGER.error("domain processing error", ex);
            throw ex;
        }
 
        // determine deleted domains
        // if domain in state file but not in zms list, means it has been deleted

        for (String name : stateMap.keySet()) {
            if (!latestZmsDomSet.contains(name)) {
                // domain was deleted, so delete from S3
                DomainState stateObj = deleteDomain(name);
                if (stateObj != null) {
                    // update the state file for the failed domain deletion
                    processedDomains.add(stateObj);
                    retStatus = false;
                }
            }
        }

        final String sb = "Sync Status:" +
                " : number-domains-uploaded: " + getNumDomainsUploaded() +
                " : number-domains-refreshed: " + getNumDomainsRefreshed() +
                " : number-domains-not-uploaded: " + getNumDomainsNotUploaded() +
                " : number-domain-upload-failures: " + getNumDomainsUploadFailed() +
                " : number-domain-deleted: " + getNumDomainsDeleted() +
                " : number-domain-deleted-failures: " + getNumDomainsDeletedFailed();
        LOGGER.info(sb);
        return retStatus;
    }

    boolean shouldRefreshDomain(DomainState domainState, long now, int domainRefreshCountLimit, int domainRefreshTimeout) {
        // if there is no state, or we have reached our limit we return false
        if (domainState == null || numDomainsRefreshed >= domainRefreshCountLimit) {
            return false;
        }
        long fetchTime = domainState.getFetchTime();
        return fetchTime != 0 && fetchTime < now - domainRefreshTimeout;
    }

    boolean saveStateToFile(String stateFileName, Struct newState) {
        // write the new state to a temporary file; move it over the old one
        final String tempFile = stateFileName + "_tmp";
        try {
            Path sourceFile = Paths.get(tempFile);
            final String output = JSON.string(newState);
            OutputStream outstr = Files.newOutputStream(sourceFile);
            outstr.write(output.getBytes());
            LOGGER.debug("created state file: {}", tempFile);

            Path destinationFile = Paths.get(stateFileName);

            Files.copy(sourceFile, destinationFile, StandardCopyOption.REPLACE_EXISTING);
            Files.deleteIfExists(sourceFile);
            LOGGER.debug("created new state file: {}", stateFileName);
        } catch (Exception exc) {
            LOGGER.error("failed to store new state file: {}", stateFileName, exc);
            return false;
        }
        return true;
    }

    boolean saveDomainsState() {
        Struct newState = new Struct().with(VERSION_FIELD, STATE_VERS_FIELD).with(DOM_STATES_FIELD, processedDomains);
        String stateFileName = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_STATE_PATH) + DOM_STATE_FILE;
        return saveStateToFile(stateFileName, newState);
    }

    boolean saveRunState(Exception exc) {

        int failures = getNumDomainsUploadFailed() + getNumDomainsDeletedFailed();
        int runStatus = failures > 0 || exc != null ? 1 : 0;

        final String msg = runStatus == 0 ? RUNS_STATUS_SUCCESS_MSG :
            exc != null ? exc.getMessage() : RUNS_STATUS_FAIL_MSG;

        // value is a number, 0 means success
        Struct newState = new Struct().with(RUN_STATUS_FIELD, runStatus).
            with(RUN_MESSAGE_FIELD, msg);

        String timeStamp = Timestamp.fromCurrentTime().toString();
        newState.with(RUN_TIME_FIELD, timeStamp).
            with(NUM_DOMS_UPLOADED_FIELD, getNumDomainsUploaded()).
            with(NUM_DOMS_REFRESHED_FIELD, getNumDomainsRefreshed()).
            with(NUM_DOMS_NOT_UPLOADED_FIELD, getNumDomainsNotUploaded()).
            with(NUM_DOMS_UPLOAD_FAILED_FIELD, getNumDomainsUploadFailed()).
            with(NUM_DOMS_DELETED_FIELD, getNumDomainsDeleted()).
            with(NUM_DOMS_DELETE_FAILED_FIELD, getNumDomainsDeletedFailed());

        final String stateFileName = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_STATE_PATH) + RUN_STATE_FILE;
        return saveStateToFile(stateFileName, newState);
    }

    public static void main(String[] args) {
        ZmsSyncer syncer = null;
        boolean syncStatus = false;
        try {
            syncer = new ZmsSyncer();
            syncStatus = syncer.processDomains();
        } catch (Exception ex) {
            LOGGER.error("zms domain syncer failure", ex);
            if (syncer != null) {
                syncer.saveRunState(ex);
            }
        }
        System.exit(syncStatus ? 0 : 1);
    }
}
