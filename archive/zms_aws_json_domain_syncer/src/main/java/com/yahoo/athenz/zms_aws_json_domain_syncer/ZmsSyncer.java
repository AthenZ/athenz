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
package com.yahoo.athenz.zms_aws_json_domain_syncer;

import com.yahoo.athenz.zms.DomainData;
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
    static final String DEFAULT_SYNCER   = "com.yahoo.athenz.zms_aws_json_domain_syncer.AwsSyncer";

    // these fields are used in the domain_state file
    //
    static final String STATE_VERS_FIELD = "1";
    static final String DOM_STATES_FIELD = "domain_states";
    static final String VERSION_FIELD    = "version";

    // these fields are used in the run_state file
    //
    static final String RUN_STATUS_FIELD  = "run-status"; // value is a number, 0 means success
    static final String RUN_MESSAGE_FIELD = "run-message"; // value is a string explaining the run_status
    static final String RUN_TIME_FIELD    = "run-time"; // value is a string that is date-time in UTC
    static final String NUM_DOMS_UPLOADED_FIELD      = "number-domains-uploaded"; // value is a number
    static final String NUM_DOMS_NOT_UPLOADED_FIELD  = "number-domains-not-uploaded"; // value is a number
    static final String NUM_DOMS_UPLOAD_FAILED_FIELD = "number-domain-upload-failures"; // value is a number
    static final String NUM_DOMS_DELETED_FIELD       = "number-domain-deleted"; //  value is a number
    static final String NUM_DOMS_DELETE_FAILED_FIELD = "number-domain-deleted-failures"; // value is a number

    static final String RUNS_STATUS_SUCCESS_MSG = "Success";
    static final String RUNS_STATUS_FAIL_MSG    = "Failed";

    private List<DomainState> processedDoms   = null;
    private CloudSyncer cloudSyncer;
    private boolean loadStateSuccess     = false;
    private int numDomainsUploaded       = 0;
    private int numDomainsNotUploaded    = 0;
    private int numDomainsUploadFailed   = 0;
    private int numDomainsDeleted        = 0;
    private int numDomainsDeletedFailed  = 0;

    private final StateFileBuilder stateFileBuilder = new StateFileBuilder();

    public ZmsSyncer() throws Exception {
        String cloudSyncClass = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_CLOUDCLASS);
        if (cloudSyncClass == null) {
            cloudSyncClass = DEFAULT_SYNCER;
        }
        LOGGER.info("ZmsSyncer: constructing cloud syncer: " + cloudSyncClass);
        cloudSyncer = (CloudSyncer) Class.forName(cloudSyncClass).newInstance();
    }

    public boolean processDomains() throws Exception {
        if (!Config.getInstance().isConfigSuccessful()) {
            LOGGER.error("ZmsSyncer: configuration is incorrect. Please check log file for errors");
            throw new Exception("ZmsSyncer: bad configuration");
        }
        Map<String, DomainState> stateMap = loadState();
        if (stateMap == null || stateMap.isEmpty()) {
            stateMap = stateFileBuilder.buildStateMap();
        }
        loadStateSuccess = (stateMap != null && !stateMap.isEmpty());
        boolean    sdRet = syncDomains(stateMap);
        boolean    ssRet = saveDomainsState();
        boolean    srRet = saveRunState(null);
        return sdRet && ssRet && srRet;
    }

    public boolean getLoadState() {
        return loadStateSuccess;
    }

    public int getNumDomainsUploaded() {
        return numDomainsUploaded;
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


    DomainState uploadDomain(String domName, ZmsReader zmsRdr) {
        // create a new stateObj to return, update the modified field
        // set the "modified" field to "0" if failed, else set it to value from ZMS
        DomainState stateObj = new DomainState();
        stateObj.setDomain(domName);
        SignedDomain sDom;
        String modified;
        try {
            sDom  = zmsRdr.getDomain(domName);
            if (sDom == null) {
                throw new Exception("zms failed to return object: perhaps no such domain or other error: domain: " + domName);
            }
            DomainData domData = sDom.getDomain();
            modified = domData.getModified().toString();
        } catch (Exception exc) {
            LOGGER.error("ZmsSyncer:uploadDomain: failed to read zms data for domain: " + domName + " : exc: " + exc);
            stateObj.setModified("0");
            ++numDomainsUploadFailed;
            return stateObj;
        }

        try {
            String jsonDoc = JSON.string(sDom);
            cloudSyncer.uploadDomain(domName, jsonDoc);
            ++numDomainsUploaded;
        } catch (Exception exc) {
            LOGGER.error("ZmsSyncer:uploadDomain: cloud sync error domain: " + domName + " : exc: " + exc);
            modified = "0";
            ++numDomainsUploadFailed;
        }
        
        stateObj.setModified(modified);
        return stateObj;
    }

    DomainState deleteDomain(String domName) {
        // delete the domain from S3 - if success, return null, else return state obj
        // with "modified" = "0"
        LOGGER.info("ZmsSyncer:deleteDomain: DELETE cloud domain: " + domName);
        try {
            cloudSyncer.deleteDomain(domName);
            ++numDomainsDeleted;
        } catch (Exception exc) {
            LOGGER.error("ZmsSyncer:deleteDomain: error DELETE cloud domain: " + domName + " : exc: " + exc);
            ++numDomainsDeletedFailed;
            DomainState state = new DomainState();
            state.setDomain(domName);
            state.setModified("0");
            return state;
        }
        return null;
    }

    Map<String, DomainState> loadState() {
        // load the state file
        //
        try {
            String stateFileName = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_STATEPATH) + DOM_STATE_FILE;
            Map<String, DomainState> stateMap = new HashMap<>(400);
            SyncerDomainStates domainStates = Config.getInstance().parseSyncerDomainStates(stateFileName);
            if (domainStates == null) {
                LOGGER.error("Unable to parse domain state file: {}", stateFileName);
                return new HashMap<>();
            }
            ArrayList<DomainState> list = domainStates.getDomainStates();
            LOGGER.debug("ZmsSyncer:loadState: got domain list from state file: num elements: " + list.size());
            for (DomainState domState : list) {
                stateMap.put(domState.getDomain(), domState);
            }
            return stateMap;
        } catch (Exception exc) {
            LOGGER.warn("ZmsSyncer: load state file failure: exc: " + exc);
            return new HashMap<>();
        }
    }

    boolean syncDomains(final Map<String, DomainState> stateMap) throws Exception {
        // get domain list
        //
        ZmsReader zmsRdr = new ZmsReader();
        Set<String> latestZmsDomSet = new HashSet<>();
        boolean retStatus = true;
        try {
            List<SignedDomain> sdList = zmsRdr.getDomainList();
            if (sdList == null || sdList.size() == 0) {
                throw new Exception("ZmsSyncer:syncDomains: no zms domain list");
            }
            
            // Compare the modified timestamp in state file to the zms domain modified timestamp, if not same
            // then it needs to be read from zms and pushed to S3. If the state file doesn't contain entry for
            // the domain, it was newly added domain, so read it from zms and push it to S3. If successful,
            // update the state file with the zms modified timestamp
            
            LOGGER.info("ZmsSyncer:syncDomains: got domain list from zms: num elements: " + sdList.size());
            processedDoms = new ArrayList<>(sdList.size());

            List<String> ignoredDomains = java.util.Arrays.asList(Config.getInstance().getIgnoredDomains());
            for (SignedDomain sDom : sdList) {

                DomainData domData = sDom.getDomain();
                String domName = domData.getName();
                String domMod  = domData.getModified().toString();
                LOGGER.debug("ZmsSyncer:syncDomains: domain: " + domName + " : list-modified: " + domMod);
                latestZmsDomSet.add(domName);

                //check domain against the ignore domain list
                if (ignoredDomains.contains(domName)) {
                    LOGGER.debug("ZmsSyncer:syncDomains: ignoring domain: " + domName);
                    ++numDomainsNotUploaded;
                    continue;
                }

                DomainState domState = stateMap.get(domName);
                boolean uploadDom = domState == null || !domMod.equals(domState.getModified());
                if (uploadDom) {
                    domState = uploadDomain(domName, zmsRdr);
                    processedDoms.add(domState); // add the updated domain state
                    if (domState.getModified().equals("0")) {
                        retStatus = false; // failed to upload this domain
                    }
                } else {
                    processedDoms.add(domState); // add the old domain state
                    ++numDomainsNotUploaded;
                    LOGGER.debug("ZmsSyncer:syncDomains: no change so no upload of domain: " + domName);
                }
            }
        } catch (Exception exc) {
            LOGGER.error("ZmsSyncer:syncDomains: domain processing error: exc: " + exc);
            throw exc;
        }
 
        // determine deleted domains
        // if domain in state file but not in zms list, means it has been deleted

        for (String name : stateMap.keySet()) {
            if (!latestZmsDomSet.contains(name)) {
                // domain was deleted, so delete from S3
                DomainState stateObj = deleteDomain(name);
                if (stateObj != null) {
                    // update the state file for the failed domain deletion
                    processedDoms.add(stateObj);
                    retStatus = false;
                }
            }
        }

        final String sb = "ZmsSyncer:syncDomains" +
                " : number-domains-uploaded: " + getNumDomainsUploaded() +
                " : number-domains-not-uploaded: " + getNumDomainsNotUploaded() +
                " : number-domain-upload-failures: " + getNumDomainsUploadFailed() +
                " : number-domain-deleted: " + getNumDomainsDeleted() +
                " : number-domain-deleted-failures: " + getNumDomainsDeletedFailed();
        LOGGER.info(sb);
        return retStatus;
    }

    boolean saveStateToFile(String stateFileName, Struct newState) {
        // write the new state to a temporary file; move it over the old one
        //
        String tempFile      = stateFileName + "_tmp";
        try {
            Path sourceFile     = Paths.get(tempFile);
            String output = JSON.string(newState);
            OutputStream outstr = Files.newOutputStream(sourceFile);
            outstr.write(output.getBytes());
            LOGGER.debug("ZmsSyncer: created state file: " + tempFile);

            Path destinationFile = Paths.get(stateFileName);

            Files.copy(sourceFile, destinationFile, StandardCopyOption.REPLACE_EXISTING);
            Files.deleteIfExists(sourceFile);
            LOGGER.debug("ZmsSyncer: created new state file: " + stateFileName);
        } catch (Exception exc) {
            LOGGER.error("ZmsSyncer: Failed to store new state file: " + stateFileName + " : exc: " + exc);
            return false;
        }
        return true;
    }

    boolean saveDomainsState() {
        Struct newState = new Struct().with(VERSION_FIELD, STATE_VERS_FIELD).with(DOM_STATES_FIELD, processedDoms);
        String stateFileName = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_STATEPATH) + DOM_STATE_FILE;
        return saveStateToFile(stateFileName, newState);
    }

    boolean saveRunState(Exception exc) {
        int failures = getNumDomainsUploadFailed();
        failures += getNumDomainsDeletedFailed();
        int runStatus = failures > 0 || exc != null ? 1 : 0;
        String msg = runStatus == 0 ? RUNS_STATUS_SUCCESS_MSG :
            exc != null ? exc.getMessage() : RUNS_STATUS_FAIL_MSG;

        Struct newState = new Struct().with(RUN_STATUS_FIELD, runStatus). // value is a number, 0 means success
            with(RUN_MESSAGE_FIELD, msg);

        String timeStamp = Timestamp.fromCurrentTime().toString();
        newState.with(RUN_TIME_FIELD, timeStamp).
            with(NUM_DOMS_UPLOADED_FIELD, getNumDomainsUploaded()).
            with(NUM_DOMS_NOT_UPLOADED_FIELD, getNumDomainsNotUploaded()).
            with(NUM_DOMS_UPLOAD_FAILED_FIELD, getNumDomainsUploadFailed()).
            with(NUM_DOMS_DELETED_FIELD, getNumDomainsDeleted()).
            with(NUM_DOMS_DELETE_FAILED_FIELD, getNumDomainsDeletedFailed());

        String stateFileName = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_STATEPATH) + RUN_STATE_FILE;
        return saveStateToFile(stateFileName, newState);
    }

    public static void main(String[] args) {
        ZmsSyncer syncer = null;
        try {
            syncer = new ZmsSyncer();
            boolean syncStatus = syncer.processDomains();
            System.exit(syncStatus ? 0 : 1);
        } catch (Exception exc) {
            LOGGER.error("ZmsSyncer: failure: exc: " + exc);
            exc.printStackTrace();
            if (syncer != null) {
                syncer.saveRunState(exc);
            }
            System.exit(1);
        }
    }
}

