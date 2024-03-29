//
// This file generated by rdl 1.5.2. Do not modify!
//

package com.yahoo.athenz.msd;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;
import com.yahoo.rdl.*;

//
// TransportPolicyValidationResponseList - List of
// TransportPolicyValidationResponse
//
@JsonIgnoreProperties(ignoreUnknown = true)
public class TransportPolicyValidationResponseList {
    public List<TransportPolicyValidationResponse> responseList;

    public TransportPolicyValidationResponseList setResponseList(List<TransportPolicyValidationResponse> responseList) {
        this.responseList = responseList;
        return this;
    }
    public List<TransportPolicyValidationResponse> getResponseList() {
        return responseList;
    }

    @Override
    public boolean equals(Object another) {
        if (this != another) {
            if (another == null || another.getClass() != TransportPolicyValidationResponseList.class) {
                return false;
            }
            TransportPolicyValidationResponseList a = (TransportPolicyValidationResponseList) another;
            if (responseList == null ? a.responseList != null : !responseList.equals(a.responseList)) {
                return false;
            }
        }
        return true;
    }
}
