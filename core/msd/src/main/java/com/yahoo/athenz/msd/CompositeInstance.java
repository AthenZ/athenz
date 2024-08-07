//
// This file generated by rdl 1.5.2. Do not modify!
//

package com.yahoo.athenz.msd;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.yahoo.rdl.*;

//
// CompositeInstance - generic instance
//
@JsonIgnoreProperties(ignoreUnknown = true)
public class CompositeInstance {
    public String domainName;
    public String serviceName;
    public String instance;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String instanceType;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String provider;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public Timestamp certExpiryTime;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public Timestamp certIssueTime;

    public CompositeInstance setDomainName(String domainName) {
        this.domainName = domainName;
        return this;
    }
    public String getDomainName() {
        return domainName;
    }
    public CompositeInstance setServiceName(String serviceName) {
        this.serviceName = serviceName;
        return this;
    }
    public String getServiceName() {
        return serviceName;
    }
    public CompositeInstance setInstance(String instance) {
        this.instance = instance;
        return this;
    }
    public String getInstance() {
        return instance;
    }
    public CompositeInstance setInstanceType(String instanceType) {
        this.instanceType = instanceType;
        return this;
    }
    public String getInstanceType() {
        return instanceType;
    }
    public CompositeInstance setProvider(String provider) {
        this.provider = provider;
        return this;
    }
    public String getProvider() {
        return provider;
    }
    public CompositeInstance setCertExpiryTime(Timestamp certExpiryTime) {
        this.certExpiryTime = certExpiryTime;
        return this;
    }
    public Timestamp getCertExpiryTime() {
        return certExpiryTime;
    }
    public CompositeInstance setCertIssueTime(Timestamp certIssueTime) {
        this.certIssueTime = certIssueTime;
        return this;
    }
    public Timestamp getCertIssueTime() {
        return certIssueTime;
    }

    @Override
    public boolean equals(Object another) {
        if (this != another) {
            if (another == null || another.getClass() != CompositeInstance.class) {
                return false;
            }
            CompositeInstance a = (CompositeInstance) another;
            if (domainName == null ? a.domainName != null : !domainName.equals(a.domainName)) {
                return false;
            }
            if (serviceName == null ? a.serviceName != null : !serviceName.equals(a.serviceName)) {
                return false;
            }
            if (instance == null ? a.instance != null : !instance.equals(a.instance)) {
                return false;
            }
            if (instanceType == null ? a.instanceType != null : !instanceType.equals(a.instanceType)) {
                return false;
            }
            if (provider == null ? a.provider != null : !provider.equals(a.provider)) {
                return false;
            }
            if (certExpiryTime == null ? a.certExpiryTime != null : !certExpiryTime.equals(a.certExpiryTime)) {
                return false;
            }
            if (certIssueTime == null ? a.certIssueTime != null : !certIssueTime.equals(a.certIssueTime)) {
                return false;
            }
        }
        return true;
    }
}
