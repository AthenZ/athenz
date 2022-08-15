package com.yahoo.athenz.zms.purge;

public class PurgeMember {
    private String domainName;
    private String collectionName;
    private String principalName;

    public PurgeMember() {
    }

    public String getDomainName() {
        return domainName;
    }

    public PurgeMember setDomainName(String domainName) {
        this.domainName = domainName;
        return this;
    }

    public String getCollectionName() {
        return collectionName;
    }

    public PurgeMember setCollectionName(String collectionName) {
        this.collectionName = collectionName;
        return this;
    }

    public String getPrincipalName() {
        return principalName;
    }

    public PurgeMember setPrincipalName(String principalName) {
        this.principalName = principalName;
        return this;
    }
}
