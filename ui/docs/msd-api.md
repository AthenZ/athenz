# Copyright The Athenz Authors Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms. The Micro Segmentation Defense (MSD) API

## API Methods

### getTransportPolicyRules(*obj, function(err, json, response) { });

`GET /transportpolicies`
API endpoint to get the transport policy rules defined in Athenz

```
obj = {
	"matchingTag": "<String>" // (optional) Retrieved from the previous request, this timestamp specifies to the server to return any policies modified since this time
};
```

### postTransportPolicyValidationRequest(*obj, function(err, json, response) { });

`POST /transportpolicy/validate`
API to validate microsegmentation policies against network policies

```
obj = {
	"transportPolicy": "<TransportPolicyValidationRequest>" // Struct representing microsegmentation policy entered by the user
};
```
*Types:* [`TransportPolicyValidationRequest <Struct>`](#transportpolicyvalidationrequest-struct)

### getTransportPolicyValidationResponseList(*obj, function(err, json, response) { });

`GET /domain/{domainName}/transportpolicy/validationstatus`
API to get transport policy validation response for transport policies of a domain

```
obj = {
	"domainName": "<DomainName>" // name of the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getTransportPolicyRules(*obj, function(err, json, response) { });

`GET /domain/{domainName}/transportpolicies`
API endpoint to get the transport policy rules defined in Athenz for a given domain

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"matchingTag": "<String>" // (optional) Retrieved from the previous request, this timestamp specifies to the server to return any policies modified since this time
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getWorkloads(*obj, function(err, json, response) { });

`GET /domain/{domainName}/service/{serviceName}/workloads`


```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"serviceName": "<EntityName>", // name of the service
	"matchingTag": "<String>" // (optional) Retrieved from the previous request, this timestamp specifies to the server to return any workloads modified since this time
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### getWorkloads(*obj, function(err, json, response) { });

`GET /workloads/{ip}`


```
obj = {
	"ip": "<String>", // ip address to query
	"matchingTag": "<String>" // (optional) Retrieved from the previous request, this timestamp specifies to the server to return any workloads modified since this time
};
```

### putWorkloadOptions(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/service/{serviceName}/workload/dynamic`
Api to perform a dynamic workload PUT operation for a domain and service Workload details are obtained from the service certificate

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"serviceName": "<EntityName>", // name of the service
	"options": "<WorkloadOptions>" // metadata about the dynamic workload
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`WorkloadOptions <Struct>`](#workloadoptions-struct)

### deleteWorkloadOptions(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/service/{serviceName}/instanceId/{instanceId}/workload/dynamic`
Api to perform a dynamic workload DELETE operation for a domain, service, and instance

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"serviceName": "<EntityName>", // name of the service
	"instanceId": "<PathElement>" // unique instance id within provider's namespace
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`PathElement <String>`](#pathelement-string)

### putStaticWorkload(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/service/{serviceName}/workload/static`
Api to perform a static workload PUT operation for a domain and service

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"serviceName": "<EntityName>", // name of the service
	"staticWorkload": "<StaticWorkload>" // Struct representing static workload entered by the user
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`StaticWorkload <Struct>`](#staticworkload-struct)

### deleteStaticWorkload(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/service/{serviceName}/name/{name}/workload/static`
Api to perform a static workload DELETE operation for a domain, service, and instance

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"serviceName": "<EntityName>", // name of the service
	"name": "<String>" // name associated with the workload. In most cases will be a FQDN
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### getStaticWorkloadServices(*obj, function(err, json, response) { });

`GET /services/{serviceType}`
Api to retrieve static workload services by its type. type=StaticWorkloadType in String representation

```
obj = {
	"serviceType": "<EntityName>", // type of the service
	"serviceValue": "<EntityName>" // (optional) specific service value
};
```
*Types:* [`EntityName <String>`](#entityname-string)

### getWorkloads(*obj, function(err, json, response) { });

`GET /domain/{domainName}/workloads`


```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"matchingTag": "<String>" // (optional) Retrieved from the previous request, this timestamp specifies to the server to return any workloads modified since this time
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### postNetworkPolicyChangeImpactRequest(*obj, function(err, json, response) { });

`POST /transportpolicy/evaluatenetworkpolicychange`
API to evaluate network policies change impact on transport policies

```
obj = {
	"detail": "<NetworkPolicyChangeImpactRequest>" // Struct representing a network policy present in the system
};
```
*Types:* [`NetworkPolicyChangeImpactRequest <Struct>`](#networkpolicychangeimpactrequest-struct)

### getRdl.Schema(*obj, function(err, json, response) { });

`GET /schema`
Get RDL Schema



## API Types

### SimpleName `<String>`

Copyright The Athenz Authors Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms. Common name types used by several API definitions A simple identifier, an element of compound name.


```
{
    "type": "String",
    "name": "SimpleName",
    "comment": "Copyright The Athenz Authors Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms. Common name types used by several API definitions A simple identifier, an element of compound name.",
    "pattern": "[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### CompoundName `<String>`

A compound name. Most names in this API are compound names.


```
{
    "type": "String",
    "name": "CompoundName",
    "comment": "A compound name. Most names in this API are compound names.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### DomainName `<String>`

A domain name is the general qualifier prefix, as its uniqueness is managed.


```
{
    "type": "String",
    "name": "DomainName",
    "comment": "A domain name is the general qualifier prefix, as its uniqueness is managed.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### EntityName `<String>`

An entity name is a short form of a resource name, including only the domain and entity.


```
{
    "type": "String",
    "name": "EntityName",
    "comment": "An entity name is a short form of a resource name, including only the domain and entity.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### EntityList `<String>`

An Entity list is comma separated compound Names


```
{
    "type": "String",
    "name": "EntityList",
    "comment": "An Entity list is comma separated compound Names",
    "pattern": "(([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*,)*([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### ServiceName `<String>`

A service name will generally be a unique subdomain.


```
{
    "type": "String",
    "name": "ServiceName",
    "comment": "A service name will generally be a unique subdomain.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### ActionName `<String>`

An action (operation) name.


```
{
    "type": "String",
    "name": "ActionName",
    "comment": "An action (operation) name.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### ResourceName `<String>`

A resource name Note that the EntityName part is optional, that is, a domain name followed by a colon is valid resource name.


```
{
    "type": "String",
    "name": "ResourceName",
    "comment": "A resource name Note that the EntityName part is optional, that is, a domain name followed by a colon is valid resource name.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*(:([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*)?"
}
```

### YBase64 `<String>`

The Y-specific URL-safe Base64 variant.


```
{
    "type": "String",
    "name": "YBase64",
    "comment": "The Y-specific URL-safe Base64 variant.",
    "pattern": "[a-zA-Z0-9\\._-]+"
}
```

### YEncoded `<String>`

YEncoded includes ybase64 chars, as well as = and %. This can represent a user cookie and URL-encoded values.


```
{
    "type": "String",
    "name": "YEncoded",
    "comment": "YEncoded includes ybase64 chars, as well as = and %. This can represent a user cookie and URL-encoded values.",
    "pattern": "[a-zA-Z0-9\\._%=-]*"
}
```

### AuthorityName `<String>`

Used as the prefix in a signed assertion. This uniquely identifies a signing authority.


```
{
    "type": "String",
    "name": "AuthorityName",
    "comment": "Used as the prefix in a signed assertion. This uniquely identifies a signing authority.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### PathElement `<String>`

A uri-safe path element


```
{
    "type": "String",
    "name": "PathElement",
    "comment": "A uri-safe path element",
    "pattern": "[a-zA-Z0-9-\\._~=+@$,:]*"
}
```

### TransportPolicySubjectDomainName `<String>`

DomainName in TransportPolicySubject should allow * to indicate ANY


```
{
    "type": "String",
    "name": "TransportPolicySubjectDomainName",
    "comment": "DomainName in TransportPolicySubject should allow * to indicate ANY",
    "pattern": "\\*|([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### TransportPolicySubjectServiceName `<String>`

ServiceName in TransportPolicySubject should allow * to indicate ANY


```
{
    "type": "String",
    "name": "TransportPolicySubjectServiceName",
    "comment": "ServiceName in TransportPolicySubject should allow * to indicate ANY",
    "pattern": "\\*|([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### TransportPolicyEnforcementState `<Enum>`

Types of transport policy enforcement states


```
{
    "type": "Enum",
    "name": "TransportPolicyEnforcementState",
    "comment": "Types of transport policy enforcement states",
    "elements": [
        {
            "symbol": "ENFORCE"
        },
        {
            "symbol": "REPORT"
        }
    ]
}
```

### TransportPolicyProtocol `<Enum>`

Types of transport policy protocols


```
{
    "type": "Enum",
    "name": "TransportPolicyProtocol",
    "comment": "Types of transport policy protocols",
    "elements": [
        {
            "symbol": "TCP"
        },
        {
            "symbol": "UDP"
        }
    ]
}
```

### TransportPolicyValidationStatus `<Enum>`

Validation Status of transport policy vs network policy


```
{
    "type": "Enum",
    "name": "TransportPolicyValidationStatus",
    "comment": "Validation Status of transport policy vs network policy",
    "elements": [
        {
            "symbol": "VALID"
        },
        {
            "symbol": "INVALID"
        },
        {
            "symbol": "PARTIAL"
        }
    ]
}
```

### TransportPolicyTrafficDirection `<Enum>`

Types of transport policy traffic direction


```
{
    "type": "Enum",
    "name": "TransportPolicyTrafficDirection",
    "comment": "Types of transport policy traffic direction",
    "elements": [
        {
            "symbol": "INGRESS"
        },
        {
            "symbol": "EGRESS"
        }
    ]
}
```

### TransportPolicyScope `<Enum>`

Scope of transport policy


```
{
    "type": "Enum",
    "name": "TransportPolicyScope",
    "comment": "Scope of transport policy",
    "elements": [
        {
            "symbol": "ALL"
        },
        {
            "symbol": "ONPREM"
        },
        {
            "symbol": "AWS"
        },
        {
            "symbol": "GCP"
        }
    ]
}
```

### TransportPolicySubject `<Struct>`

Subject for a transport policy


```
{
    "type": "Struct",
    "name": "TransportPolicySubject",
    "comment": "Subject for a transport policy",
    "fields": [
        {
            "name": "domainName",
            "type": "TransportPolicySubjectDomainName",
            "optional": false,
            "comment": "Name of the domain"
        },
        {
            "name": "serviceName",
            "type": "TransportPolicySubjectServiceName",
            "optional": false,
            "comment": "Name of the service"
        }
    ],
    "closed": false
}
```

### TransportPolicyCondition `<Struct>`

Transport policy condition. Used to specify additional restrictions for the subject of a transport policy


```
{
    "type": "Struct",
    "name": "TransportPolicyCondition",
    "comment": "Transport policy condition. Used to specify additional restrictions for the subject of a transport policy",
    "fields": [
        {
            "name": "enforcementState",
            "type": "TransportPolicyEnforcementState",
            "optional": false,
            "comment": "State of transport policy enforcement ( ENFORCE / REPORT )"
        },
        {
            "name": "instances",
            "type": "Array",
            "optional": true,
            "comment": "Acts as restrictions. If present, this transport policy should be restricted to only mentioned instances.",
            "items": "String"
        },
        {
            "name": "scope",
            "type": "Array",
            "optional": true,
            "comment": "Scope of transport policy",
            "items": "TransportPolicyScope"
        }
    ],
    "closed": false
}
```

### PolicyPort `<Struct>`

generic policy port. Will be used by TransportPolicyPort and NetworkPolicyPort structs


```
{
    "type": "Struct",
    "name": "PolicyPort",
    "comment": "generic policy port. Will be used by TransportPolicyPort and NetworkPolicyPort structs",
    "fields": [
        {
            "name": "port",
            "type": "Int32",
            "optional": false,
            "comment": "Start port of the port range. port and endPort will have same values for a single port definition."
        },
        {
            "name": "endPort",
            "type": "Int32",
            "optional": false,
            "comment": "End port of the port range. port and endPort will have same values for a single port definition."
        }
    ],
    "closed": false
}
```

### TransportPolicyPort `<PolicyPort>`

Transport policy port


```
{
    "type": "PolicyPort",
    "name": "TransportPolicyPort",
    "comment": "Transport policy port",
    "fields": [
        {
            "name": "protocol",
            "type": "TransportPolicyProtocol",
            "optional": false,
            "comment": "Protocol for this transport policy"
        }
    ],
    "closed": false
}
```

### TransportPolicyMatch `<Struct>`

Selector for the subject of a transport policy


```
{
    "type": "Struct",
    "name": "TransportPolicyMatch",
    "comment": "Selector for the subject of a transport policy",
    "fields": [
        {
            "name": "athenzService",
            "type": "TransportPolicySubject",
            "optional": false,
            "comment": "Subject where this transport policy applies"
        },
        {
            "name": "conditions",
            "type": "Array",
            "optional": false,
            "comment": "List of additional requirements for restrictions. Requirements are ANDed.",
            "items": "TransportPolicyCondition"
        }
    ],
    "closed": false
}
```

### TransportPolicyPeer `<Struct>`

Source or destination for a transport policy


```
{
    "type": "Struct",
    "name": "TransportPolicyPeer",
    "comment": "Source or destination for a transport policy",
    "fields": [
        {
            "name": "athenzServices",
            "type": "Array",
            "optional": false,
            "comment": "List of transport policy subjects",
            "items": "TransportPolicySubject"
        },
        {
            "name": "ports",
            "type": "Array",
            "optional": false,
            "comment": "List of network traffic port part of this transport policy",
            "items": "TransportPolicyPort"
        }
    ],
    "closed": false
}
```

### TransportPolicyEntitySelector `<Struct>`

Entity to which a transport policy applies. Describes the subject and port(s) for a transport policy.


```
{
    "type": "Struct",
    "name": "TransportPolicyEntitySelector",
    "comment": "Entity to which a transport policy applies. Describes the subject and port(s) for a transport policy.",
    "fields": [
        {
            "name": "match",
            "type": "TransportPolicyMatch",
            "optional": false,
            "comment": "Requirements for selecting the subject for this transport policy."
        },
        {
            "name": "ports",
            "type": "Array",
            "optional": false,
            "comment": "List of network traffic port of the subject eligible for the transport policy",
            "items": "TransportPolicyPort"
        }
    ],
    "closed": false
}
```

### TransportPolicyIngressRule `<Struct>`

Transport policy ingress rule


```
{
    "type": "Struct",
    "name": "TransportPolicyIngressRule",
    "comment": "Transport policy ingress rule",
    "fields": [
        {
            "name": "id",
            "type": "Int64",
            "optional": false,
            "comment": "Assertion id associated with this transport policy"
        },
        {
            "name": "lastModified",
            "type": "Timestamp",
            "optional": false,
            "comment": "Last modification timestamp of this transport policy"
        },
        {
            "name": "entitySelector",
            "type": "TransportPolicyEntitySelector",
            "optional": false,
            "comment": "Entity to which this transport policy applies"
        },
        {
            "name": "from",
            "type": "TransportPolicyPeer",
            "optional": true,
            "comment": "Source of network traffic"
        }
    ],
    "closed": false
}
```

### TransportPolicyEgressRule `<Struct>`

Transport policy egress rule


```
{
    "type": "Struct",
    "name": "TransportPolicyEgressRule",
    "comment": "Transport policy egress rule",
    "fields": [
        {
            "name": "id",
            "type": "Int64",
            "optional": false,
            "comment": "Assertion id associated with this transport policy"
        },
        {
            "name": "lastModified",
            "type": "Timestamp",
            "optional": false,
            "comment": "Last modification timestamp of this transport policy"
        },
        {
            "name": "entitySelector",
            "type": "TransportPolicyEntitySelector",
            "optional": false,
            "comment": "Entity to which this transport policy applies"
        },
        {
            "name": "to",
            "type": "TransportPolicyPeer",
            "optional": true,
            "comment": "Destination of network traffic"
        }
    ],
    "closed": false
}
```

### TransportPolicyRules `<Struct>`

Transport policy containing ingress and egress rules


```
{
    "type": "Struct",
    "name": "TransportPolicyRules",
    "comment": "Transport policy containing ingress and egress rules",
    "fields": [
        {
            "name": "ingress",
            "type": "Array",
            "optional": false,
            "comment": "List of ingress rules",
            "items": "TransportPolicyIngressRule"
        },
        {
            "name": "egress",
            "type": "Array",
            "optional": false,
            "comment": "List of egress rules",
            "items": "TransportPolicyEgressRule"
        }
    ],
    "closed": false
}
```

### TransportPolicyValidationRequest `<Struct>`

Transport policy request object to be validated


```
{
    "type": "Struct",
    "name": "TransportPolicyValidationRequest",
    "comment": "Transport policy request object to be validated",
    "fields": [
        {
            "name": "entitySelector",
            "type": "TransportPolicyEntitySelector",
            "optional": false,
            "comment": "Describes the entity to which this transport policy applies"
        },
        {
            "name": "peer",
            "type": "TransportPolicyPeer",
            "optional": false,
            "comment": "source or destination of the network traffic depending on direction"
        },
        {
            "name": "id",
            "type": "Int64",
            "optional": true,
            "comment": "If present, assertion id associated with this transport policy"
        },
        {
            "name": "trafficDirection",
            "type": "TransportPolicyTrafficDirection",
            "optional": false
        }
    ],
    "closed": false
}
```

### TransportPolicyValidationResponse `<Struct>`

Response object of transport policy rule validation


```
{
    "type": "Struct",
    "name": "TransportPolicyValidationResponse",
    "comment": "Response object of transport policy rule validation",
    "fields": [
        {
            "name": "status",
            "type": "TransportPolicyValidationStatus",
            "optional": false
        },
        {
            "name": "errors",
            "type": "Array",
            "optional": true,
            "items": "String"
        },
        {
            "name": "updateTime",
            "type": "Timestamp",
            "optional": true,
            "comment": "most recent update timestamp in the backend"
        },
        {
            "name": "id",
            "type": "Int64",
            "optional": true,
            "comment": "If present, assertion id associated with the transport policy"
        }
    ],
    "closed": false
}
```

### TransportPolicyValidationResponseList `<Struct>`

List of TransportPolicyValidationResponse


```
{
    "type": "Struct",
    "name": "TransportPolicyValidationResponseList",
    "comment": "List of TransportPolicyValidationResponse",
    "fields": [
        {
            "name": "responseList",
            "type": "Array",
            "optional": false,
            "comment": "list of transport policy validation response",
            "items": "TransportPolicyValidationResponse"
        }
    ],
    "closed": false
}
```

### StaticWorkloadType `<Enum>`

Enum representing defined types of static workloads.


```
{
    "type": "Enum",
    "name": "StaticWorkloadType",
    "comment": "Enum representing defined types of static workloads.",
    "elements": [
        {
            "symbol": "VIP"
        },
        {
            "symbol": "ENTERPRISE_APPLIANCE"
        },
        {
            "symbol": "CLOUD_LB"
        },
        {
            "symbol": "CLOUD_NAT"
        },
        {
            "symbol": "EXTERNAL_APPLIANCE"
        },
        {
            "symbol": "VIP_LB"
        },
        {
            "symbol": "CLOUD_MANAGED"
        },
        {
            "symbol": "SERVICE_SUBNET"
        }
    ]
}
```

### DynamicWorkload `<Struct>`

workload type describing workload bootstrapped with an identity


```
{
    "type": "Struct",
    "name": "DynamicWorkload",
    "comment": "workload type describing workload bootstrapped with an identity",
    "fields": [
        {
            "name": "domainName",
            "type": "DomainName",
            "optional": false,
            "comment": "name of the domain"
        },
        {
            "name": "serviceName",
            "type": "EntityName",
            "optional": false,
            "comment": "name of the service"
        },
        {
            "name": "uuid",
            "type": "String",
            "optional": false,
            "comment": "unique identifier for the workload, usually defined by provider"
        },
        {
            "name": "ipAddresses",
            "type": "Array",
            "optional": false,
            "comment": "list of IP addresses associated with the workload, optional for getWorkloadsByIP API call",
            "items": "String"
        },
        {
            "name": "hostname",
            "type": "String",
            "optional": false,
            "comment": "hostname associated with the workload"
        },
        {
            "name": "provider",
            "type": "String",
            "optional": false,
            "comment": "infrastructure provider e.g. Kubernetes, AWS, Azure, openstack etc."
        },
        {
            "name": "updateTime",
            "type": "Timestamp",
            "optional": false,
            "comment": "most recent update timestamp in the backend"
        },
        {
            "name": "certExpiryTime",
            "type": "Timestamp",
            "optional": false,
            "comment": "certificate expiry time (ex: getNotAfter)"
        },
        {
            "name": "certIssueTime",
            "type": "Timestamp",
            "optional": true,
            "comment": "certificate issue time (ex: getNotBefore)"
        }
    ],
    "closed": false
}
```

### Workload `<DynamicWorkload>`

kept for backward compatibility sake. Will be eventually deprecated in favor of DynamicWorkload


```
{
    "type": "DynamicWorkload",
    "name": "Workload",
    "comment": "kept for backward compatibility sake. Will be eventually deprecated in favor of DynamicWorkload",
    "fields": [],
    "closed": false
}
```

### StaticWorkload `<Struct>`

workload type describing workload indirectly associated with an identity ( without bootstrap )


```
{
    "type": "Struct",
    "name": "StaticWorkload",
    "comment": "workload type describing workload indirectly associated with an identity ( without bootstrap )",
    "fields": [
        {
            "name": "domainName",
            "type": "DomainName",
            "optional": false,
            "comment": "name of the domain"
        },
        {
            "name": "serviceName",
            "type": "EntityName",
            "optional": false,
            "comment": "name of the service"
        },
        {
            "name": "type",
            "type": "StaticWorkloadType",
            "optional": false,
            "comment": "value representing one of the StaticWorkloadType enum"
        },
        {
            "name": "ipAddresses",
            "type": "Array",
            "optional": true,
            "comment": "list of IP addresses associated with the workload, optional for getWorkloadsByIP API call",
            "items": "String"
        },
        {
            "name": "name",
            "type": "String",
            "optional": true,
            "comment": "name associated with the workload. In most cases will be a FQDN"
        },
        {
            "name": "updateTime",
            "type": "Timestamp",
            "optional": true,
            "comment": "most recent update timestamp in the backend"
        }
    ],
    "closed": false
}
```

### WorkloadOptions `<Struct>`

```
{
    "type": "Struct",
    "name": "WorkloadOptions",
    "fields": [
        {
            "name": "ipChanged",
            "type": "Bool",
            "optional": false,
            "comment": "boolean flag to signal a change in IP state"
        }
    ],
    "closed": false
}
```

### Workloads `<Struct>`

list of workloads


```
{
    "type": "Struct",
    "name": "Workloads",
    "comment": "list of workloads",
    "fields": [
        {
            "name": "workloadList",
            "type": "Array",
            "optional": false,
            "comment": "list of workloads",
            "items": "Workload"
        },
        {
            "name": "dynamicWorkloadList",
            "type": "Array",
            "optional": true,
            "comment": "list of dynamic workloads",
            "items": "DynamicWorkload"
        },
        {
            "name": "staticWorkloadList",
            "type": "Array",
            "optional": true,
            "comment": "list of static workloads",
            "items": "StaticWorkload"
        }
    ],
    "closed": false
}
```

### StaticWorkloadService `<Struct>`

static workload service


```
{
    "type": "Struct",
    "name": "StaticWorkloadService",
    "comment": "static workload service",
    "fields": [
        {
            "name": "type",
            "type": "StaticWorkloadType",
            "optional": false,
            "comment": "value representing one of the StaticWorkloadType enum"
        },
        {
            "name": "serviceName",
            "type": "EntityName",
            "optional": false,
            "comment": "name of the service"
        },
        {
            "name": "instance",
            "type": "EntityName",
            "optional": false,
            "comment": "service instance"
        }
    ],
    "closed": false
}
```

### StaticWorkloadServices `<Struct>`

list of services


```
{
    "type": "Struct",
    "name": "StaticWorkloadServices",
    "comment": "list of services",
    "fields": [
        {
            "name": "staticWorkloadServices",
            "type": "Array",
            "optional": false,
            "items": "StaticWorkloadService"
        }
    ],
    "closed": false
}
```

### NetworkPolicyChangeEffect `<Enum>`

IMPACT indicates that a change in network policy will interfere with workings of one or more transport policies NO_IMAPCT indicates that a change in network policy will not interfere with workings of any transport policy


```
{
    "type": "Enum",
    "name": "NetworkPolicyChangeEffect",
    "comment": "IMPACT indicates that a change in network policy will interfere with workings of one or more transport policies NO_IMAPCT indicates that a change in network policy will not interfere with workings of any transport policy",
    "elements": [
        {
            "symbol": "IMPACT"
        },
        {
            "symbol": "NO_IMPACT"
        }
    ]
}
```

### IPBlock `<Struct>`

Struct representing ip blocks used by network policy in CIDR (Classless inter-domain routing) format


```
{
    "type": "Struct",
    "name": "IPBlock",
    "comment": "Struct representing ip blocks used by network policy in CIDR (Classless inter-domain routing) format",
    "fields": [
        {
            "name": "cidr",
            "type": "String",
            "optional": false,
            "comment": "cidr notation. can be used for ipv4 or ipv6"
        }
    ],
    "closed": false
}
```

### NetworkPolicyPort `<PolicyPort>`

network policy port.


```
{
    "type": "PolicyPort",
    "name": "NetworkPolicyPort",
    "comment": "network policy port.",
    "fields": [
        {
            "name": "protocol",
            "type": "TransportPolicyProtocol",
            "optional": false,
            "comment": "protocol used by the network policy"
        }
    ],
    "closed": false
}
```

### NetworkPolicyPorts `<Struct>`

allows creating a unique tuple of source and destination ports


```
{
    "type": "Struct",
    "name": "NetworkPolicyPorts",
    "comment": "allows creating a unique tuple of source and destination ports",
    "fields": [
        {
            "name": "sourcePorts",
            "type": "Array",
            "optional": false,
            "comment": "list of source ports",
            "items": "NetworkPolicyPort"
        },
        {
            "name": "destinationPorts",
            "type": "Array",
            "optional": false,
            "comment": "list of destination ports",
            "items": "NetworkPolicyPort"
        }
    ],
    "closed": false
}
```

### NetworkPolicyChangeImpactRequest `<Struct>`

struct representing input details for evaluating network policies change impact on transport policies


```
{
    "type": "Struct",
    "name": "NetworkPolicyChangeImpactRequest",
    "comment": "struct representing input details for evaluating network policies change impact on transport policies",
    "fields": [
        {
            "name": "from",
            "type": "Array",
            "optional": false,
            "comment": "from ip address range list in cidr format",
            "items": "IPBlock"
        },
        {
            "name": "to",
            "type": "Array",
            "optional": false,
            "comment": "to ip address range list in cidr format",
            "items": "IPBlock"
        },
        {
            "name": "ports",
            "type": "Array",
            "optional": false,
            "comment": "list of ports. Facilitates multiple transports for the same source and destinations.",
            "items": "NetworkPolicyPorts"
        }
    ],
    "closed": false
}
```

### NetworkPolicyChangeImpactDetail `<Struct>`

```
{
    "type": "Struct",
    "name": "NetworkPolicyChangeImpactDetail",
    "fields": [
        {
            "name": "domain",
            "type": "DomainName",
            "optional": false,
            "comment": "Name of the domain of the corresponding transport policy"
        },
        {
            "name": "policy",
            "type": "EntityName",
            "optional": false,
            "comment": "Name of the Athenz policy corresponding to transport policy"
        },
        {
            "name": "transportPolicyId",
            "type": "Int64",
            "optional": false,
            "comment": "Unique id of the transport policy"
        }
    ],
    "closed": false
}
```

### NetworkPolicyChangeImpactResponse `<Struct>`

struct representing response of evaluating network policies change impact on transport policies


```
{
    "type": "Struct",
    "name": "NetworkPolicyChangeImpactResponse",
    "comment": "struct representing response of evaluating network policies change impact on transport policies",
    "fields": [
        {
            "name": "effect",
            "type": "NetworkPolicyChangeEffect",
            "optional": false,
            "comment": "enum indicating effect of network policy change on one or more transport policies"
        },
        {
            "name": "details",
            "type": "Array",
            "optional": true,
            "comment": "if the above enum value is IMPACT then this optional object contains more details about the impacted transport policies",
            "items": "NetworkPolicyChangeImpactDetail"
        }
    ],
    "closed": false
}
```

### rdl.Identifier `<String>`

All names need to be of this restricted string type


```
{
    "type": "String",
    "name": "rdl.Identifier",
    "comment": "All names need to be of this restricted string type",
    "pattern": "[a-zA-Z_]+[a-zA-Z_0-9]*"
}
```

### rdl.NamespacedIdentifier `<String>`

A Namespace is a dotted compound name, using reverse domain name order (i.e. "com.yahoo.auth")


```
{
    "type": "String",
    "name": "rdl.NamespacedIdentifier",
    "comment": "A Namespace is a dotted compound name, using reverse domain name order (i.e. \"com.yahoo.auth\")",
    "pattern": "([a-zA-Z_]+[a-zA-Z_0-9]*)(\\.[a-zA-Z_]+[a-zA-Z_0-9])*"
}
```

### rdl.BaseType `<Enum>`

```
{
    "type": "Enum",
    "name": "rdl.BaseType",
    "elements": [
        {
            "symbol": "Bool"
        },
        {
            "symbol": "Int8"
        },
        {
            "symbol": "Int16"
        },
        {
            "symbol": "Int32"
        },
        {
            "symbol": "Int64"
        },
        {
            "symbol": "Float32"
        },
        {
            "symbol": "Float64"
        },
        {
            "symbol": "Bytes"
        },
        {
            "symbol": "String"
        },
        {
            "symbol": "Timestamp"
        },
        {
            "symbol": "Symbol"
        },
        {
            "symbol": "UUID"
        },
        {
            "symbol": "Array"
        },
        {
            "symbol": "Map"
        },
        {
            "symbol": "Struct"
        },
        {
            "symbol": "Enum"
        },
        {
            "symbol": "Union"
        },
        {
            "symbol": "Any"
        }
    ]
}
```

### rdl.ExtendedAnnotation `<String>`

ExtendedAnnotation - parsed and preserved, but has no defined meaning in RDL. Such annotations must begin with "x_", and may have an associated string literal value (the value will be "" if the annotation is just a flag).


```
{
    "type": "String",
    "name": "rdl.ExtendedAnnotation",
    "comment": "ExtendedAnnotation - parsed and preserved, but has no defined meaning in RDL. Such annotations must begin with \"x_\", and may have an associated string literal value (the value will be \"\" if the annotation is just a flag).",
    "pattern": "x_[a-zA-Z_0-9]*"
}
```

### rdl.TypeDef `<Struct>`

TypeDef is the basic type definition.


```
{
    "type": "Struct",
    "name": "rdl.TypeDef",
    "comment": "TypeDef is the basic type definition.",
    "fields": [
        {
            "name": "type",
            "type": "rdl.TypeRef",
            "optional": false,
            "comment": "The type this type is derived from. For base types, it is the same as the name"
        },
        {
            "name": "name",
            "type": "rdl.TypeName",
            "optional": false,
            "comment": "The name of the type"
        },
        {
            "name": "comment",
            "type": "String",
            "optional": true,
            "comment": "The comment for the type"
        },
        {
            "name": "annotations",
            "type": "Map",
            "optional": true,
            "comment": "additional annotations starting with \"x_\"",
            "items": "String",
            "keys": "rdl.ExtendedAnnotation"
        }
    ],
    "closed": false
}
```

### rdl.AliasTypeDef `<rdl.TypeDef>`

AliasTypeDef is used for type definitions that add no additional attributes, and thus just create an alias


```
{
    "type": "rdl.TypeDef",
    "name": "rdl.AliasTypeDef",
    "comment": "AliasTypeDef is used for type definitions that add no additional attributes, and thus just create an alias",
    "fields": [],
    "closed": false
}
```

### rdl.BytesTypeDef `<rdl.TypeDef>`

Bytes allow the restriction by fixed size, or min/max size.


```
{
    "type": "rdl.TypeDef",
    "name": "rdl.BytesTypeDef",
    "comment": "Bytes allow the restriction by fixed size, or min/max size.",
    "fields": [
        {
            "name": "size",
            "type": "Int32",
            "optional": true,
            "comment": "Fixed size"
        },
        {
            "name": "minSize",
            "type": "Int32",
            "optional": true,
            "comment": "Min size"
        },
        {
            "name": "maxSize",
            "type": "Int32",
            "optional": true,
            "comment": "Max size"
        }
    ],
    "closed": false
}
```

### rdl.StringTypeDef `<rdl.TypeDef>`

Strings allow the restriction by regular expression pattern or by an explicit set of values. An optional maximum size may be asserted


```
{
    "type": "rdl.TypeDef",
    "name": "rdl.StringTypeDef",
    "comment": "Strings allow the restriction by regular expression pattern or by an explicit set of values. An optional maximum size may be asserted",
    "fields": [
        {
            "name": "pattern",
            "type": "String",
            "optional": true,
            "comment": "A regular expression that must be matched. Mutually exclusive with values"
        },
        {
            "name": "values",
            "type": "Array",
            "optional": true,
            "comment": "A set of allowable values",
            "items": "String"
        },
        {
            "name": "minSize",
            "type": "Int32",
            "optional": true,
            "comment": "Min size"
        },
        {
            "name": "maxSize",
            "type": "Int32",
            "optional": true,
            "comment": "Max size"
        }
    ],
    "closed": false
}
```

### rdl.Number `<Union>`

A numeric is any of the primitive numeric types


```
{
    "type": "Union",
    "name": "rdl.Number",
    "comment": "A numeric is any of the primitive numeric types",
    "variants": [
        "Int8",
        "Int16",
        "Int32",
        "Int64",
        "Float32",
        "Float64"
    ]
}
```

### rdl.NumberTypeDef `<rdl.TypeDef>`

A number type definition allows the restriction of numeric values.


```
{
    "type": "rdl.TypeDef",
    "name": "rdl.NumberTypeDef",
    "comment": "A number type definition allows the restriction of numeric values.",
    "fields": [
        {
            "name": "min",
            "type": "rdl.Number",
            "optional": true,
            "comment": "Min value"
        },
        {
            "name": "max",
            "type": "rdl.Number",
            "optional": true,
            "comment": "Max value"
        }
    ],
    "closed": false
}
```

### rdl.ArrayTypeDef `<rdl.TypeDef>`

Array types can be restricted by item type and size


```
{
    "type": "rdl.TypeDef",
    "name": "rdl.ArrayTypeDef",
    "comment": "Array types can be restricted by item type and size",
    "fields": [
        {
            "name": "items",
            "type": "rdl.TypeRef",
            "optional": false,
            "comment": "The type of the items, default to any type"
        },
        {
            "name": "size",
            "type": "Int32",
            "optional": true,
            "comment": "If present, indicate the fixed size."
        },
        {
            "name": "minSize",
            "type": "Int32",
            "optional": true,
            "comment": "If present, indicate the min size"
        },
        {
            "name": "maxSize",
            "type": "Int32",
            "optional": true,
            "comment": "If present, indicate the max size"
        }
    ],
    "closed": false
}
```

### rdl.MapTypeDef `<rdl.TypeDef>`

Map types can be restricted by key type, item type and size


```
{
    "type": "rdl.TypeDef",
    "name": "rdl.MapTypeDef",
    "comment": "Map types can be restricted by key type, item type and size",
    "fields": [
        {
            "name": "keys",
            "type": "rdl.TypeRef",
            "optional": false,
            "comment": "The type of the keys, default to String."
        },
        {
            "name": "items",
            "type": "rdl.TypeRef",
            "optional": false,
            "comment": "The type of the items, default to Any type"
        },
        {
            "name": "size",
            "type": "Int32",
            "optional": true,
            "comment": "If present, indicates the fixed size."
        },
        {
            "name": "minSize",
            "type": "Int32",
            "optional": true,
            "comment": "If present, indicate the min size"
        },
        {
            "name": "maxSize",
            "type": "Int32",
            "optional": true,
            "comment": "If present, indicate the max size"
        }
    ],
    "closed": false
}
```

### rdl.StructFieldDef `<Struct>`

Each field in a struct_field_spec is defined by this type


```
{
    "type": "Struct",
    "name": "rdl.StructFieldDef",
    "comment": "Each field in a struct_field_spec is defined by this type",
    "fields": [
        {
            "name": "name",
            "type": "rdl.Identifier",
            "optional": false,
            "comment": "The name of the field"
        },
        {
            "name": "type",
            "type": "rdl.TypeRef",
            "optional": false,
            "comment": "The type of the field"
        },
        {
            "name": "optional",
            "type": "Bool",
            "optional": false,
            "comment": "The field may be omitted even if specified",
            "default": false
        },
        {
            "name": "default",
            "type": "Any",
            "optional": true,
            "comment": "If field is absent, what default value should be assumed."
        },
        {
            "name": "comment",
            "type": "String",
            "optional": true,
            "comment": "The comment for the field"
        },
        {
            "name": "items",
            "type": "rdl.TypeRef",
            "optional": true,
            "comment": "For map or array fields, the type of the items"
        },
        {
            "name": "keys",
            "type": "rdl.TypeRef",
            "optional": true,
            "comment": "For map type fields, the type of the keys"
        },
        {
            "name": "annotations",
            "type": "Map",
            "optional": true,
            "comment": "additional annotations starting with \"x_\"",
            "items": "String",
            "keys": "rdl.ExtendedAnnotation"
        }
    ],
    "closed": false
}
```

### rdl.StructTypeDef `<rdl.TypeDef>`

A struct can restrict specific named fields to specific types. By default, any field not specified is allowed, and can be of any type. Specifying closed means only those fields explicitly


```
{
    "type": "rdl.TypeDef",
    "name": "rdl.StructTypeDef",
    "comment": "A struct can restrict specific named fields to specific types. By default, any field not specified is allowed, and can be of any type. Specifying closed means only those fields explicitly",
    "fields": [
        {
            "name": "fields",
            "type": "Array",
            "optional": false,
            "comment": "The fields in this struct. By default, open Structs can have any fields in addition to these",
            "items": "rdl.StructFieldDef"
        },
        {
            "name": "closed",
            "type": "Bool",
            "optional": false,
            "comment": "indicates that only the specified fields are acceptable. Default is open (any fields)",
            "default": false
        }
    ],
    "closed": false
}
```

### rdl.EnumElementDef `<Struct>`

EnumElementDef defines one of the elements of an Enum


```
{
    "type": "Struct",
    "name": "rdl.EnumElementDef",
    "comment": "EnumElementDef defines one of the elements of an Enum",
    "fields": [
        {
            "name": "symbol",
            "type": "rdl.Identifier",
            "optional": false,
            "comment": "The identifier representing the value"
        },
        {
            "name": "comment",
            "type": "String",
            "optional": true,
            "comment": "the comment for the element"
        },
        {
            "name": "annotations",
            "type": "Map",
            "optional": true,
            "comment": "additional annotations starting with \"x_\"",
            "items": "String",
            "keys": "rdl.ExtendedAnnotation"
        }
    ],
    "closed": false
}
```

### rdl.EnumTypeDef `<rdl.TypeDef>`

Define an enumerated type. Each value of the type is represented by a symbolic identifier.


```
{
    "type": "rdl.TypeDef",
    "name": "rdl.EnumTypeDef",
    "comment": "Define an enumerated type. Each value of the type is represented by a symbolic identifier.",
    "fields": [
        {
            "name": "elements",
            "type": "Array",
            "optional": false,
            "comment": "The enumeration of the possible elements",
            "items": "rdl.EnumElementDef"
        }
    ],
    "closed": false
}
```

### rdl.UnionTypeDef `<rdl.TypeDef>`

Define a type as one of any other specified type.


```
{
    "type": "rdl.TypeDef",
    "name": "rdl.UnionTypeDef",
    "comment": "Define a type as one of any other specified type.",
    "fields": [
        {
            "name": "variants",
            "type": "Array",
            "optional": false,
            "comment": "The type names of constituent types. Union types get expanded, this is a flat list",
            "items": "rdl.TypeRef"
        }
    ],
    "closed": false
}
```

### rdl.Type `<Union>`

A Type can be specified by any of the above specialized Types, determined by the value of the the 'type' field


```
{
    "type": "Union",
    "name": "rdl.Type",
    "comment": "A Type can be specified by any of the above specialized Types, determined by the value of the the 'type' field",
    "variants": [
        "rdl.BaseType",
        "rdl.StructTypeDef",
        "rdl.MapTypeDef",
        "rdl.ArrayTypeDef",
        "rdl.EnumTypeDef",
        "rdl.UnionTypeDef",
        "rdl.StringTypeDef",
        "rdl.BytesTypeDef",
        "rdl.NumberTypeDef",
        "rdl.AliasTypeDef"
    ]
}
```

### rdl.ResourceInput `<Struct>`

ResourceOutput defines input characteristics of a Resource


```
{
    "type": "Struct",
    "name": "rdl.ResourceInput",
    "comment": "ResourceOutput defines input characteristics of a Resource",
    "fields": [
        {
            "name": "name",
            "type": "rdl.Identifier",
            "optional": false,
            "comment": "the formal name of the input"
        },
        {
            "name": "type",
            "type": "rdl.TypeRef",
            "optional": false,
            "comment": "The type of the input"
        },
        {
            "name": "comment",
            "type": "String",
            "optional": true,
            "comment": "The optional comment"
        },
        {
            "name": "pathParam",
            "type": "Bool",
            "optional": false,
            "comment": "true of this input is a path parameter",
            "default": false
        },
        {
            "name": "queryParam",
            "type": "String",
            "optional": true,
            "comment": "if present, the name of the query param name"
        },
        {
            "name": "header",
            "type": "String",
            "optional": true,
            "comment": "If present, the name of the header the input is associated with"
        },
        {
            "name": "pattern",
            "type": "String",
            "optional": true,
            "comment": "If present, the pattern associated with the pathParam (i.e. wildcard path matches)"
        },
        {
            "name": "default",
            "type": "Any",
            "optional": true,
            "comment": "If present, the default value for optional params"
        },
        {
            "name": "optional",
            "type": "Bool",
            "optional": false,
            "comment": "If present, indicates that the input is optional",
            "default": false
        },
        {
            "name": "flag",
            "type": "Bool",
            "optional": false,
            "comment": "If present, indicates the queryparam is of flag style (no value)",
            "default": false
        },
        {
            "name": "context",
            "type": "String",
            "optional": true,
            "comment": "If present, indicates the parameter comes form the implementation context"
        },
        {
            "name": "annotations",
            "type": "Map",
            "optional": true,
            "comment": "additional annotations starting with \"x_\"",
            "items": "String",
            "keys": "rdl.ExtendedAnnotation"
        }
    ],
    "closed": false
}
```

### rdl.ResourceOutput `<Struct>`

ResourceOutput defines output characteristics of a Resource


```
{
    "type": "Struct",
    "name": "rdl.ResourceOutput",
    "comment": "ResourceOutput defines output characteristics of a Resource",
    "fields": [
        {
            "name": "name",
            "type": "rdl.Identifier",
            "optional": false,
            "comment": "the formal name of the output"
        },
        {
            "name": "type",
            "type": "rdl.TypeRef",
            "optional": false,
            "comment": "The type of the output"
        },
        {
            "name": "header",
            "type": "String",
            "optional": false,
            "comment": "the name of the header associated with this output"
        },
        {
            "name": "comment",
            "type": "String",
            "optional": true,
            "comment": "The optional comment for the output"
        },
        {
            "name": "optional",
            "type": "Bool",
            "optional": false,
            "comment": "If present, indicates that the output is optional (the server decides)",
            "default": false
        },
        {
            "name": "annotations",
            "type": "Map",
            "optional": true,
            "comment": "additional annotations starting with \"x_\"",
            "items": "String",
            "keys": "rdl.ExtendedAnnotation"
        }
    ],
    "closed": false
}
```

### rdl.ResourceAuth `<Struct>`

ResourceAuth defines authentication and authorization attributes of a resource. Presence of action, resource, or domain implies authentication; the authentication flag alone is required only when no authorization is done.


```
{
    "type": "Struct",
    "name": "rdl.ResourceAuth",
    "comment": "ResourceAuth defines authentication and authorization attributes of a resource. Presence of action, resource, or domain implies authentication; the authentication flag alone is required only when no authorization is done.",
    "fields": [
        {
            "name": "authenticate",
            "type": "Bool",
            "optional": false,
            "comment": "if present and true, then the requester must be authenticated",
            "default": false
        },
        {
            "name": "action",
            "type": "String",
            "optional": true,
            "comment": "the action to authorize access to. This forces authentication"
        },
        {
            "name": "resource",
            "type": "String",
            "optional": true,
            "comment": "the resource identity to authorize access to"
        },
        {
            "name": "domain",
            "type": "String",
            "optional": true,
            "comment": "if present, the alternate domain to check access to. This is rare."
        }
    ],
    "closed": false
}
```

### rdl.ExceptionDef `<Struct>`

ExceptionDef describes the exception a symbolic response code maps to.


```
{
    "type": "Struct",
    "name": "rdl.ExceptionDef",
    "comment": "ExceptionDef describes the exception a symbolic response code maps to.",
    "fields": [
        {
            "name": "type",
            "type": "String",
            "optional": false,
            "comment": "The type of the exception"
        },
        {
            "name": "comment",
            "type": "String",
            "optional": true,
            "comment": "the optional comment for the exception"
        }
    ],
    "closed": false
}
```

### rdl.Resource `<Struct>`

A Resource of a REST service


```
{
    "type": "Struct",
    "name": "rdl.Resource",
    "comment": "A Resource of a REST service",
    "fields": [
        {
            "name": "type",
            "type": "rdl.TypeRef",
            "optional": false,
            "comment": "The type of the resource"
        },
        {
            "name": "method",
            "type": "String",
            "optional": false,
            "comment": "The method for the action (typically GET, POST, etc for HTTP access)"
        },
        {
            "name": "path",
            "type": "String",
            "optional": false,
            "comment": "The resource path template"
        },
        {
            "name": "comment",
            "type": "String",
            "optional": true,
            "comment": "The optional comment"
        },
        {
            "name": "inputs",
            "type": "Array",
            "optional": true,
            "comment": "An Array named inputs",
            "items": "rdl.ResourceInput"
        },
        {
            "name": "outputs",
            "type": "Array",
            "optional": true,
            "comment": "An Array of named outputs",
            "items": "rdl.ResourceOutput"
        },
        {
            "name": "auth",
            "type": "rdl.ResourceAuth",
            "optional": true,
            "comment": "The optional authentication or authorization directive"
        },
        {
            "name": "expected",
            "type": "String",
            "optional": false,
            "comment": "The expected symbolic response code",
            "default": "OK"
        },
        {
            "name": "alternatives",
            "type": "Array",
            "optional": true,
            "comment": "The set of alternative but non-error response codes",
            "items": "String"
        },
        {
            "name": "exceptions",
            "type": "Map",
            "optional": true,
            "comment": "A map of symbolic response code to Exception definitions",
            "items": "rdl.ExceptionDef",
            "keys": "String"
        },
        {
            "name": "async",
            "type": "Bool",
            "optional": true,
            "comment": "A hint to server implementations that this resource would be better implemented with async I/O"
        },
        {
            "name": "annotations",
            "type": "Map",
            "optional": true,
            "comment": "additional annotations starting with \"x_\"",
            "items": "String",
            "keys": "rdl.ExtendedAnnotation"
        },
        {
            "name": "consumes",
            "type": "Array",
            "optional": true,
            "comment": "Optional hint for resource acceptable input types",
            "items": "String"
        },
        {
            "name": "produces",
            "type": "Array",
            "optional": true,
            "comment": "Optional hint for resource output content types",
            "items": "String"
        },
        {
            "name": "name",
            "type": "rdl.Identifier",
            "optional": true,
            "comment": "The optional name of the resource"
        }
    ],
    "closed": false
}
```

### rdl.Schema `<Struct>`

A Schema is a container for types and resources. It is self-contained (no external references). and is the output of the RDL parser.


```
{
    "type": "Struct",
    "name": "rdl.Schema",
    "comment": "A Schema is a container for types and resources. It is self-contained (no external references). and is the output of the RDL parser.",
    "fields": [
        {
            "name": "namespace",
            "type": "rdl.NamespacedIdentifier",
            "optional": true,
            "comment": "The namespace for the schema"
        },
        {
            "name": "name",
            "type": "rdl.Identifier",
            "optional": true,
            "comment": "The name of the schema"
        },
        {
            "name": "version",
            "type": "Int32",
            "optional": true,
            "comment": "The version of the schema"
        },
        {
            "name": "comment",
            "type": "String",
            "optional": true,
            "comment": "The comment for the entire schema"
        },
        {
            "name": "types",
            "type": "Array",
            "optional": true,
            "comment": "The types this schema defines.",
            "items": "rdl.Type"
        },
        {
            "name": "resources",
            "type": "Array",
            "optional": true,
            "comment": "The resources for a service this schema defines",
            "items": "rdl.Resource"
        },
        {
            "name": "base",
            "type": "String",
            "optional": true,
            "comment": "the base path for resources in the schema."
        },
        {
            "name": "annotations",
            "type": "Map",
            "optional": true,
            "comment": "additional annotations starting with \"x_\"",
            "items": "String",
            "keys": "rdl.ExtendedAnnotation"
        }
    ],
    "closed": false
}
```


*generated on Wed Sep 27 2023 11:23:44 GMT-0700 (Pacific Daylight Time)*