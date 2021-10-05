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
            "type": "DomainName",
            "optional": false,
            "comment": "Name of the domain"
        },
        {
            "name": "serviceName",
            "type": "EntityName",
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
        }
    ],
    "closed": false
}
```

### TransportPolicyPort `<Struct>`

Transport policy port


```
{
    "type": "Struct",
    "name": "TransportPolicyPort",
    "comment": "Transport policy port",
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
        },
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
            "comment": "Describes the entity to which this transport policy applies"
        },
        {
            "name": "from",
            "type": "TransportPolicyPeer",
            "optional": false,
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
            "optional": false,
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
            "optional": false,
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


*generated on Mon Oct 04 2021 21:08:20 GMT-0700 (Pacific Daylight Time)*