var ztsspec = {
  "openapi" : "3.0.1",
  "info" : {
    "title" : "ZTS Swagger",
    "version" : "1.0.0"
  },
  "servers" : [ {
    "url" : "/v1/api"
  } ],
  "paths" : {
    "/v1/instance/{provider}/{domain}/{service}/{instanceId}" : {
      "post" : {
        "description" : "Refresh the given service instance and issue a new x.509 service identity certificate once the provider validates the attestation data along with the request attributes. only TLS Certificate authentication is allowed",
        "operationId" : "postInstanceRefreshInformation",
        "parameters" : [ {
          "name" : "provider",
          "in" : "path",
          "description" : "the provider service name (i.e. \"aws.us-west-2\", \"aws.us-east-1\")",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "domain",
          "in" : "path",
          "description" : "the domain of the instance",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "service",
          "in" : "path",
          "description" : "the service this instance is supposed to run",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "instanceId",
          "in" : "path",
          "description" : "unique instance id within provider's namespace",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "the refresh request",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/InstanceRefreshInformation"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/InstanceIdentity"
                }
              }
            }
          }
        }
      },
      "delete" : {
        "description" : "Delete the given service instance certificate record thus blocking any future refresh requests from the given instance for this service There are two possible authorization checks for this endpoint: 1) domain admin: authorize(\"delete\", \"{domain}:instance.{instanceId}\") the authorized user can remove the instance record from the datastore 2) provider itself: if the identity of the caller is the provider itself then the provider is notifying ZTS that the instance was deleted",
        "operationId" : "deleteInstanceIdentity",
        "parameters" : [ {
          "name" : "provider",
          "in" : "path",
          "description" : "the provider service name (i.e. \"aws.us-west-2\", \"aws.us-east-1\")",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "domain",
          "in" : "path",
          "description" : "the domain of the instance",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "service",
          "in" : "path",
          "description" : "the service this instance is supposed to run",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "instanceId",
          "in" : "path",
          "description" : "unique instance id within provider's namespace",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/role/{role}/creds" : {
      "get" : {
        "description" : "perform an AWS AssumeRole of the target role and return the credentials. ZTS must have been granted the ability to assume the role in IAM, and granted the ability to assume_aws_role in Athenz for this to succeed.",
        "operationId" : "getAWSTemporaryCredentials",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain containing the role, which implies the target account",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "role",
          "in" : "path",
          "description" : "the target AWS role name in the domain account, in Athenz terms, i.e. \"the.role\"",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "durationSeconds",
          "in" : "query",
          "description" : "how long the aws temp creds should be issued for",
          "schema" : {
            "type" : "integer",
            "format" : "int32"
          }
        }, {
          "name" : "externalId",
          "in" : "query",
          "description" : "aws assume role external id",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/AWSTemporaryCredentials"
                }
              }
            }
          }
        }
      }
    },
    "/v1/access/domain/{domainName}/role/{roleName}/principal/{principal}" : {
      "get" : {
        "operationId" : "getAccess",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "roleName",
          "in" : "path",
          "description" : "name of the role to check access for",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "principal",
          "in" : "path",
          "description" : "carry out the access check for this principal",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Access"
                }
              }
            }
          }
        }
      }
    },
    "/v1/cacerts/{name}" : {
      "get" : {
        "description" : "Return the request CA X.509 Certificate bundle",
        "operationId" : "getCertificateAuthorityBundle",
        "parameters" : [ {
          "name" : "name",
          "in" : "path",
          "description" : "name of the CA cert bundle",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/CertificateAuthorityBundle"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/signed_policy_data" : {
      "get" : {
        "description" : "Get a signed policy enumeration from the service, to transfer to a local store. An ETag is generated for the PolicyList that changes when any item in the list changes. If the If-None-Match header is provided, and it matches the ETag that would be returned, then a NOT_MODIFIED response is returned instead of the list.",
        "operationId" : "getDomainSignedPolicyData",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "If-None-Match",
          "in" : "header",
          "description" : "Retrieved from the previous request, this timestamp specifies to the server to return any policies modified since this time",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/host/{host}/services" : {
      "get" : {
        "description" : "Enumerate services provisioned on a specific host",
        "operationId" : "getHostServices",
        "parameters" : [ {
          "name" : "host",
          "in" : "path",
          "description" : "name of the host",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/HostServices"
                }
              }
            }
          }
        }
      }
    },
    "/v1/instance/{provider}/{domain}/{service}/{instanceId}/token" : {
      "get" : {
        "description" : "Request a token for the given service to be bootstrapped for the given provider. The caller must have authorization to manage the service in the given domain. The token will be valid for 30 mins for one time use only for the initial registration. The token must be sent back in the register request as the value of the attestationData field in the InstanceRegisterInformation object",
        "operationId" : "getInstanceRegisterToken",
        "parameters" : [ {
          "name" : "provider",
          "in" : "path",
          "description" : "the provider service name (i.e. \"aws.us-west-2\")",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "domain",
          "in" : "path",
          "description" : "the domain of the instance",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "service",
          "in" : "path",
          "description" : "the service this instance is supposed to run",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "instanceId",
          "in" : "path",
          "description" : "unique instance id within provider's namespace",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/InstanceRegisterToken"
                }
              }
            }
          }
        }
      }
    },
    "/v1/oauth2/keys" : {
      "get" : {
        "operationId" : "getJWKList",
        "parameters" : [ {
          "name" : "rfc",
          "in" : "query",
          "description" : "flag to indicate ec curve names are restricted to RFC values",
          "schema" : {
            "type" : "boolean",
            "default" : false
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/JWKList"
                }
              }
            }
          }
        }
      }
    },
    "/v1/.well-known/openid-configuration" : {
      "get" : {
        "operationId" : "getOpenIDConfig",
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/OpenIDConfig"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/service/{serviceName}/publickey/{keyId}" : {
      "get" : {
        "description" : "Retrieve the specified public key from the service.",
        "operationId" : "getPublicKeyEntry",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "serviceName",
          "in" : "path",
          "description" : "name of the service",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "keyId",
          "in" : "path",
          "description" : "the identifier of the public key to be retrieved",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/PublicKeyEntry"
                }
              }
            }
          }
        }
      }
    },
    "/v1/schema" : {
      "get" : {
        "description" : "Get RDL Schema",
        "operationId" : "getRdlSchema",
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Schema"
                }
              }
            }
          }
        }
      }
    },
    "/v1/access/{action}/{resource}" : {
      "get" : {
        "description" : "Check access for the specified operation on the specified resource for the currently authenticated user. This is the slow centralized access for control-plane purposes. Use distributed mechanisms for decentralized (data-plane) access by fetching signed policies and role tokens for users. With this endpoint the resource is part of the uri and restricted to its strict definition of resource name. If needed, you can use the GetAccessExt api that allows resource name to be less restrictive.",
        "operationId" : "getResourceAccess",
        "parameters" : [ {
          "name" : "action",
          "in" : "path",
          "description" : "action as specified in the policy assertion, i.e. update or read",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "resource",
          "in" : "path",
          "description" : "the resource to check access against, i.e. \"media.news:articles\"",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "domain",
          "in" : "query",
          "description" : "usually null. If present, it specifies an alternate domain for cross-domain trust relation",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "principal",
          "in" : "query",
          "description" : "usually null. If present, carry out the access check for this principal",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/ResourceAccess"
                }
              }
            }
          }
        }
      }
    },
    "/v1/access/{action}" : {
      "get" : {
        "description" : "Check access for the specified operation on the specified resource for the currently authenticated user. This is the slow centralized access for control-plane purposes.",
        "operationId" : "getResourceAccessExt",
        "parameters" : [ {
          "name" : "action",
          "in" : "path",
          "description" : "action as specified in the policy assertion, i.e. update or read",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "resource",
          "in" : "query",
          "description" : "the resource to check access against, i.e. \"media.news:articles\"",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "domain",
          "in" : "query",
          "description" : "usually null. If present, it specifies an alternate domain for cross-domain trust relation",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "principal",
          "in" : "query",
          "description" : "usually null. If present, carry out the access check for this principal",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/ResourceAccess"
                }
              }
            }
          }
        }
      }
    },
    "/v1/access/domain/{domainName}/principal/{principal}" : {
      "get" : {
        "operationId" : "getRoleAccess",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "principal",
          "in" : "path",
          "description" : "carry out the role access lookup for this principal",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/RoleAccess"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/token" : {
      "get" : {
        "description" : "Return a security token for the specific role in the namespace that the principal can assume. If the role is omitted, then all roles in the namespace that the authenticated user can assume are returned. the caller can specify how long the RoleToken should be valid for by specifying the minExpiryTime and maxExpiryTime parameters. The minExpiryTime specifies that the returned RoleToken must be at least valid (min/lower bound) for specified number of seconds, while maxExpiryTime specifies that the RoleToken must be at most valid (max/upper bound) for specified number of seconds. If both values are the same, the server must return a RoleToken for that many seconds. If no values are specified, the server's default RoleToken Timeout value is used.",
        "operationId" : "getRoleToken",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "role",
          "in" : "query",
          "description" : "only interested for a token for these comma separated roles",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "minExpiryTime",
          "in" : "query",
          "description" : "in seconds min expiry time",
          "schema" : {
            "type" : "integer",
            "format" : "int32"
          }
        }, {
          "name" : "maxExpiryTime",
          "in" : "query",
          "description" : "in seconds max expiry time",
          "schema" : {
            "type" : "integer",
            "format" : "int32"
          }
        }, {
          "name" : "proxyForPrincipal",
          "in" : "query",
          "description" : "optional this request is proxy for this principal",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/RoleToken"
                }
              }
            }
          }
        }
      }
    },
    "/v1/role/cert" : {
      "get" : {
        "description" : "Fetch all roles that are tagged as requiring role certificates for principal",
        "operationId" : "getRolesRequireRoleCert",
        "parameters" : [ {
          "name" : "principal",
          "in" : "query",
          "description" : "If not present, will return roles for the user making the call",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/RoleAccess"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/service/{serviceName}" : {
      "get" : {
        "description" : "Get info for the specified ServiceIdentity.",
        "operationId" : "getServiceIdentity",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "serviceName",
          "in" : "path",
          "description" : "name of the service to be retrieved",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/ServiceIdentity"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/service" : {
      "get" : {
        "description" : "Enumerate services provisioned in this domain.",
        "operationId" : "getServiceIdentityList",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/ServiceIdentityList"
                }
              }
            }
          }
        }
      }
    },
    "/v1/status" : {
      "get" : {
        "description" : "Retrieve the server status",
        "operationId" : "getStatus",
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Status"
                }
              }
            }
          }
        }
      }
    },
    "/v1/providerdomain/{providerDomainName}/user/{userName}" : {
      "get" : {
        "description" : "Get list of tenant domains user has access to for specified provider domain and service",
        "operationId" : "getTenantDomains",
        "parameters" : [ {
          "name" : "providerDomainName",
          "in" : "path",
          "description" : "name of the provider domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "userName",
          "in" : "path",
          "description" : "name of the user to retrieve tenant domain access for",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "roleName",
          "in" : "query",
          "description" : "role name to filter on when looking for the tenants in provider",
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "serviceName",
          "in" : "query",
          "description" : "service name to filter on when looking for the tenants in provider",
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/TenantDomains"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/service/{serviceName}/transportRules" : {
      "get" : {
        "operationId" : "getTransportRules",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "serviceName",
          "in" : "path",
          "description" : "name of the service",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/TransportRules"
                }
              }
            }
          }
        }
      }
    },
    "/v1/workloads/{ip}" : {
      "get" : {
        "operationId" : "getWorkloadsByIP",
        "parameters" : [ {
          "name" : "ip",
          "in" : "path",
          "description" : "ip address to query",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Workloads"
                }
              }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/service/{serviceName}/workloads" : {
      "get" : {
        "operationId" : "getWorkloadsByService",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "serviceName",
          "in" : "path",
          "description" : "name of the service",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Workloads"
                }
              }
            }
          }
        }
      }
    },
    "/v1/oauth2/token" : {
      "post" : {
        "operationId" : "postAccessTokenRequest",
        "requestBody" : {
          "content" : {
            "application/x-www-form-urlencoded" : {
              "schema" : {
                "type" : "string"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/AccessTokenResponse"
                }
              }
            }
          }
        }
      }
    },
    "/v1/instance/{domain}/{service}/refresh" : {
      "post" : {
        "description" : "Refresh Service tokens into TLS Certificate",
        "operationId" : "postInstanceRefreshRequest",
        "parameters" : [ {
          "name" : "domain",
          "in" : "path",
          "description" : "name of the domain requesting the refresh",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "service",
          "in" : "path",
          "description" : "name of the service requesting the refresh",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "the refresh request",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/InstanceRefreshRequest"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/Identity"
                }
              }
            }
          }
        }
      }
    },
    "/v1/instance" : {
      "post" : {
        "description" : "Register a new service instance and issue an x.509 service identity certificate once the provider validates the attestation data along with the request attributes. We have an authenticate enabled for this endpoint but in most cases the service owner might need to make it optional by setting the zts servers no_auth_uri list to include this endpoint. We need the authenticate in case the request comes with a client certificate and the provider needs to know who that principal was in the client certificate",
        "operationId" : "postInstanceRegisterInformation",
        "requestBody" : {
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/InstanceRegisterInformation"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/role/{roleName}/token" : {
      "post" : {
        "description" : "Return a TLS certificate for the specific role in the namespace that the principal can assume. Role certificates are valid for 30 days by default. This is deprecated and \"POST /rolecert\" api should be used instead.",
        "operationId" : "postRoleCertificateRequest",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "roleName",
          "in" : "path",
          "description" : "name of role",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "csr request",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/RoleCertificateRequest"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/RoleToken"
                }
              }
            }
          }
        }
      }
    },
    "/v1/rolecert" : {
      "post" : {
        "description" : "Return a TLS certificate for a role that the principal can assume. The role arn is in the CN field of the Subject and the principal is in the SAN URI field.",
        "operationId" : "postRoleCertificateRequestExt",
        "requestBody" : {
          "description" : "csr request",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/RoleCertificateRequest"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/RoleCertificate"
                }
              }
            }
          }
        }
      }
    },
    "/v1/sshcert" : {
      "post" : {
        "operationId" : "postSSHCertRequest",
        "requestBody" : {
          "description" : "ssh certificate request",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/SSHCertRequest"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/v1/domain/{domainName}/policy/signed" : {
      "post" : {
        "description" : "Get a signed policy enumeration from the service, to transfer to a local store. An ETag is generated for the PolicyList that changes when any item in the list changes. If the If-None-Match header is provided, and it matches the ETag that would be returned, then a NOT_MODIFIED response is returned instead of the list.",
        "operationId" : "postSignedPolicyRequest",
        "parameters" : [ {
          "name" : "domainName",
          "in" : "path",
          "description" : "name of the domain",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        }, {
          "name" : "If-None-Match",
          "in" : "header",
          "description" : "Retrieved from the previous request, this timestamp specifies to the server to return any policies modified since this time",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "requestBody" : {
          "description" : "policy version request details",
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/SignedPolicyRequest"
              }
            }
          },
          "required" : true
        },
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/json" : { }
            }
          }
        }
      }
    },
    "/application.wadl/{path}" : {
      "get" : {
        "operationId" : "getExternalGrammar",
        "parameters" : [ {
          "name" : "path",
          "in" : "path",
          "required" : true,
          "schema" : {
            "type" : "string"
          }
        } ],
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/xml" : { }
            }
          }
        }
      }
    },
    "/application.wadl" : {
      "get" : {
        "operationId" : "getWadl",
        "responses" : {
          "default" : {
            "description" : "default response",
            "content" : {
              "application/vnd.sun.wadl+xml" : { },
              "application/xml" : { }
            }
          }
        }
      }
    }
  },
  "components" : {
    "schemas" : {
      "AWSTemporaryCredentials" : {
        "type" : "object",
        "properties" : {
          "accessKeyId" : {
            "type" : "string"
          },
          "secretAccessKey" : {
            "type" : "string"
          },
          "sessionToken" : {
            "type" : "string"
          },
          "expiration" : {
            "$ref" : "#/components/schemas/Timestamp"
          }
        }
      },
      "Timestamp" : {
        "type" : "object"
      },
      "Access" : {
        "type" : "object",
        "properties" : {
          "granted" : {
            "type" : "boolean"
          }
        }
      },
      "CertificateAuthorityBundle" : {
        "type" : "object",
        "properties" : {
          "name" : {
            "type" : "string"
          },
          "certs" : {
            "type" : "string"
          }
        }
      },
      "HostServices" : {
        "type" : "object",
        "properties" : {
          "host" : {
            "type" : "string"
          },
          "names" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          }
        }
      },
      "InstanceRegisterToken" : {
        "type" : "object",
        "properties" : {
          "provider" : {
            "type" : "string"
          },
          "domain" : {
            "type" : "string"
          },
          "service" : {
            "type" : "string"
          },
          "attestationData" : {
            "type" : "string"
          },
          "attributes" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          }
        }
      },
      "JWK" : {
        "type" : "object",
        "properties" : {
          "kty" : {
            "type" : "string"
          },
          "kid" : {
            "type" : "string"
          },
          "alg" : {
            "type" : "string"
          },
          "use" : {
            "type" : "string"
          },
          "crv" : {
            "type" : "string"
          },
          "x" : {
            "type" : "string"
          },
          "y" : {
            "type" : "string"
          },
          "n" : {
            "type" : "string"
          },
          "e" : {
            "type" : "string"
          }
        }
      },
      "JWKList" : {
        "type" : "object",
        "properties" : {
          "keys" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/JWK"
            }
          }
        }
      },
      "OpenIDConfig" : {
        "type" : "object",
        "properties" : {
          "issuer" : {
            "type" : "string"
          },
          "authorization_endpoint" : {
            "type" : "string"
          },
          "jwks_uri" : {
            "type" : "string"
          },
          "response_types_supported" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "subject_types_supported" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "id_token_signing_alg_values_supported" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "claims_supported" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          }
        }
      },
      "PublicKeyEntry" : {
        "type" : "object",
        "properties" : {
          "key" : {
            "type" : "string"
          },
          "id" : {
            "type" : "string"
          }
        }
      },
      "AliasTypeDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          }
        }
      },
      "ArrayTypeDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "items" : {
            "type" : "string"
          },
          "size" : {
            "type" : "integer",
            "format" : "int32"
          },
          "minSize" : {
            "type" : "integer",
            "format" : "int32"
          },
          "maxSize" : {
            "type" : "integer",
            "format" : "int32"
          }
        }
      },
      "BytesTypeDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "size" : {
            "type" : "integer",
            "format" : "int32"
          },
          "minSize" : {
            "type" : "integer",
            "format" : "int32"
          },
          "maxSize" : {
            "type" : "integer",
            "format" : "int32"
          }
        }
      },
      "EnumElementDef" : {
        "type" : "object",
        "properties" : {
          "symbol" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          }
        }
      },
      "EnumTypeDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "elements" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/EnumElementDef"
            }
          }
        }
      },
      "ExceptionDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          }
        }
      },
      "MapTypeDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "keys" : {
            "type" : "string"
          },
          "items" : {
            "type" : "string"
          },
          "size" : {
            "type" : "integer",
            "format" : "int32"
          },
          "minSize" : {
            "type" : "integer",
            "format" : "int32"
          },
          "maxSize" : {
            "type" : "integer",
            "format" : "int32"
          }
        }
      },
      "Number" : {
        "type" : "object",
        "properties" : {
          "Int8" : {
            "type" : "string",
            "format" : "byte"
          },
          "Int16" : {
            "type" : "integer",
            "format" : "int32"
          },
          "Int32" : {
            "type" : "integer",
            "format" : "int32"
          },
          "Int64" : {
            "type" : "integer",
            "format" : "int64"
          },
          "Float32" : {
            "type" : "number",
            "format" : "float"
          },
          "Float64" : {
            "type" : "number",
            "format" : "double"
          }
        }
      },
      "NumberTypeDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "min" : {
            "$ref" : "#/components/schemas/Number"
          },
          "max" : {
            "$ref" : "#/components/schemas/Number"
          }
        }
      },
      "Resource" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "method" : {
            "type" : "string"
          },
          "path" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "inputs" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/ResourceInput"
            }
          },
          "outputs" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/ResourceOutput"
            }
          },
          "auth" : {
            "$ref" : "#/components/schemas/ResourceAuth"
          },
          "expected" : {
            "type" : "string"
          },
          "alternatives" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "exceptions" : {
            "type" : "object",
            "additionalProperties" : {
              "$ref" : "#/components/schemas/ExceptionDef"
            }
          },
          "async" : {
            "type" : "boolean"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "consumes" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "produces" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "name" : {
            "type" : "string"
          }
        }
      },
      "ResourceAuth" : {
        "type" : "object",
        "properties" : {
          "authenticate" : {
            "type" : "boolean"
          },
          "action" : {
            "type" : "string"
          },
          "resource" : {
            "type" : "string"
          },
          "domain" : {
            "type" : "string"
          }
        }
      },
      "ResourceInput" : {
        "type" : "object",
        "properties" : {
          "name" : {
            "type" : "string"
          },
          "type" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "pathParam" : {
            "type" : "boolean"
          },
          "queryParam" : {
            "type" : "string"
          },
          "header" : {
            "type" : "string"
          },
          "pattern" : {
            "type" : "string"
          },
          "optional" : {
            "type" : "boolean"
          },
          "flag" : {
            "type" : "boolean"
          },
          "context" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "default" : {
            "type" : "object"
          }
        }
      },
      "ResourceOutput" : {
        "type" : "object",
        "properties" : {
          "name" : {
            "type" : "string"
          },
          "type" : {
            "type" : "string"
          },
          "header" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "optional" : {
            "type" : "boolean"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          }
        }
      },
      "Schema" : {
        "type" : "object",
        "properties" : {
          "namespace" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "version" : {
            "type" : "integer",
            "format" : "int32"
          },
          "comment" : {
            "type" : "string"
          },
          "types" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/Type"
            }
          },
          "resources" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/Resource"
            }
          },
          "base" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          }
        }
      },
      "StringTypeDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "pattern" : {
            "type" : "string"
          },
          "values" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "minSize" : {
            "type" : "integer",
            "format" : "int32"
          },
          "maxSize" : {
            "type" : "integer",
            "format" : "int32"
          }
        }
      },
      "StructFieldDef" : {
        "type" : "object",
        "properties" : {
          "name" : {
            "type" : "string"
          },
          "type" : {
            "type" : "string"
          },
          "optional" : {
            "type" : "boolean"
          },
          "comment" : {
            "type" : "string"
          },
          "items" : {
            "type" : "string"
          },
          "keys" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "default" : {
            "type" : "object"
          }
        }
      },
      "StructTypeDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "fields" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/StructFieldDef"
            }
          },
          "closed" : {
            "type" : "boolean"
          }
        }
      },
      "Type" : {
        "type" : "object",
        "properties" : {
          "BaseType" : {
            "type" : "string",
            "enum" : [ "Bool", "Int8", "Int16", "Int32", "Int64", "Float32", "Float64", "Bytes", "String", "Timestamp", "Symbol", "UUID", "Array", "Map", "Struct", "Enum", "Union", "Any" ]
          },
          "StructTypeDef" : {
            "$ref" : "#/components/schemas/StructTypeDef"
          },
          "MapTypeDef" : {
            "$ref" : "#/components/schemas/MapTypeDef"
          },
          "ArrayTypeDef" : {
            "$ref" : "#/components/schemas/ArrayTypeDef"
          },
          "EnumTypeDef" : {
            "$ref" : "#/components/schemas/EnumTypeDef"
          },
          "UnionTypeDef" : {
            "$ref" : "#/components/schemas/UnionTypeDef"
          },
          "StringTypeDef" : {
            "$ref" : "#/components/schemas/StringTypeDef"
          },
          "BytesTypeDef" : {
            "$ref" : "#/components/schemas/BytesTypeDef"
          },
          "NumberTypeDef" : {
            "$ref" : "#/components/schemas/NumberTypeDef"
          },
          "AliasTypeDef" : {
            "$ref" : "#/components/schemas/AliasTypeDef"
          }
        }
      },
      "UnionTypeDef" : {
        "type" : "object",
        "properties" : {
          "type" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "comment" : {
            "type" : "string"
          },
          "annotations" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "variants" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          }
        }
      },
      "ResourceAccess" : {
        "type" : "object",
        "properties" : {
          "granted" : {
            "type" : "boolean"
          }
        }
      },
      "RoleAccess" : {
        "type" : "object",
        "properties" : {
          "roles" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          }
        }
      },
      "RoleToken" : {
        "type" : "object",
        "properties" : {
          "token" : {
            "type" : "string"
          },
          "expiryTime" : {
            "type" : "integer",
            "format" : "int64"
          }
        }
      },
      "ServiceIdentity" : {
        "type" : "object",
        "properties" : {
          "name" : {
            "type" : "string"
          },
          "publicKeys" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/PublicKeyEntry"
            }
          },
          "providerEndpoint" : {
            "type" : "string"
          },
          "modified" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "executable" : {
            "type" : "string"
          },
          "hosts" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "user" : {
            "type" : "string"
          },
          "group" : {
            "type" : "string"
          }
        }
      },
      "ServiceIdentityList" : {
        "type" : "object",
        "properties" : {
          "names" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          }
        }
      },
      "Status" : {
        "type" : "object",
        "properties" : {
          "code" : {
            "type" : "integer",
            "format" : "int32"
          },
          "message" : {
            "type" : "string"
          }
        }
      },
      "TenantDomains" : {
        "type" : "object",
        "properties" : {
          "tenantDomainNames" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          }
        }
      },
      "TransportRule" : {
        "type" : "object",
        "properties" : {
          "endPoint" : {
            "type" : "string"
          },
          "sourcePortRange" : {
            "type" : "string"
          },
          "port" : {
            "type" : "integer",
            "format" : "int32"
          },
          "protocol" : {
            "type" : "string"
          },
          "direction" : {
            "type" : "string",
            "enum" : [ "IN", "OUT" ]
          }
        }
      },
      "TransportRules" : {
        "type" : "object",
        "properties" : {
          "ingressRules" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/TransportRule"
            }
          },
          "egressRules" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/TransportRule"
            }
          }
        }
      },
      "Workload" : {
        "type" : "object",
        "properties" : {
          "domainName" : {
            "type" : "string"
          },
          "serviceName" : {
            "type" : "string"
          },
          "uuid" : {
            "type" : "string"
          },
          "ipAddresses" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "hostname" : {
            "type" : "string"
          },
          "provider" : {
            "type" : "string"
          },
          "updateTime" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "certExpiryTime" : {
            "$ref" : "#/components/schemas/Timestamp"
          }
        }
      },
      "Workloads" : {
        "type" : "object",
        "properties" : {
          "workloadList" : {
            "type" : "array",
            "items" : {
              "$ref" : "#/components/schemas/Workload"
            }
          }
        }
      },
      "AccessTokenResponse" : {
        "type" : "object",
        "properties" : {
          "access_token" : {
            "type" : "string"
          },
          "token_type" : {
            "type" : "string"
          },
          "expires_in" : {
            "type" : "integer",
            "format" : "int32"
          },
          "scope" : {
            "type" : "string"
          },
          "refresh_token" : {
            "type" : "string"
          },
          "id_token" : {
            "type" : "string"
          }
        }
      },
      "InstanceIdentity" : {
        "type" : "object",
        "properties" : {
          "provider" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "instanceId" : {
            "type" : "string"
          },
          "x509Certificate" : {
            "type" : "string"
          },
          "x509CertificateSigner" : {
            "type" : "string"
          },
          "sshCertificate" : {
            "type" : "string"
          },
          "sshCertificateSigner" : {
            "type" : "string"
          },
          "serviceToken" : {
            "type" : "string"
          },
          "attributes" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          }
        }
      },
      "InstanceRefreshInformation" : {
        "type" : "object",
        "properties" : {
          "attestationData" : {
            "type" : "string"
          },
          "csr" : {
            "type" : "string"
          },
          "ssh" : {
            "type" : "string"
          },
          "sshCertRequest" : {
            "$ref" : "#/components/schemas/SSHCertRequest"
          },
          "token" : {
            "type" : "boolean"
          },
          "expiryTime" : {
            "type" : "integer",
            "format" : "int32"
          },
          "hostname" : {
            "type" : "string"
          },
          "hostCnames" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          }
        }
      },
      "SSHCertRequest" : {
        "type" : "object",
        "properties" : {
          "certRequestData" : {
            "$ref" : "#/components/schemas/SSHCertRequestData"
          },
          "certRequestMeta" : {
            "$ref" : "#/components/schemas/SSHCertRequestMeta"
          },
          "csr" : {
            "type" : "string"
          }
        }
      },
      "SSHCertRequestData" : {
        "type" : "object",
        "properties" : {
          "principals" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "sources" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "destinations" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "publicKey" : {
            "type" : "string"
          },
          "touchPublicKey" : {
            "type" : "string"
          },
          "caPubKeyAlgo" : {
            "type" : "integer",
            "format" : "int32"
          },
          "command" : {
            "type" : "string"
          }
        }
      },
      "SSHCertRequestMeta" : {
        "type" : "object",
        "properties" : {
          "requestor" : {
            "type" : "string"
          },
          "origin" : {
            "type" : "string"
          },
          "clientInfo" : {
            "type" : "string"
          },
          "sshClientVersion" : {
            "type" : "string"
          },
          "certType" : {
            "type" : "string"
          },
          "keyIdPrincipals" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          },
          "athenzService" : {
            "type" : "string"
          },
          "instanceId" : {
            "type" : "string"
          },
          "prevCertValidFrom" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "prevCertValidTo" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "transId" : {
            "type" : "string"
          }
        }
      },
      "Identity" : {
        "type" : "object",
        "properties" : {
          "name" : {
            "type" : "string"
          },
          "certificate" : {
            "type" : "string"
          },
          "caCertBundle" : {
            "type" : "string"
          },
          "sshCertificate" : {
            "type" : "string"
          },
          "sshCertificateSigner" : {
            "type" : "string"
          },
          "serviceToken" : {
            "type" : "string"
          },
          "attributes" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          }
        }
      },
      "InstanceRefreshRequest" : {
        "type" : "object",
        "properties" : {
          "csr" : {
            "type" : "string"
          },
          "expiryTime" : {
            "type" : "integer",
            "format" : "int32"
          },
          "keyId" : {
            "type" : "string"
          }
        }
      },
      "InstanceRegisterInformation" : {
        "type" : "object",
        "properties" : {
          "provider" : {
            "type" : "string"
          },
          "domain" : {
            "type" : "string"
          },
          "service" : {
            "type" : "string"
          },
          "attestationData" : {
            "type" : "string"
          },
          "csr" : {
            "type" : "string"
          },
          "ssh" : {
            "type" : "string"
          },
          "sshCertRequest" : {
            "$ref" : "#/components/schemas/SSHCertRequest"
          },
          "token" : {
            "type" : "boolean"
          },
          "expiryTime" : {
            "type" : "integer",
            "format" : "int32"
          },
          "hostname" : {
            "type" : "string"
          },
          "hostCnames" : {
            "type" : "array",
            "items" : {
              "type" : "string"
            }
          }
        }
      },
      "RoleCertificateRequest" : {
        "type" : "object",
        "properties" : {
          "csr" : {
            "type" : "string"
          },
          "proxyForPrincipal" : {
            "type" : "string"
          },
          "expiryTime" : {
            "type" : "integer",
            "format" : "int64"
          },
          "prevCertNotBefore" : {
            "$ref" : "#/components/schemas/Timestamp"
          },
          "prevCertNotAfter" : {
            "$ref" : "#/components/schemas/Timestamp"
          }
        }
      },
      "RoleCertificate" : {
        "type" : "object",
        "properties" : {
          "x509Certificate" : {
            "type" : "string"
          }
        }
      },
      "SignedPolicyRequest" : {
        "type" : "object",
        "properties" : {
          "policyVersions" : {
            "type" : "object",
            "additionalProperties" : {
              "type" : "string"
            }
          },
          "signatureP1363Format" : {
            "type" : "boolean"
          }
        }
      }
    }
  }
}