Once a domain has been registered in Athenz, the administrator will
register service identities that are specified in domain roles and
policy assertions. The latter can reference those roles having access to
specified resources. Athenz supports service authentication with
two types of credentials:

- X.509 Certificates (preferred approach)
- Public/Private Key Pairs [Instructions](reg_service_guide.md)

To contact Athenz Services (ZMS/ZTS) or other Athenz Enabled services,
the client service must first obtain an Athenz CA issued X.509 certificate.
In this section we'll cover how to register the service identity and
obtain X.509 certificates based on what environment your service will be running in.

## Use Case 1: Service Running in AWS EC2

If the service is running in AWS, Service Identity Agent (SIA) running on the
instance is responsible for generating a private key for the service and
obtaining a x.509 certificate from ZTS Service. The files are located in
the following locations:

```
    private-key: /var/lib/sia/keys/<domain>.<service>.key.pem
    certificate: /var/lib/sia/certs/<domain>.<service>.cert.pem
```

The certificate is valid for 30 days and SIA agent automatically
will refresh the certificate daily. Follow [these steps](service_x509_credentials_aws.md) for
full details how to configure SIA agent running in AWS as part
of the foundation image.

## Use Case 2: Service running on-prem within an Athenz Enabled Framework (K8S)

If the service is running within an Athenz enabled framework then it
must already have access to service identity x.509 certificate that
was generated for the service. Refer to the documentation provided
by the framework to see where the files are located.

## Use Case 3: Service Running in AWS ECS (Elastic Container Service)

If the service is running in AWS ECS, Service Identity Agent (SIA) included
in your image is responsible for generating a private key for the service and
obtaining a x.509 certificate from ZTS Service. The files are located in
the following locations:

```
    private-key: /var/lib/sia/keys/<domain>.<service>.key.pem
    certificate: /var/lib/sia/certs/<domain>.<service>.cert.pem
```

The certificate is valid for 30 days and SIA agent automatically
will refresh the certificate daily. Follow [these steps](service_x509_credentials_aws_ecs.md) for
full details how to configure SIA agent running in AWS as part of your image.

## Use Case 4: Service Running in AWS Lambda Function

If the service is running in AWS Lambda function, the function being invoked will be
responsible for generating a private key and then a csr for its request. It will submit
that request to the ZTS Server to retrieve its X.509 certificate which then it
can use  along with its generated private key to establish TLS connections to
other Athenz enabled services. Athenz Team provides functions/methods in Go
and Java programming languages to quickly generate a private key and request its
corresponding X.509 certificate from ZTS Server.

The certificate is valid for 30 days. The short lifetime and stateless nature of
the function means it cannot rotate its certificates. It just gets new ones when needed.

Follow [these steps](service_x509_credentials_aws_lambda.md) for
full details how to obtain service x.509 credentials within your function.

## Use Case 5: Service Running in AWS Fargate

If the service is running in AWS Fargate, Service Identity Agent (SIA) included
in your image is responsible for generating a private key for the service and
obtaining a x.509 certificate from ZTS Service. The files are located in
the following locations:

```
    private-key: /var/lib/sia/keys/<domain>.<service>.key.pem
    certificate: /var/lib/sia/certs/<domain>.<service>.cert.pem
```

The certificate is valid for 7 days and SIA agent automatically
will refresh the certificate daily. Follow [these steps](service_x509_credentials_aws_fargate.md) for
full details how to configure SIA agent running in AWS as part of your image.

## Use Case 6: Service Running in AWS EKS

If the service is running in AWS EKS, Service Identity Agent (SIA) included
in your image is responsible for generating a private key for the service and
obtaining a x.509 certificate from ZTS Service. The files are located in
the following locations:

```
    private-key: /var/lib/sia/keys/<domain>.<service>.key.pem
    certificate: /var/lib/sia/certs/<domain>.<service>.cert.pem
```

The certificate is valid for 7 days and SIA agent automatically
will refresh the certificate daily. Follow [these steps](service_x509_credentials_aws_eks.md) for
full details how to configure SIA agent running in AWS as part of your image.
