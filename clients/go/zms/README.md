# zms-go-client

A Go client library to talk to Athenz ZMS.

The model.go and client.go files are generated from zms_core, and checked in so users of this library need not know that.

Additionally, an implementation of rdl.Authorizer and rdl.Authenticator are provided that use this library to delegate that functionality to Athenz ZMS:

Release Notes:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Version 1.0 (2016-09-06)
 - Initial opensource release

## Usage

To get it into your workspace:

    go get github.com/AthenZ/athenz/clients/go/zms

Then in your Go code:

    import (
        zms "github.com/AthenZ/athenz/clients/go/zms"
    )
    func main() {
         var principal rdl.Principal /* init this from an actual user credential */
         ...
         client := zms.NewClient()
         client.AddCredentials(principal.GetHTTPHeaderName(), principal.GetCredentials())
         dmn, err := client.GetDomain("athenz") //
         ...
    }

To use the ZMSAuthorizer from your RDL-generated server:

    import (
        zms "github.com/AthenZ/athenz/clients/go/zms"
    )
    ...
    endpoint := "localhost:4080"
    domain := "your.server.domain"

    zmsURL := "http://localhost:10080/zms/v1" //set this to "" for debug mode
    authn := zms.Authenticator(zmsURL)
    authz := zms.Authorizer(domain, zmsURL)

    handler := contacts.Init(impl, url, authz, authn)
    http.ListenAndServe(endpoint, handler)

## License

Copyright The Athenz Authors

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
