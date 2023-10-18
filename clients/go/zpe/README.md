# ZPE Go library

[LY Corporation](https://www.lycorp.co.jp/en/) wrote an authorization library called [AthenZ/athenz-authorizer](https://github.com/AthenZ/athenz-authorizer);
therefore, no competing implementation has been written in this repo.

Please see its documentation and examples for more detailed information and in general you'll need to:

1. Instantiate and configure with a `New`-prefixed method with `Option`s
2. Check for error, and call `Init` to do one fetch synchronously in the right sequence (public certs before signed
   policies, e.g.)
3. Call `Start` to schedule background processors and listen to its returned `<-chan error` to take action as needed.
4. Use the appropriate `Authorize`-prefixed method for each request and reject requests with errors.

    **NOTE**: at the time of writing, `AuthorizeAccessToken` is the most full-featured, returning `authorizedRoles` in
    the `Principal`. 
