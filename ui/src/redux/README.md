Common-Language Redux: # Language: markdown
[]: # Path: src/redux/README.md

Common-Language Redux Functions:
get - loading data from the backend.
load - inserting data fetched from the backend into the store.
to_store - using in the end of an add function in order to separate the backend put data function and the function which save the new data in the store - (example: addRole, addRoleToStore)
from_store - using in the end on a delete function in order to separate the backend delete data function and the function which delete the data from the store - (example: deleteRole, deleteRoleFromStore)

Architecture:
Store: the store seperated to 10 different reducers.
each reducer in the store holds a domain name, expiry and the data. (for example the roles reducer look like: {domainData:'dom', expiry:'', roles:{} })
in order to improve convince of writing code we transform the data from array to map (the data the server returns is an array but holds in the store as a map).
the keys for the roles/groups/services/polices are full names (<domain-name>:role/group.<role-name>)
we use immer library in order to save our store immutable. (https://immerjs.github.io/immer/)

1. services: holds all the services
2. domains: holds all the data of all the domains which the user visit in a specific session in order the save api calls in the movement between domains.
3. domainData: holds the general data of the current domain such as domain header, tags, history etc...
4. roles: holds all the roles
5. groups: holds all the groups
6. policies: holds all the policies
7. templates: holds all the tamplates
8. microsegmentation: holds the in bound and out bound of microsegmentation
9. isLoading: holds all the api calls for the server which happen in a specific time in order the present a loading page.
10. user: holds the current user spesific data.
    thunks: to demonstrate how all thunks work we will use role thunk as an example.
    role: 1. getRoles: - check whether the roles are in the store, if not, fetch them from the server. - if the domain has changed -
    _ if the domain is not in the store, fetch it from the server.
    _ if the domain is in the store global domains store, but the expiry is less than now, fetch it from the server. \* if the domain is in the store global domains store, and the expiry is greater than now, replace the current domain data. - if the roles are in the store, check whether they are expired, if so, fetch them from the server. - if the roles are in the store, and they are not expired, return the roles. 2. getRole: - check whether the roles are expired and if it does we reload them from the server, we do it with the use of the getRoles thunk. - we check if the data we need already exits in th store if it is we return it else we fetch it from the server. 3. addRole/deleteRole: - check whether the roles are expired and if it does we reload them from the server, we do it with the use of the getRoles thunk. - check whether the data we need already exits/not exists in th store if it is we return an error else we send the request to the server to add/delete it.
    selectors: selectors are function that retrieve a specific data from the store,
    by using them the components doesn't need to know where the data is located in the store,
    furthermore it allows us to add logic to the retrieved data.
    ** pay attention most of the data in the store, stored as a map while the components use data in a list format,
    ** we use the selector in order to convert the map object from to store into a list object which used in the components by using (mapToList func).
