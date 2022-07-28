Common-Language Redux: # Language: markdown
[]: # Path: src/redux/README.md

Architecture:

Functions: our functions dived into 6 main formulas:
get - get function will be build like this:
** pay attention that in most of the get api calls the server side returns the data as an array,
** while in the store we store it as a map with the name of the collection as the key, so you will need to use listToMap function. 1. check if the data asked exists in the store - getState().groups.expiry
_ if it does, check that the domain hasn't changed.
_ if it changed:
1.dispatch store function in order to save the data in the global cache(domains),
2.check if the data need is in the global cache and isn't expired if it is return it, if it isn't make an api call to get the required data
_ if it didn't change: check if the data is not expired, if it is make an api call in order to load the data, else return the data
_ if it didn't, make an api call in order to get the data 2. every thunk has an utils file, in the utils file we will create all the api calls, the api returns on themselves several times and if we will want to change something we will do it in a single place
load - load function are reducer function and its suppose to load data which returned from api call into the store.
return - return function are reducer function that been activated if in a get function we discover that we have the data required.
store - store function are function which activated only in case the domain has been changed, and it supposes to save the current data into the global cache (domains).
add - add function will be build like this: 1. use a selector to get the relevant data from the store 2. check if the data has expired,
_ if it did, make an api call to get the data and then use the selector again
_ if it didn't, check if the data that needed to be added already exists in the store, if it is, return a fail, else make an api call to add the data.
delete - delete function will be build like this: 1. use a selector to get the relevant data from the store 2. check if the data has expired,
_ if it did, make an api call to get the data and then use the selector again
_ if it didn't, check if the data that needed to be deleted is exists in the store, if it isn't return a fail, else make an api call to delete the data.

Store Structure: \*_ for roles,groups, services,policies - the structure of the reducer is: {domainName, expiry, data(which for each of them will be the reducer name - for groups it will be groups and for roles it will be roles) 1. domains - is the global cache, it contains all the data that we have seen in all the domains which we visit in a session. 2. domainData - contains the data which is global for all pages of the current domain (header details). 3. roles - contains all the data of the roles that the current domain has. 4. groups - contains all the data of the groups that the current domain has.
_ the group structure is: {domainName, expiry, groups, roleMembers) # the groups is a map which its key is the group name and its value is the group data. 5. services - contains all the data of the services that the current domain has. 6. policies - contains all the data of the policies that the current domain has.

Reducers: the reducer are the break-up of the store to smaller peaces which is easier to deal with.
\*\* pay attention

Selectors:
selectors are function that retrieve a specific data from the store,
by using them the components doesn't need to know where the data is located in the store,
furthermore it allows us to add logic to the retrieved data.
** pay attention most of the data in the store, stored as a map while the components use data in a list format,
** we use the selector in order to convert the map object from to store into a list object which used in the components by using (mapToList func).

adding a page steps:

1. add new thunk for the page.
    1. get${REDUCER_NAME} thunk is split to 2 parts -
        1. first time initial - fetch the data from the api
        2. was initial -
            1. expiry has past - if domain changed - store the data. fetch it from the api.
            2. the domain has changed - store the data in the domains reducer,
               try to get the new domain data from the domains reducer and make sure the expiry is ok if success load it, else fetch it from the api.
            3. all good - returns the data
2. add the actions - load${REDUCER_NAME} and return${REDUCER_NAME}
3. add the store${REDUCER_NAME} action to the domains actions.
4. add the reducer - add the 2 action to the reducer.
5. add to the domains reducer the store${REDUCER_NAME} case.
