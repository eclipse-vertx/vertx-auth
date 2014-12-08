# Authentication and Authorisation Service for Vert.x

This Vert.x service provides authentication and authorisation functionality for use in your Vert.x applications.

Internally it currently delegates to [Apache Shiro](http://shiro.apache.org/) to handle the actual authentication and
authorisation but the design allows other, non Shiro auth providers to be used in the future.

The service uses a familiar user/role/permission model that you will probably be familiar with already:

Users can have one or more roles (e.g. "manager", "developer"). Roles can have one or more permissions (e.g.
"approve expenses", "submit_expenses").

Please see the service documentation (TODO - once docgen is complete this will be generated from the JavaDoc) for more 
information on this service.

## Authentication

The service allows you to *authenticate* (i.e. log-in) users with some *credentials* (usually username and password).

## Authorisation

The service allows you to check if users have specific roles or a set of roles, and it allows you to check if users
have specific permissions.

## Realm implementations

We currently support the following realm implementations out of the box:

### Properties

You store your user/role/permission information in a simple properties file.

### LDAP

Your user/role/permission information is stored in an LDAP server. This service will interact with the LDAP server
in order to authenticate and authorise your users.

### JDBC

TODO (waiting on JDBC service)

Your user/role/permission information is stored in a database. This service will interact with the database via JDBC
in order to authenticate and authorise your users.

### Other Shiro realms

You can plug-in any other Shiro `Realm` implementation and use that if you prefer.
 

