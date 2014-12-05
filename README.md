# MongoDB Service for Vert.x

A Vert.x service allowing applications to seamlessly interact with a MongoDB instance, whether that's
saving, retrieving, searching, or deleting documents. Mongo is a great match for persisting data in a Vert.x application
since it natively handles JSON (BSON) documents.

**Features**
 - Completely Async and Non-blocking
 - Custom codec to support fast serialization to/from Vert.x JSON
 - Supports a majority of the configuration options from the MongoDB Java Driver
 - Event Bus Proxy Support

*Note: The MongoDB Java Driver is still under heavy development.*

# Getting Started

## Maven

Add the following dependency to your maven project

```xml
<dependencies>
  <dependency>
    <groupId>io.vertx</groupId>
    <artifactId>ext-mongo</artifactId>
    <version>$version</version>
  </dependency>
</dependencies>
```

## Gradle ##

Add the following dependency to your gradle project

```groovy
dependencies {
  compile("io.vertx:ext-mongo:$version")
}
```

## Deploy as a service

The easiest way to get started is to deploy it as a service

```java
Vertx vertx = Vertx.vertx();
vertx.deployVerticle("service:io.vertx:ext-mongo");
```

This will make the MongoService available as a [Service Proxy](#service-proxy) to be used throughout your application.

You can also configure the service during deployment

```java
JsonObject config = new JsonObject();
config.put("db_name", "mydb");
config.put("username", "john").put("password", "passw0rd");
vertx.deployVerticle("service:io.vertx:ext-mongo", new DeploymentOptions().setConfig(config));
```

See the [Configuration](#configuration) section below for a full list of configuration options.

## Service Proxy

Assuming you already have the service deployed, to retrieve the MongoService (from inside a Verticle for example)

```java
public class MyVerticle extends AbstractVerticle

  @Override
  public void start() {
    MongoService service = MongoService.createEventBusProxy(vertx, "vertx.mongo");
    ...
  }
```

This will create the service proxy allowing you to call the MongoService API methods instead of having to send
messages over the event bus. See [Service Proxy](https://github.com/vert-x3/service-proxy) for more information.

## Send manually over Event Bus

The service can also be called by sending JSON over the event bus manually.

Here's an example of performing a [Save](#save) by sending json over the event bus.
```java
JsonObject save = new JsonObject();
save.put("collection", "books");
JsonObject document = new JsonObject().put("title", "The Hobbit");
save.put("document", document);
save.put("options", new JsonObject());
vertx.eventBus().send("vertx.mongo", save, new DeliveryOptions().addHeader("action", "save"), saveResult -> {
  if (saveResult.succeeded()) {
    String id = (String) saveResult.result().body();
    System.out.println("Saved book with id " + id);
  } else {
    saveResult.cause().printStackTrace();
  }
});
```

See [Service Proxy](https://github.com/vert-x3/service-proxy) for more information on how this works.

# Operations

The following are some examples of the operations supported by the MongoService API. Consult the javadoc/documentation
for detailed information on all API methods.

## Save

Saves a document into the collection. If the document has no id, it is inserted.  Otherwise, it is upserted
using the document's id as the query filter.

If the document is inserted and has no id, then the id field generated will be returned to the result handler. Otherwise it
is null.

Example of saving a document into the books collection
```java
JsonObject document = new JsonObject().put("title", "The Hobbit");
service.save("books", document, outcome -> {
  if (outcome.succeeded()) {
    String id = outcome.result();
    System.out.println("Saved book with id " + id);
  } else {
    outcome.cause().printStackTrace();
  }
});
```

## Insert

Inserts a document into the collection.

If the document has no `id`, then the `id` field generated will be returned to the result handler. Otherwise it
is `null`.

Example of inserting a document into the books collection
```java
JsonObject document = new JsonObject().put("title", "The Hobbit");
service.insert("books", document, outcome -> {
  if (outcome.succeeded()) {
    String id = outcome.result();
    System.out.println("Saved book with id " + id);
  } else {
    outcome.cause().printStackTrace();
  }
});
```

## Update

Updates one or multiple documents in a collection. The JsonObject that is passed in as part of the update must contain
[Update Operators](http://docs.mongodb.org/manual/reference/operator/update-field/).

Example of updating a document in the books collection
```java
JsonObject query = new JsonObject().put("title", "The Hobbit");
JsonObject update = new JsonObject().put("$set", new JsonObject().put("author", "J. R. R. Tolkien"));
service.update("books", query, update, outcome -> {
  if (outcome.succeeded()) {
    System.out.println("Book updated !");
  } else {
    outcome.cause().printStackTrace();
  }
});
```

To specify if the update should upsert or update multiple documents, use the `updateWithOptions` operation and pass in the an `UpdateOptions` object.

UpdateOptions
 - `multi` set to true to update multiple documents
 - `upsert` set to true to insert the document if the query doesn't match
 - `writeConcern` the write concern for this operation

## Replace

Replaces a document in a collection.

This is similar to the update operation, however it does not take any [Update Operators](http://docs.mongodb.org/manual/reference/operator/update-field/).
Instead it replaces the entire document with the one provided.

Example of replacing a document in the books collection
```java
JsonObject query = new JsonObject().put("title", "The Hobbit");
JsonObject replace = new JsonObject().put("title", "The Lord of the Rings").put("author", "J. R. R. Tolkien");
service.replace("books", query, replace, outcome -> {
  if (outcome.succeeded()) {
    System.out.println("Book replaced !");
  } else {
    outcome.cause().printStackTrace();
  }
});
```

## Find

Finds matching documents in a collection

Example of finding all documents in the books collection
```java
JsonObject query = new JsonObject(); // empty query = match any
service.find("books", query, outcome -> {
  if (outcome.succeeded()) {
    for (JsonObject json : outcome.result()) {
      System.out.println(json.encodePrettily());
    }
  } else {
    outcome.cause().printStackTrace();
  }
});
```

To specify things like what fields to return, how many results to return, etc use the `findWithOptions` operation and
pass in the a `FindOptions` object.

FindOptions
 - `fields` The fields to return in the results. Defaults to `null`, meaning all fields will be returned
 - `sort` The fields to sort. Defaults to `null`.
 - `limit` The limit of the number of results to return. Default to `-1`, meaning all results will be returned.
 - `skip` The number of documents to skip before returning the results. Defaults to `0`.

## Count

Counts the number of documents in a collection

Example of counting the total number of documents in the books collection
```java
JsonObject query = new JsonObject(); // empty query = match any
service.count("books", query, outcome -> {
  if (outcome.succeeded()) {
    long count = outcome.result();
    System.out.println(count + " document(s) found.");
  } else {
    outcome.cause().printStackTrace();
  }
});
```
## Remove

Removes matching documents in a collection

Example of removing all documents in the books collection
```java
JsonObject query = new JsonObject(); // empty query = match any
service.remove("books", query, outcome -> {
  if (outcome.succeeded()) {
    System.out.println("Removed all documents !");
  } else {
    outcome.cause().printStackTrace();
  }
});
```

## Commands

Runs an arbitrary mongoDB command.

Commands can be used to run more advanced mongoDB features, such as using MapReduce.
For more information see the mongo docs for supported [Commands](http://docs.mongodb.org/manual/reference/command).

Example of running a ping command
```java
service.runCommand(new JsonObject().put("ping", 1), outcome -> {
  if (outcome.succeeded()) {
    System.out.println("Result: " + outcome.result().encodePrettily());
  } else {
    outcome.cause().printStackTrace();
  }
});
```

# Configuration

The following configuration is supported by the mongo service. The sections are broken out for clarity, but
it's important to note that this is **one** configuration file.

## Service Configuration

```javascript
{
  "address" : "some.address", // string
  "db_name" : "some.db"       // string
  "useObjectId" : true        // boolean
}
```

 - `address` The event bus address used by the service proxy. Defaults to `vertx.mongo`
 - `db_name` Name of the database in the mongoDB instance to use. Defaults to `default_db`
 - `useObjectId` Toggle this option to support persisting and retrieving ObjectId's as strings. Defaults to false

## Driver Configuration

The mongo service tries to support most options that are allowed by the driver. There are two ways to configure mongo
for use by the driver, either by a [Connection String](#connection-string) or by separate [Configuration Options](#configuration-options)

*Note: If the connection string is used the mongo service will ignore any [Configuration Options](#configuration-options)*

## Connection String

To specify the connection string to configure mongo

```javascript
{
  "connection_string" : "mongodb://localhost:27017"
}
```

 - `connection_string` The connection string the driver uses to create the client.

For more information on the format of the connection string consult the driver documentation.

## Configuration Options

Below are the supported options to configure the mongo client for the java driver.

```javascript
{
  // Single Cluster Settings
  "host" : "17.0.0.1", // string
  "port" : 27017,      // int

  // Multiple Cluster Settings
  "hosts" : [
    {
      "host" : "cluster1", // string
      "port" : 27000       // int
    },
    {
      "host" : "cluster2", // string
      "port" : 28000       // int
    },
    ...
  ]
  "replicaSet" :  "foo"    // string

  // Connection Pool Settings
  "maxPoolSize" : 50,                // int
  "minPoolSize" : 25,                // int
  "maxIdleTimeMS" : 300000,          // long
  "maxLifeTimeMS" : 3600000,         // long
  "waitQueueMultiple"  : 10,         // int
  "waitQueueTimeoutMS" : 10000,      // long
  "maintenanceFrequencyMS" : 2000,   // long
  "maintenanceInitialDelayMS" : 500, // long

  // Credentials / Auth
  "username"   : "john",     // string
  "password"   : "passw0rd", // string
  "authSource" : "some.db"   // string
     // Auth mechanism
  "authMechanism"     : "GSSAPI",        // string
  "gssapiServiceName" : "myservicename", // string

  // Socket Settings
  "connectTimeoutMS" : 300000, // int
  "socketTimeoutMS"  : 100000, // int
  "sendBufferSize"    : 8192,  // int
  "receiveBufferSize" : 8192,  // int
  "keepAlive" : true           // boolean

  // Heartbeat socket settings
  "heartbeat.socket" : {
    "connectTimeoutMS" : 300000, // int
    "socketTimeoutMS"  : 100000, // int
    "sendBufferSize"    : 8192,  // int
    "receiveBufferSize" : 8192,  // int
    "keepAlive" : true           // boolean
  }

  // Server Settings
  "heartbeatFrequencyMS" :    1000 // long
  "minHeartbeatFrequencyMS" : 500 // long
}
```

**Option Descriptions**
 - `host` The host the mongoDB instance is running. Defaults to `127.0.0.1`. This is ignored if `hosts` is specified
 - `port` The port the mongoDB instance is listening on. Defaults to `27017`. This is ignored if `hosts` is specified
 - `hosts` An array representing the hosts and ports to support a mongoDB cluster (sharding / replication)
   - `host` A host in the cluster
   - `port` The port a host in the cluster is listening on
 - `replicaSet` The name of the replica set, if the mongoDB instance is a member of a replica set
 - `maxPoolSize` The maximum number of connections in the connection pool. The default value is `100`
 - `minPoolSize` The minimum number of connections in the connection pool. The default value is `0`
 - `maxIdleTimeMS` The maximum idle time of a pooled connection. The default value is `0` which means there is no limit
 - `maxLifeTimeMS` The maximum time a pooled connection can live for. The default value is `0` which means there is no limit
 - `waitQueueMultiple` The maximum number of waiters for a connection to become available from the pool. Default value is `500`
 - `waitQueueTimeoutMS` The maximum time that a thread may wait for a connection to become available. Default value is `120000` (2 minutes)
 - `maintenanceFrequencyMS` The time period between runs of the maintenance job. Default is `0`.
 - `maintenanceInitialDelayMS` The period of time to wait before running the first maintenance job on the connection pool. Default is `0`.
 - `username` The username to authenticate. Default is `null` (meaning no authentication required)
 - `password` The password to use to authenticate.
 - `authSource` The database name associated with the user's credentials. Default value is `admin`
 - `authMechanism` The authentication mechanism to use. See [Authentication](http://docs.mongodb.org/manual/core/authentication/) for more details.
 - `gssapiServiceName` The Kerberos service name if `GSSAPI` is specified as the `authMechanism`.
 - `connectTimeoutMS` The time in milliseconds to attempt a connection before timing out. Default is `10000` (10 seconds)
 - `socketTimeoutMS` The time in milliseconds to attempt a send or receive on a socket before the attempt times out. Default is `0` meaning there is no timeout
 - `sendBufferSize` Sets the send buffer size (SO_SNDBUF) for the socket. Default is `0`, meaning it will use the OS default for this option.
 - `receiveBufferSize` Sets the receive buffer size (SO_RCVBUF) for the socket. Default is `0`, meaning it will use the OS default for this option.
 - `keepAlive` Sets the keep alive (SO_KEEPALIVE) for the socket. Default is `false`
 - `heartbeat.socket` Configures the socket settings for the cluster monitor of the MongoDB java driver.
 - `heartbeatFrequencyMS` The frequency that the cluster monitor attempts to reach each server. Default is `5000` (5 seconds)
 - `minHeartbeatFrequencyMS` The minimum heartbeat frequency. The default value is `1000` (1 second)

*Note: Most of the default values listed above use the default values of the MongoDB Java Driver.
Please consult the driver documentation for up to date information.*

TODO: Include links to 3.0 driver documentation when made available
