/*
 * Copyright 2014 Red Hat, Inc.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Apache License v2.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * The Apache License v2.0 is available at
 * http://www.opensource.org/licenses/apache2.0.php
 *
 * You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth.mongo.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.mongo.*;
import io.vertx.ext.mongo.FindOptions;
import io.vertx.ext.mongo.MongoClient;

import java.util.*;

/**
 * An implementation of {@link MongoAuthorization}
 *
 * @author mremme
 */
public class MongoAuthorizationImpl implements MongoAuthorization {
  private static final Logger log = LoggerFactory.getLogger(MongoAuthorizationImpl.class);
  private final MongoClient mongoClient;
  private final String providerId;
  private final MongoAuthorizationOptions options;
  private final JsonArray lookupRolePermissionsPipeline;

  /**
   * Creates a new instance
   * @param providerId
   *          the provider ID to differentiate from others
   * @param mongoClient
   *          the {@link MongoClient} to be used
   * @param options
   *          the options for configuring the new instance
   */
  public MongoAuthorizationImpl(String providerId, MongoClient mongoClient, MongoAuthorizationOptions options) {
    this.providerId = Objects.requireNonNull(providerId);
    this.mongoClient = mongoClient;
    this.options = options;
    // precompute the part of the pipeline that never changes
    this.lookupRolePermissionsPipeline = options.isReadRolePermissions() ? lookupRolePermissionsPipeline() : null;
  }

  /**
   * The default implementation uses the usernameField as search field
   *
   * @param username
   * @return
   */
  protected JsonObject createQuery(String username) {
    if (!options.isReadRolePermissions()) {
      return new JsonObject().put(options.getUsernameField(), username);
    } else {
      JsonArray pipeline = new JsonArray();
      // match the user at the beginning of the pipeline
      pipeline.add(new JsonObject()
        .put("$match", new JsonObject()
          .put(options.getUsernameField(), username)
        )
      );
      // the rest of the pipeline does not change
      for (int i=0 ; i<lookupRolePermissionsPipeline.size() ; i++) {
        pipeline.add(lookupRolePermissionsPipeline.getJsonObject(i));
      }
      return new JsonObject()
        .put("aggregate", options.getCollectionName())
        .put("pipeline", pipeline)
        // make sure the batch size is larger than the expected result size (= 1)
        .put("cursor", new JsonObject()
          .put("batchSize", 2)
        );
    }
  }

  @Override
  public String getId() {
    return providerId;
  }

  @Override
  public void getAuthorizations(User user, Handler<AsyncResult<Void>> handler) {
    JsonObject query = createQuery(user.principal().getString(options.getUsernameField()));
    Handler<AsyncResult<List<JsonObject>>> queryResultHandler = res -> {
      if (res.failed()) {
        handler.handle(Future.failedFuture(res.cause()));
        return;
      }
      user.authorizations().clear(providerId);
      for (JsonObject jsonObject : res.result()) {
        JsonArray roles = jsonObject.getJsonArray(options.getRoleField());
        if (roles != null) {
          for (int i = 0; i < roles.size(); i++) {
            String role = roles.getString(i);
            user.authorizations().add(providerId, RoleBasedAuthorization.create(role));
          }
        }
        JsonArray permissions = jsonObject.getJsonArray(options.getPermissionField());
        if (permissions != null) {
          for (int i = 0; i < permissions.size(); i++) {
            String permission = permissions.getString(i);
            Authorization authorization = PermissionBasedAuthorization.create(permission);
            user.authorizations().add(providerId, authorization);
          }
        }
      }
      handler.handle(Future.succeededFuture());
    };
    if (!options.isReadRolePermissions()) {
      FindOptions findOptions = new FindOptions()
        .setLimit(1)
        .setFields(
          new JsonObject()
            .put("_id", 0)
            .put(options.getUsernameField(), 1)
            .put(options.getPermissionField(), 1)
            .put(options.getRoleField(), 1));
      mongoClient.findWithOptions(options.getCollectionName(), query, findOptions, queryResultHandler);
    } else {
      mongoClient.runCommand("aggregate", query, res -> {
        if (res.succeeded()) {
          JsonArray batch = res.result().getJsonObject("cursor").getJsonArray("firstBatch");
          List<JsonObject> usersList;
          if (batch.isEmpty()) {
            usersList = Collections.emptyList();
          } else {
            JsonObject result = batch.getJsonObject(0);
            JsonArray users = result.getJsonArray("users");
            usersList = new ArrayList<>(result.size());
            for (int i=0; i<users.size() ; i++) {
              usersList.add(users.getJsonObject(0));
            }
          }
          queryResultHandler.handle(Future.succeededFuture(usersList));
        } else {
          queryResultHandler.handle(Future.failedFuture(res.cause()));
        }
      });
    }
  }

  private JsonArray lookupRolePermissionsPipeline() {
    // the full pipeline looks like this:
    // (not that this method does not create the first $match step that is dependent on the username)
    /*
        [{$match: {
          "username": "tim"
        }}, {$lookup: {
          from: 'roles',
          localField: 'roles',
          foreignField: 'rolename',
          as: 'joinedRoles'
        }}, {$project: {
          _id: 0,
          username: 1,
          roles: 1,
          "permissions": {
            $reduce: {
              input: "$joinedRoles.permissions",
              initialValue: {
                $cond: {
                  if: {
                    $isArray: ["$permissions"]
                  },
                  then: "$permissions",
                  else: []
                }
              },
              in: {
                $setUnion: ["$$value", { $cond: { if: { $isArray: [ "$$this" ] }, then: "$$this", else: [] } }]
              }
            }
          }
        }}, {$group: {
          _id: "username",
          users: {
            $push: "$$ROOT"
          }
        }}]
    */
    JsonArray result = new JsonArray();
    // lookup role permissions from the role collections
    result.add(new JsonObject()
        .put("$lookup", new JsonObject()
          .put("from", options.getRoleCollectionName())
          .put("localField", options.getRoleField())
          .put("foreignField", options.getRoleNameField())
          .put("as", "joinedRoles")
        )
      )
      // merge users permissions and all roles permissions into a new permissions array
      .add(new JsonObject()
        .put("$project", new JsonObject()
          .put("_id", 0)
          .put(options.getUsernameField(), 1)
          .put(options.getRoleField(), 1)
          .put(options.getPermissionField(), new JsonObject()
            .put("$reduce", new JsonObject()
              .put("input", "$joinedRoles." + options.getRolePermissionField())
              .put("initialValue", new JsonObject()
                // don't fail if no permissions field on user or if non array value
                .put("$cond", new JsonObject()
                  .put("if", new JsonObject()
                    .put("$isArray", new JsonArray().add("$" + options.getPermissionField()))
                  )
                  .put("then", "$" + options.getPermissionField())
                  .put("else", new JsonArray())
                ))
              .put("in", new JsonObject()
                .put("$setUnion", new JsonArray().add("$$value").add(
                    // don't fail if no permissions field on role or if non array value
                    new JsonObject()
                      .put("$cond", new JsonObject()
                        .put("if", new JsonObject()
                          .put("$isArray", new JsonArray().add("$$this"))
                        )
                        .put("then", "$$this")
                        .put("else", new JsonArray())
                      )
                  )
                )
              )
            )
          )
        )
      )
      // make sure we get a single object containing all objects as a result (in case of duplicate usernames)
      .add(new JsonObject()
        .put("$group", new JsonObject()
          .put("_id", "")
          .put("users", new JsonObject()
            .put("$push", "$$ROOT")
          )
        )
      );
    return result;
  }

}
