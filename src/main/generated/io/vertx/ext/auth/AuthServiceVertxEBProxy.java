/*
* Copyright 2014 Red Hat, Inc.
*
* Red Hat licenses this file to you under the Apache License, version 2.0
* (the "License"); you may not use this file except in compliance with the
* License. You may obtain a copy of the License at:
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
* License for the specific language governing permissions and limitations
* under the License.
*/

package io.vertx.ext.auth;

import io.vertx.ext.auth.AuthService;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.Vertx;
import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.util.ArrayList;import java.util.HashSet;import java.util.List;import java.util.Map;import java.util.Set;import io.vertx.serviceproxy.ProxyHelper;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.ext.auth.AuthService;

/*
  Generated Proxy code - DO NOT EDIT
  @author Roger the Robot
*/
public class AuthServiceVertxEBProxy implements AuthService {

  private Vertx _vertx;
  private String _address;
  private boolean closed;

  public AuthServiceVertxEBProxy(Vertx vertx, String address) {
    this._vertx = vertx;
    this._address = address;
  }

  public void login(JsonObject credentials, Handler<AsyncResult<Void>> resultHandler) {
    checkClosed();
    JsonObject _json = new JsonObject();
    _json.put("credentials", credentials);
    DeliveryOptions _deliveryOptions = new DeliveryOptions();
    _deliveryOptions.addHeader("action", "login");
    _vertx.eventBus().<Void>send(_address, _json, _deliveryOptions, res -> {
      if (res.failed()) {
        resultHandler.handle(Future.failedFuture(res.cause()));
      } else {
        resultHandler.handle(Future.succeededFuture(res.result().body()));
      }
    });
  }

  public void hasRole(String subject, Handler<AsyncResult<Boolean>> resultHandler) {
    checkClosed();
    JsonObject _json = new JsonObject();
    _json.put("subject", subject);
    DeliveryOptions _deliveryOptions = new DeliveryOptions();
    _deliveryOptions.addHeader("action", "hasRole");
    _vertx.eventBus().<Boolean>send(_address, _json, _deliveryOptions, res -> {
      if (res.failed()) {
        resultHandler.handle(Future.failedFuture(res.cause()));
      } else {
        resultHandler.handle(Future.succeededFuture(res.result().body()));
      }
    });
  }

  public void hasPermission(String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    checkClosed();
    JsonObject _json = new JsonObject();
    _json.put("permission", permission);
    DeliveryOptions _deliveryOptions = new DeliveryOptions();
    _deliveryOptions.addHeader("action", "hasPermission");
    _vertx.eventBus().<Boolean>send(_address, _json, _deliveryOptions, res -> {
      if (res.failed()) {
        resultHandler.handle(Future.failedFuture(res.cause()));
      } else {
        resultHandler.handle(Future.succeededFuture(res.result().body()));
      }
    });
  }

  public void start() {
  }

  public void stop() {
  }


  private List<Character> convertToListChar(JsonArray arr) {
    List<Character> list = new ArrayList<>();
    for (Object obj: arr) {
      Integer jobj = (Integer)obj;
      list.add((char)jobj.intValue());
    }
    return list;
  }

  private Set<Character> convertToSetChar(JsonArray arr) {
    Set<Character> set = new HashSet<>();
    for (Object obj: arr) {
      Integer jobj = (Integer)obj;
      set.add((char)jobj.intValue());
    }
    return set;
  }

  private void checkClosed() {
    if (closed) {
      throw new IllegalStateException("Proxy is closed");
    }
  }
  private <T> Map<String, T> convertMap(Map map) {
    return (Map<String, T>)map;
  }
  private <T> List<T> convertList(List list) {
    return (List<T>)list;
  }
  private <T> Set<T> convertSet(List list) {
    return new HashSet<T>((List<T>)list);
  }
}