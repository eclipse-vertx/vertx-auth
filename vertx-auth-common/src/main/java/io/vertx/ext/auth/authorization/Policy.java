/*
 * Copyright 2023 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */
package io.vertx.ext.auth.authorization;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authorization.impl.AttributeImpl;
import io.vertx.ext.auth.authorization.impl.AuthorizationConverter;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@DataObject
public class Policy {

  private String name;

  private Set<String> subjects;

  private Set<Attribute> attributes;
  private Set<Authorization> authorizations;

  public Policy() {
  }

  public Policy(JsonObject json) {
    name = json.getString("name");
    if (json.containsKey("subjects")) {
      subjects = json
        .getJsonArray("subjects")
        .stream()
        .map(o -> (String) o)
        .collect(Collectors.toSet());
    }
    if (json.containsKey("attributes")) {
      attributes = json
        .getJsonArray("attributes")
        .stream()
        .map(o -> (JsonObject) o)
        .map(AttributeImpl::new)
        .collect(Collectors.toSet());
    }
    if (json.containsKey("authorizations")) {
      authorizations = json
        .getJsonArray("authorizations")
        .stream()
        .map(o -> (JsonObject) o)
        .map(AuthorizationConverter::decode)
        .peek(authn -> {
          if (authn instanceof AndAuthorization || authn instanceof OrAuthorization) {
            throw new IllegalArgumentException("AND/OR Authorizations are not allowed in a policy");
          }
        })
        .collect(Collectors.toSet());
    }
  }

  public String getName() {
    return name;
  }

  public Policy setName(String name) {
    this.name = name;
    return this;
  }

  public Set<String> getSubjects() {
    return subjects;
  }

  public Policy addSubject(String subject) {
    if (subjects == null) {
      subjects = new HashSet<>();
    }
    subjects.add(subject);
    return this;
  }

  public Policy setSubjects(Set<String> subjects) {
    this.subjects = subjects;
    return this;
  }

  public Set<Attribute> getAttributes() {
    return attributes;
  }

  public Policy setAttributes(Set<Attribute> attributes) {
    this.attributes = attributes;
    return this;
  }

  public Policy addAttribute(Attribute attribute) {
    Objects.requireNonNull(attribute, "attribute cannot be null");

    if (attributes == null) {
      attributes = new HashSet<>();
    }
    attributes.add(attribute);
    return this;
  }

  public Set<Authorization> getAuthorizations() {
    return authorizations;
  }

  public Policy setAuthorizations(Set<Authorization> authorizations) {
    // We can't allow OR
    // AND need to be exploded
    this.authorizations = authorizations;
    return this;
  }

  public Policy addAuthorization(Authorization authorization) {
    Objects.requireNonNull(authorization, "authorization cannot be null");

    if (authorization instanceof AndAuthorization || authorization instanceof OrAuthorization) {
      throw new IllegalArgumentException("AND/OR Authorizations are not allowed in a policy");
    }

    if (authorizations == null) {
      authorizations = new HashSet<>();
    }
    authorizations.add(authorization);
    return this;
  }

  public JsonObject toJson() {
    final JsonObject json = new JsonObject();
    if (name != null) {
      json.put("name", name);
    }
    if (subjects != null) {
      JsonArray array = new JsonArray();
      subjects.forEach(array::add);
      json.put("subjects", array);
    }
    if (attributes != null) {
      JsonArray array = new JsonArray();
      attributes.forEach(el -> array.add(el.toJson()));
      json.put("attributes", array);
    }
    if (authorizations != null) {
      JsonArray array = new JsonArray();
      authorizations.forEach(el -> array.add(el.toJson()));
      json.put("authorizations", array);
    }
    return json;
  }

  @Override
  public String toString() {
    return toJson().encode();
  }
}
