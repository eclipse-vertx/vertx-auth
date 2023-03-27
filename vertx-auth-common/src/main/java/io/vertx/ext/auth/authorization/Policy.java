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
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.impl.AttributeImpl;
import io.vertx.ext.auth.authorization.impl.AuthorizationConverter;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Simple definition of ABAC policies.
 */
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
        .getJsonObject("attributes")
        .stream()
        .map(kv -> new AttributeImpl(kv.getKey(), (JsonObject) kv.getValue()))
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

  /**
   * Get the name of the policy
   */
  public String getName() {
    return name;
  }

  /**
   * Set the policy name. This is optional and has no effect on the policy evaluation.
   *
   * @param name the name.
   */
  public Policy setName(String name) {
    this.name = name;
    return this;
  }

  /**
   * Get the subjects of the policy. This is an exact match on subject ids.
   */
  public Set<String> getSubjects() {
    return subjects;
  }

  /**
   * Add a subject to the current policy.
   *
   * @param subject the subject id as in the return of {@link User#subject()}
   */
  public Policy addSubject(String subject) {
    if (subjects == null) {
      subjects = new HashSet<>();
    }
    subjects.add(subject);
    return this;
  }

  /**
   * Replaces all active subjects with the given set. No {@code subjects} implies that the policy applies to all users.
   */
  public Policy setSubjects(Set<String> subjects) {
    this.subjects = subjects;
    return this;
  }

  /**
   * Get the attributes of the policy. Attributes are environmental values that are extracted from the {@link User}.
   * Attributes are used to filter the amount of policies to be evaluated. For example, if a policy has an attribute:
   *
   * <pre>{/principal/amr: {"in: ["pwd"]}}</pre>
   * <p>
   * It will filter out any user that wasn't authenticated with a {@code username/password}.
   */
  public Set<Attribute> getAttributes() {
    return attributes;
  }

  /**
   * Set the attributes of the policy. Attributes are environmental values that are extracted from the {@link User}.
   */
  public Policy setAttributes(Set<Attribute> attributes) {
    this.attributes = attributes;
    return this;
  }

  /**
   * Add an attribute to the policy.
   */
  public Policy addAttribute(Attribute attribute) {
    Objects.requireNonNull(attribute, "attribute cannot be null");

    if (attributes == null) {
      attributes = new HashSet<>();
    }
    attributes.add(attribute);
    return this;
  }

  /**
   * Get the authorizations of the policy. Authorizations are the actual permissions that are granted to the user.
   * If a user matches the policy (meaning the subjects and attributes match) then the authorizations applied to the
   * user so they can be later evaluated.
   */
  public Set<Authorization> getAuthorizations() {
    return authorizations;
  }

  /**
   * Set the authorizations of the policy. Authorizations are the actual permissions that are granted to the user.
   * Composite authorizations ({@link AndAuthorization} and {@link OrAuthorization}) are not allowed in a policy.
   */
  public Policy setAuthorizations(Set<Authorization> authorizations) {
    if (authorizations != null) {
      authorizations
        .forEach(authn -> {
          if (authn instanceof AndAuthorization || authn instanceof OrAuthorization) {
            throw new IllegalArgumentException("AND/OR Authorizations are not allowed in a policy");
          }
        });
    }

    this.authorizations = authorizations;
    return this;
  }

  /**
   * Add an authorization to the policy. Composite authorizations ({@link AndAuthorization} and
   * {@link OrAuthorization}) are not allowed in a policy.
   */
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

  /**
   * Encode this policy as a JSON document to facilitate storage and retrieval.
   */
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
      JsonObject object = new JsonObject();
      attributes.forEach(el -> object.mergeIn(el.toJson()));
      json.put("attributes", object);
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
