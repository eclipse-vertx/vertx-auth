/********************************************************************************
 * Copyright (c) 2019 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 3
 *
 * Contributors: 4
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.ext.auth.authorization.impl;

import io.vertx.core.MultiMap;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

public class VariableAwareExpression {
  private final String value;
  private final transient Function<MultiMap, String>[] parts;
  private transient boolean hasVariable = false;

  @SuppressWarnings("unchecked")
  public VariableAwareExpression(String value) {
    this.value = Objects.requireNonNull(value).trim();

    List<Function<MultiMap, String>> tmpParts = new ArrayList<>();
    int currentPos = 0;
    while (currentPos != -1) {
      int openingCurlyBracePos = value.indexOf("{", currentPos);
      if (openingCurlyBracePos == -1) {
        if (currentPos < value.length()) {
          String authorizationPart = value.substring(currentPos, value.length() - currentPos);
          tmpParts.add(ctx -> authorizationPart);
        }
        break;
      } else {
        if (openingCurlyBracePos > currentPos) {
          String authorizationPart = value.substring(currentPos, openingCurlyBracePos);
          tmpParts.add(ctx -> authorizationPart);
        }
        int closingCurlyBracePos = value.indexOf("}", currentPos + 1);
        if (closingCurlyBracePos == -1) {
          throw new IllegalArgumentException("opening '{' without corresponding closing '}'");
        } else if (closingCurlyBracePos - openingCurlyBracePos == 1) {
          throw new IllegalArgumentException("empty '{}' is not allowed");
        } else {
          String part = value.substring(openingCurlyBracePos, closingCurlyBracePos + 1);
          String variableName = value.substring(openingCurlyBracePos + 1, closingCurlyBracePos);
          hasVariable = true;
          tmpParts.add(ctx -> {
            // substitute parameter
            String result = ctx.get(variableName);
            if (result != null) {
              return result;
            }
            return part;
          });
          currentPos = closingCurlyBracePos + 1;
        }
      }
    }
    this.parts = new Function[tmpParts.size()];
    for (int i = 0; i < tmpParts.size(); i++) {
      this.parts[i] = tmpParts.get(i);
    }
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (!(obj instanceof VariableAwareExpression))
      return false;
    VariableAwareExpression other = (VariableAwareExpression) obj;
    return Objects.equals(value, other.value);
  }

  public boolean hasVariable() {
    return hasVariable;
  }

  public String getValue() {
    return value;
  }

  @Override
  public int hashCode() {
    return Objects.hash(value);
  }

  public String resolve(MultiMap context) {
    // shortcut if there is no variable
    if (!hasVariable) {
      return value;
    }

    if (parts.length == 1) {
      return parts[0].apply(context);
    } else if (parts.length > 1) {
      StringBuilder result = new StringBuilder();
      for (Function<MultiMap, String> part : parts) {
        result.append(part.apply(context));
      }
      return result.toString();
    }
    // should only happen when the length is 0
    return "";
  }

}
