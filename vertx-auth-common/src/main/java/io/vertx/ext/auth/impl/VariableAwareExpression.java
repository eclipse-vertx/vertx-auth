package io.vertx.ext.auth.impl;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

import io.vertx.ext.auth.AuthorizationContext;

class VariableAwareExpression {
	private String value;
	private transient Function<AuthorizationContext, String>[] parts;
	private transient boolean hasVariable = false;

	@SuppressWarnings("unchecked")
	public VariableAwareExpression(String value) {
		this.value = Objects.requireNonNull(value).trim();

		List<Function<AuthorizationContext, String>> tmpParts = new ArrayList<>();
		int currentPos = 0;
		while (currentPos != -1) {
			int openingCurlyBracePos = value.indexOf("{", currentPos);
			if (openingCurlyBracePos == -1) {
				if (currentPos < value.length()) {
					String authorizationPart = value.substring(currentPos, value.length() - currentPos);
					tmpParts.add(ctx -> authorizationPart);
				}
				break;
			}
			else {
				if (openingCurlyBracePos > currentPos) {
					String authorizationPart = value.substring(currentPos, openingCurlyBracePos);
					tmpParts.add(ctx -> authorizationPart);
				}
				int closingCurlyBracePos = value.indexOf("}", currentPos + 1);
				if (closingCurlyBracePos == -1) {
					throw new IllegalArgumentException("opening '{' without corresponding closing '}'");
				}
				else if (closingCurlyBracePos - openingCurlyBracePos == 1) {
					throw new IllegalArgumentException("empty '{}' is not allowed");
				}
				else {
					String part = value.substring(openingCurlyBracePos, closingCurlyBracePos + 1);
					String variableName = value.substring(openingCurlyBracePos + 1, closingCurlyBracePos);
					hasVariable = true;
					tmpParts.add(ctx -> {
						// substitute parameter
						Object result = ctx.request().getParam(variableName);
						if (result instanceof String) {
							return (String) result;
						}
						return part;
					});
					currentPos = closingCurlyBracePos + 1;
				}
			}
		}
		this.parts = (Function<AuthorizationContext, String>[]) Array.newInstance(Function.class, tmpParts.size());
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

	public Function<AuthorizationContext, String>[] parts() {
		return parts;
	}

	public String resolve(AuthorizationContext context) {
		if (parts.length == 1) {
			return parts[0].apply(context);
		}
		else if (parts.length > 1) {
			StringBuilder result = new StringBuilder();
			for (Function<AuthorizationContext, String> part : parts) {
				result.append(part.apply(context));
			}
			return result.toString();
		}
		// should only happen when the length is 0
		return "";
	}

}