package io.vertx.ext.auth.audit.impl;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpVersion;
import io.vertx.core.internal.logging.Logger;
import io.vertx.core.internal.logging.LoggerFactory;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.SocketAddress;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.audit.Marker;
import io.vertx.ext.auth.audit.SecurityAudit;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authorization.Authorization;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public final class SecurityAuditLogger implements SecurityAudit {

  public static final Logger LOGGER = LoggerFactory.getLogger(SecurityAudit.class);

  private static final String FORMAT = System.getProperty("io.vertx.ext.auth.audit.format", "rfc5424");

  private static final String MASK = "********************************";

  private static String mask(String input) {
    int len = input.length();
    if (len > 32) {
      return MASK + "...";
    }
    return MASK.substring(0, len);
  }

  private static final Set<String> MASKED = new HashSet<>();

  static {
    Collections.addAll(MASKED, "password", "secret", "jwt", "nonce", "cnonce", "assertion", "token", "challenge");
  }

  /**
   * Escape any NLF (newline function) and Backspace to prevent log injection attacks.
   *
   * @param value string to convert
   * @return converted string
   * @see <a href="https://unicode.org/versions/Unicode14.0.0/UnicodeStandard-14.0.pdf#page=235">Unicode Standard</a>
   */
  private static void escapeNLFChars(StringBuilder sb, String value) {
    for (char c : value.toCharArray()) {
      switch (c) {
        case '\n':
          sb.append("\\n");
          break;
        case '\r':
          sb.append("\\r");
          break;
        case '\u0085':
          // NEL
          sb.append("\\u0085");
          break;
        case '\u000B':
          // VT
          sb.append("\\u000B");
          break;
        case '\u000C':
          // FF
          sb.append("\\u000C");
          break;
        case '\u2028':
          // LS
          sb.append("\\u2028");
          break;
        case '\u2029':
          // PS
          sb.append("\\u2029");
          break;
        case '\b':
          sb.append("\\b");
          break;
        default:
          sb.append(c);
          break;
      }
    }
  }


  private SocketAddress source;
  private SocketAddress destination;
  private String resource;
  private Credentials credentials;
  private User user;
  private Authorization authorization;
  private int status;

  public static boolean isEnabled() {
    return LOGGER.isInfoEnabled();
  }

  @Override
  public SecurityAudit source(SocketAddress address) {
    this.source = address;
    return this;
  }

  @Override
  public SecurityAudit destination(SocketAddress address) {
    this.destination = address;
    return this;
  }

  @Override
  public SecurityAudit resource(HttpVersion version, HttpMethod method, String path) {
    StringBuilder sb = new StringBuilder();
    switch (version){
      case HTTP_1_0:
        sb.append("HTTP/1.0");
        break;
      case HTTP_1_1:
        sb.append("HTTP/1.1");
        break;
      case HTTP_2:
        sb.append("HTTP/2.0");
        break;
    }

    sb.append(' ');
    sb.append(method.name());
    sb.append(' ');
    sb.append(path);

    resource = sb.toString();
    return this;
  }

  @Override
  public SecurityAudit resource(String resource) {
    this.resource = resource;
    return this;
  }

  @Override
  public SecurityAudit credentials(Credentials credentials) {
    this.credentials = credentials;
    return this;
  }

  @Override
  public SecurityAudit user(User user) {
    this.user = user;
    return this;
  }

  @Override
  public SecurityAudit authorization(Authorization authorization) {
    this.authorization = authorization;
    return this;
  }

  @Override
  public SecurityAudit status(int status) {
    this.status = status;
    return this;
  }

  @Override
  public void audit(Marker marker, boolean success) {
    switch (FORMAT) {
      case "json":
        auditJSON(marker, success);
        break;
      case "rfc5424":
      default:
        auditRFC5424(marker, success);
        break;
    }
  }

  private void auditRFC5424(Marker marker, boolean success) {
    StringBuilder sb = new StringBuilder();

    sb
      .append('[')
      .append(marker.name());

    sb.append(" epoch=\"")
      .append(System.currentTimeMillis())
      .append('"');

    if (source != null) {
      if (source.isInetSocket()) {
        sb.append(" source=\"")
          .append(source.host());
      } else {
        sb.append(" source=\"");
        escapeNLFChars(sb, source.path());
      }
      sb.append('"');
    }
    if (destination != null) {
      if (destination.isInetSocket()) {
        sb.append(" destination=\"")
          .append(destination.host());
      } else {
        sb.append(" destination=\"");
        escapeNLFChars(sb, destination.path());
      }
      sb.append('"');
    }
    if (resource != null) {
      sb.append(" resource=\"");
      escapeNLFChars(sb, resource);
      sb.append('"');
    }

    switch (marker) {
      case AUTHENTICATION:
        if (credentials != null) {
          for (Map.Entry<String, ?> kv : credentials.toJson()) {
            String key = kv.getKey();
            sb.append(' ');
            escapeNLFChars(sb, key);
            sb.append('=');
            Object value = kv.getValue();
            if (value == null) {
              sb.append("null");
            } else {
              sb.append('"');
              if (MASKED.contains(key)) {
                sb.append(mask(value.toString()));
              } else {
                escapeNLFChars(sb, value.toString());
              }
              sb.append('"');
            }
          }
        }

        break;
      case AUTHORIZATION:
        if (user != null) {
          String sub = user.subject();
          if (sub != null) {
            sb.append(" subject=\"");
            escapeNLFChars(sb, sub);
            sb.append('"');
          }
        }
        if (authorization != null) {
          sb.append(" authorization=\"");
          escapeNLFChars(sb, authorization.toString());
          sb.append('"');
        }
        break;
      case REQUEST:
        sb.append(" status=").append(status);
        break;
    }
    sb
      .append("] ")
      .append(success ? "OK" : "FAIL");

    LOGGER.info(sb.toString());
  }

  private void auditJSON(Marker marker, boolean success) {
    final JsonObject json = new JsonObject();
    json.put("marker", marker.name());

    json.put("epoch", System.currentTimeMillis());

    if (source != null) {
      if (source.isInetSocket()) {
        json.put("source", source.host());
      } else {
        json.put("source", source.path());
      }
    }
    if (destination != null) {
      if (destination.isInetSocket()) {
        json.put("destination", destination.host());
      } else {
        json.put("destination", destination.path());
      }
    }
    if (resource != null) {
      json.put("resource", resource);
    }

    switch (marker) {
      case AUTHENTICATION:
        if (credentials != null) {
          for (Map.Entry<String, ?> kv : credentials.toJson()) {
            String key = kv.getKey();
            Object value = kv.getValue();
            if (value != null) {
              if (MASKED.contains(key)) {
                json.put(key, mask(value.toString()));
              } else {
                json.put(key, value.toString());
              }
            }
          }
        }
        break;
      case AUTHORIZATION:
        if (user != null) {
          String sub = user.subject();
          if (sub != null) {
            json.put("subject", sub);
          }
        }
        if (authorization != null) {
          json.put("authorization", authorization.toString());
        }
        break;
      case REQUEST:
        json.put("status", status);
        break;
    }

    json.put("result", success ? "OK" : "FAIL");

    LOGGER.info(json.encode());
  }
}
