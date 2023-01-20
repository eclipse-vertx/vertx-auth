package io.vertx.ext.auth.audit.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.ext.auth.audit.Marker;
import io.vertx.ext.auth.audit.AuditLogger;
import io.vertx.ext.auth.audit.StructuredData;
import io.vertx.ext.auth.impl.Codec;
import io.vertx.ext.auth.impl.jose.JWK;
import io.vertx.ext.auth.impl.jose.JWS;

import java.nio.charset.StandardCharsets;
import java.util.*;

public class SecurityLoggerImpl implements AuditLogger {

  public static final AuditLogger INSTANCE = new SecurityLoggerImpl();

  private static JWS SIGNATURE;

  public static void init(JWK key) {
    Objects.requireNonNull(key, "'key' cannot be null");
    SIGNATURE = new JWS(key);
  }

  @Override
  public void succeeded(Marker marker, StructuredData data) {
    StringBuffer sb = new StringBuffer();
    encodeStructuredData(sb, marker, data);
    if (marker.signed() && SIGNATURE != null) {
      String signature = Codec.base64Encode(SIGNATURE.sign(sb.toString().getBytes(StandardCharsets.UTF_8)));
      sb.append("; sig=").append(signature);
    }
    if (marker.logger().isInfoEnabled()) {
      marker.logger().info(sb);
    }
  }

  @Override
  public void failed(Marker marker, StructuredData data, Throwable cause) {
    StringBuffer sb = new StringBuffer();
    encodeStructuredData(sb, marker, data);
    sb.append(' ');
    if (cause != null) {
      escapeNLFChars(sb, cause.getMessage());
    }
    if (marker.signed() && SIGNATURE != null) {
      String signature = Codec.base64Encode(SIGNATURE.sign(sb.toString().getBytes(StandardCharsets.UTF_8)));
      sb.append("; sig=").append(signature);
    }
    if (marker.logger().isWarnEnabled()) {
      marker.logger().warn(sb);
    }
  }

  @Override
  public <T> Handler<AsyncResult<T>> handle(Marker marker, StructuredData data) {
    return event -> {
      if (event.succeeded()) {
        succeeded(marker, data);
      } else {
        failed(marker, data, event.cause());
      }
    };
  }

  private static final String MASK = "********************************";

  private String mask(String input) {
    int len = input.length();
    if (len > 32) {
      return MASK + "...";
    }
    return MASK.substring(0, len);
  }

  private void encodeStructuredData(StringBuffer sb, Marker marker, StructuredData structuredData) {
    if (structuredData == null) {
      sb.append('-');
    } else {
      sb.append('[');

      sb.append("iat=").append(structuredData.getIat());
      if (structuredData.getSub() != null) {
        sb.append(" sub=\"");
        if (marker.mask("sub")) {
          sb.append(mask(structuredData.getSub()));
        } else {
          escapeNLFChars(sb, structuredData.getSub());
        }
        sb.append('"');
      }
      if (structuredData.getResource() != null) {
        sb.append(" resource=\"");
        if (marker.mask("resource")) {
          sb.append(mask(structuredData.getResource()));
        } else {
          escapeNLFChars(sb, structuredData.getResource());
        }
        sb.append('"');
      }
      if (structuredData.getWants() != null) {
        sb.append(" wants=[");
        for (int i = 0; i < structuredData.getWants().size(); i++) {
          if (i != 0) {
            sb.append(',');
          }
          if (marker.mask("wants")) {
            sb.append(mask(structuredData.getWants().get(i).getClass().getName()));
          } else {
            escapeNLFChars(sb, structuredData.getWants().get(i).getClass().getName());
          }
        }
        sb.append(']');
      }

      if (structuredData.getHas() != null) {
        sb.append(" has=[");
        for (int i = 0; i < structuredData.getHas().size(); i++) {
          if (i != 0) {
            sb.append(',');
          }
          if (marker.mask("has")) {
            sb.append(mask(structuredData.getHas().get(i).getClass().getName()));
          } else {
            escapeNLFChars(sb, structuredData.getHas().get(i).getClass().getName());
          }
        }
        sb.append(']');
      }

      if (structuredData.getExtra() != null) {
        for (Map.Entry<String, ?> kv : structuredData.getExtra().entrySet()) {
          String key = kv.getKey();
          if ("sub".equals(key) || "resource".equals(key)) {
            continue;
          }
          sb.append(' ');
          escapeNLFChars(sb, key);
          sb.append('=');
          Object value = kv.getValue();
          if (value == null) {
            sb.append("null");
          } else {
            sb.append('"');
            if (marker.mask(key)) {
              sb.append(mask(value.toString()));
            } else {
              escapeNLFChars(sb, value.toString());
            }
            sb.append('"');
          }
        }
      }

      sb.append(']');
    }
  }

  /**
   * Escape any NLF (newline function) and Backspace to prevent log injection attacks.
   *
   * @param value string to convert
   * @return converted string
   * @see <a href="https://unicode.org/versions/Unicode14.0.0/UnicodeStandard-14.0.pdf#page=235">Unicode Standard</a>
   */
  private static void escapeNLFChars(StringBuffer sb, String value) {
    for (char c : value.toCharArray()) {
      switch (c) {
        case '\n':
          sb.append("\\n");
          break;
        case '\r':
          sb.append("\\r");
          break;
        case '"':
          sb.append("\\\"");
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
}
