/*
 * JACOB - CBOR implementation in Java.
 *
 * (C) Copyright - 2013 - J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package io.vertx.ext.auth.webauthn.impl;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Provides a decoder capable of handling CBOR encoded data from a {@link InputStream}.
 */
public final class CBOR implements AutoCloseable {

  /** Major type 0: unsigned integers. */
  public static final int TYPE_UNSIGNED_INTEGER = 0x00;
  /** Major type 1: negative integers. */
  public static final int TYPE_NEGATIVE_INTEGER = 0x01;
  /** Major type 2: byte string. */
  public static final int TYPE_BYTE_STRING = 0x02;
  /** Major type 3: text/UTF8 string. */
  public static final int TYPE_TEXT_STRING = 0x03;
  /** Major type 4: array of items. */
  public static final int TYPE_ARRAY = 0x04;
  /** Major type 5: map of pairs. */
  public static final int TYPE_MAP = 0x05;
  /** Major type 6: semantic tags. */
  public static final int TYPE_TAG = 0x06;
  /** Major type 7: floating point, simple data types. */
  public static final int TYPE_FLOAT_SIMPLE = 0x07;

  /** Denotes a one-byte value (uint8). */
  public static final int ONE_BYTE = 0x18;
  /** Denotes a two-byte value (uint16). */
  public static final int TWO_BYTES = 0x19;
  /** Denotes a four-byte value (uint32). */
  public static final int FOUR_BYTES = 0x1a;
  /** Denotes a eight-byte value (uint64). */
  public static final int EIGHT_BYTES = 0x1b;

  /** The CBOR-encoded boolean <code>false</code> value (encoded as "simple value"). */
  public static final int FALSE = 0x14;
  /** The CBOR-encoded boolean <code>true</code> value (encoded as "simple value"). */
  public static final int TRUE = 0x15;
  /** The CBOR-encoded <code>null</code> value (encoded as "simple value"). */
  public static final int NULL = 0x16;
  /** The CBOR-encoded "undefined" value (encoded as "simple value"). */
  public static final int UNDEFINED = 0x17;
  /** Denotes a half-precision float (two-byte IEEE 754). */
  public static final int HALF_PRECISION_FLOAT = 0x19;
  /** Denotes a single-precision float (four-byte IEEE 754). */
  public static final int SINGLE_PRECISION_FLOAT = 0x1a;
  /** Denotes a double-precision float (eight-byte IEEE 754). */
  public static final int DOUBLE_PRECISION_FLOAT = 0x1b;
  /** The CBOR-encoded "break" stop code for unlimited arrays/maps. */
  public static final int BREAK = 0x1f;

  /** Semantic tag value describing date/time values in the standard format (UTF8 string, RFC3339). */
  public static final int TAG_STANDARD_DATE_TIME = 0;
  /** Semantic tag value describing date/time values as Epoch timestamp (numeric, RFC3339). */
  public static final int TAG_EPOCH_DATE_TIME = 1;
  /** Semantic tag value describing a positive big integer value (byte string). */
  public static final int TAG_POSITIVE_BIGINT = 2;
  /** Semantic tag value describing a negative big integer value (byte string). */
  public static final int TAG_NEGATIVE_BIGINT = 3;
  /** Semantic tag value describing a decimal fraction value (two-element array, base 10). */
  public static final int TAG_DECIMAL_FRACTION = 4;
  /** Semantic tag value describing a big decimal value (two-element array, base 2). */
  public static final int TAG_BIGDECIMAL = 5;
  /** Semantic tag value describing an expected conversion to base64url encoding. */
  public static final int TAG_EXPECTED_BASE64_URL_ENCODED = 21;
  /** Semantic tag value describing an expected conversion to base64 encoding. */
  public static final int TAG_EXPECTED_BASE64_ENCODED = 22;
  /** Semantic tag value describing an expected conversion to base16 encoding. */
  public static final int TAG_EXPECTED_BASE16_ENCODED = 23;
  /** Semantic tag value describing an encoded CBOR data item (byte string). */
  public static final int TAG_CBOR_ENCODED = 24;
  /** Semantic tag value describing an URL (UTF8 string). */
  public static final int TAG_URI = 32;
  /** Semantic tag value describing a base64url encoded string (UTF8 string). */
  public static final int TAG_BASE64_URL_ENCODED = 33;
  /** Semantic tag value describing a base64 encoded string (UTF8 string). */
  public static final int TAG_BASE64_ENCODED = 34;
  /** Semantic tag value describing a regular expression string (UTF8 string, PCRE). */
  public static final int TAG_REGEXP = 35;
  /** Semantic tag value describing a MIME message (UTF8 string, RFC2045). */
  public static final int TAG_MIME_MESSAGE = 36;
  /** Semantic tag value describing CBOR content. */
  public static final int TAG_CBOR_MARKER = 55799;

  private final PushbackInputStream m_is;
  private final int length;

  /**
   * Creates a new {@link CBOR} instance.
   *
   * @param data the actual byte array to read the CBOR-encoded data from, cannot be <code>null</code>.
   */
  public CBOR(byte[] data) {
    Objects.requireNonNull(data, "'data' cannot be null");
    this.length = data.length;
    m_is = new PushbackInputStream(new ByteArrayInputStream(data));
  }

  @Override
  public void close() throws IOException {
    m_is.close();
  }

  /**
   * Prolog to reading an array value in CBOR format.
   *
   * @return the number of elements in the array to read, or <tt>-1</tt> in case of infinite-length arrays.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private long readArrayLength() throws IOException {
    return readMajorTypeWithSize(TYPE_ARRAY);
  }

  /**
   * Reads a boolean value in CBOR format.
   *
   * @return the read boolean.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private Boolean readBoolean() throws IOException {
    int b = readMajorType(TYPE_FLOAT_SIMPLE);
    if (b != FALSE && b != TRUE) {
      throw new IOException("Unexpected boolean value: " + b);
    }
    return b == TRUE;
  }

  /**
   * Reads a "break"/stop value in CBOR format.
   *
   * @return always <code>null</code>.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private Object readBreak() throws IOException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, BREAK);

    return null;
  }

  /**
   * Reads a byte string value in CBOR format.
   *
   * @return the read byte string, never <code>null</code>. In case the encoded string has a length of <tt>0</tt>, an empty string is returned.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private byte[] readByteString() throws IOException {
    long len = readMajorTypeWithSize(TYPE_BYTE_STRING);
    if (len < 0) {
      throw new IOException("Infinite-length byte strings not supported!");
    }
    if (len > Integer.MAX_VALUE) {
      throw new IOException("String length too long!");
    }
    return readFully(new byte[(int) len]);
  }

  /**
   * Prolog to reading a byte string value in CBOR format.
   *
   * @return the number of bytes in the string to read, or <tt>-1</tt> in case of infinite-length strings.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private long readByteStringLength() throws IOException {
    return readMajorTypeWithSize(TYPE_BYTE_STRING);
  }

  /**
   * Reads a double-precision float value in CBOR format.
   *
   * @return the read double value, values from {@link Float#MIN_VALUE} to {@link Float#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private Double readDouble() throws IOException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, DOUBLE_PRECISION_FLOAT);

    return Double.longBitsToDouble(readUInt64());
  }

  /**
   * Reads a single-precision float value in CBOR format.
   *
   * @return the read float value, values from {@link Float#MIN_VALUE} to {@link Float#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private Float readFloat() throws IOException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, SINGLE_PRECISION_FLOAT);

    return Float.intBitsToFloat((int) readUInt32());
  }

  /**
   * Reads a half-precision float value in CBOR format.
   *
   * @return the read half-precision float value, values from {@link Float#MIN_VALUE} to {@link Float#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private Double readHalfPrecisionFloat() throws IOException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, HALF_PRECISION_FLOAT);

    int half = readUInt16();
    int exp = (half >> 10) & 0x1f;
    int mant = half & 0x3ff;

    double val;
    if (exp == 0) {
      val = mant * Math.pow(2, -24);
    } else if (exp != 31) {
      val = (mant + 1024) * Math.pow(2, exp - 25);
    } else if (mant != 0) {
      val = Double.NaN;
    } else {
      val = Double.POSITIVE_INFINITY;
    }

    return ((half & 0x8000) == 0) ? val : -val;
  }

  /**
   * Reads a signed or unsigned integer value in CBOR format.
   *
   * @return the read integer value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private Long readInt() throws IOException {
    int ib = m_is.read();

    // in case of negative integers, extends the sign to all bits; otherwise zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does a ones complement
    return ui ^ readUInt(ib & 0x1f, false /* breakAllowed */);
  }

  /**
   * Reads a signed or unsigned 16-bit integer value in CBOR format.
   * read the small integer value, values from <tt>[-65536..65535]</tt> are supported.
   *
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying output stream.
   */
  private int readInt16() throws IOException {
    int ib = m_is.read();

    // in case of negative integers, extends the sign to all bits; otherwise zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does a ones complement
    return (int) (ui ^ readUIntExact(TWO_BYTES, ib & 0x1f));
  }

  /**
   * Reads a signed or unsigned 32-bit integer value in CBOR format.
   * read the small integer value, values in the range <tt>[-4294967296..4294967295]</tt> are supported.
   *
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying output stream.
   */
  private long readInt32() throws IOException {
    int ib = m_is.read();

    // in case of negative integers, extends the sign to all bits; otherwise zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does a ones complement
    return ui ^ readUIntExact(FOUR_BYTES, ib & 0x1f);
  }

  /**
   * Reads a signed or unsigned 64-bit integer value in CBOR format.
   * read the small integer value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   *
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying output stream.
   */
  private long readInt64() throws IOException {
    int ib = m_is.read();

    // in case of negative integers, extends the sign to all bits; otherwise zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does a ones complement
    return ui ^ readUIntExact(EIGHT_BYTES, ib & 0x1f);
  }

  /**
   * Reads a signed or unsigned 8-bit integer value in CBOR format.
   * read the small integer value, values in the range <tt>[-256..255]</tt> are supported.
   *
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying output stream.
   */
  private int readInt8() throws IOException {
    int ib = m_is.read();

    // in case of negative integers, extends the sign to all bits; otherwise zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does a ones complement
    return (int) (ui ^ readUIntExact(ONE_BYTE, ib & 0x1f));
  }

  /**
   * Prolog to reading a map of key-value pairs in CBOR format.
   *
   * @return the number of entries in the map, >= 0.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private long readMapLength() throws IOException {
    return readMajorTypeWithSize(TYPE_MAP);
  }

  /**
   * Reads a <code>null</code>-value in CBOR format.
   *
   * @return always <code>null</code>.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private Object readNull() throws IOException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, NULL);
    return null;
  }

  /**
   * Reads a single byte value in CBOR format.
   *
   * @return the read byte value.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private Byte readSimpleValue() throws IOException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, ONE_BYTE);
    return (byte) readUInt8();
  }

  /**
   * Reads a signed or unsigned small (&lt;= 23) integer value in CBOR format.
   * read the small integer value, values in the range <tt>[-24..23]</tt> are supported.
   *
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying output stream.
   */
  private int readSmallInt() throws IOException {
    int ib = m_is.read();

    // in case of negative integers, extends the sign to all bits; otherwise zero...
    long ui = expectIntegerType(ib);
    // in case of negative integers does a ones complement
    return (int) (ui ^ readUIntExact(-1, ib & 0x1f));
  }

  /**
   * Reads a semantic tag value in CBOR format.
   *
   * @return the read tag value.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private Long readTag() throws IOException {
    return readUInt(readMajorType(TYPE_TAG), false /* breakAllowed */);
  }

  /**
   * Reads an UTF-8 encoded string value in CBOR format.
   *
   * @return the read UTF-8 encoded string, never <code>null</code>. In case the encoded string has a length of <tt>0</tt>, an empty string is returned.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private String readTextString() throws IOException {
    long len = readMajorTypeWithSize(TYPE_TEXT_STRING);
    if (len < 0) {
      throw new IOException("Infinite-length text strings not supported!");
    }
    if (len > Integer.MAX_VALUE) {
      throw new IOException("String length too long!");
    }
    return new String(readFully(new byte[(int) len]), StandardCharsets.UTF_8);
  }

  /**
   * Prolog to reading an UTF-8 encoded string value in CBOR format.
   *
   * @return the length of the string to read, or <tt>-1</tt> in case of infinite-length strings.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private long readTextStringLength() throws IOException {
    return readMajorTypeWithSize(TYPE_TEXT_STRING);
  }

  /**
   * Reads an undefined value in CBOR format.
   *
   * @return always <code>null</code>.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private Object readUndefined() throws IOException {
    readMajorTypeExact(TYPE_FLOAT_SIMPLE, UNDEFINED);
    return null;
  }

  /**
   * Reads the next major type from the underlying input stream, and verifies whether it matches the given expectation.
   *
   * @param ib the expected major type, cannot be <code>null</code> (unchecked).
   * @return either <tt>-1</tt> if the major type was an signed integer, or <tt>0</tt> otherwise.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private long expectIntegerType(int ib) throws IOException {
    int majorType = ((ib & 0xFF) >>> 5);
    if ((majorType != TYPE_UNSIGNED_INTEGER) && (majorType != TYPE_NEGATIVE_INTEGER)) {
      throw new IOException("Unexpected type: [" + majorType + "]: expected [" + TYPE_UNSIGNED_INTEGER + " | " + TYPE_NEGATIVE_INTEGER + "]");
    }
    return -majorType;
  }

  /**
   * Reads the next major type from the underlying input stream, and verifies whether it matches the given expectation.
   *
   * @param majorType the expected major type, cannot be <code>null</code> (unchecked).
   * @return the read subtype, or payload, of the read major type.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private int readMajorType(int majorType) throws IOException {
    int ib = m_is.read();
    if (majorType != ((ib >>> 5) & 0x07)) {
      throw new IOException("Unexpected type: [" + ib + "]: expected [" + majorType + "]");
    }
    return ib & 0x1F;
  }

  /**
   * Reads the next major type from the underlying input stream, and verifies whether it matches the given expectations.
   *
   * @param majorType the expected major type, cannot be <code>null</code> (unchecked);
   * @param subtype   the expected subtype.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private void readMajorTypeExact(int majorType, int subtype) throws IOException {
    int st = readMajorType(majorType);
    if ((st ^ subtype) != 0) {
      throw new IOException("Unexpected subtype [" + st + "]: expected [" + subtype +"]");
    }
  }

  /**
   * Reads the next major type from the underlying input stream, verifies whether it matches the given expectation, and decodes the payload into a size.
   *
   * @param majorType the expected major type, cannot be <code>null</code> (unchecked).
   * @return the number of succeeding bytes, &gt;= 0, or <tt>-1</tt> if an infinite-length type is read.
   * @throws IOException in case of I/O problems reading the CBOR-encoded value from the underlying input stream.
   */
  private long readMajorTypeWithSize(int majorType) throws IOException {
    return readUInt(readMajorType(majorType), true /* breakAllowed */);
  }

  /**
   * Reads an unsigned integer with a given length-indicator.
   *
   * @param length the length indicator to use;
   * @return the read unsigned integer, as long value.
   * @throws IOException in case of I/O problems reading the unsigned integer from the underlying input stream.
   */
  private long readUInt(int length, boolean breakAllowed) throws IOException {
    long result = -1;
    if (length < ONE_BYTE) {
      result = length;
    } else if (length == ONE_BYTE) {
      result = readUInt8();
    } else if (length == TWO_BYTES) {
      result = readUInt16();
    } else if (length == FOUR_BYTES) {
      result = readUInt32();
    } else if (length == EIGHT_BYTES) {
      result = readUInt64();
    } else if (breakAllowed && length == BREAK) {
      return -1;
    }
    if (result < 0) {
      throw new IOException("Not well-formed CBOR integer found, invalid length: " + result);
    }
    return result;
  }

  /**
   * Reads an unsigned 16-bit integer value
   *
   * @return value the read value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  private int readUInt16() throws IOException {
    byte[] buf = readFully(new byte[2]);
    return (buf[0] & 0xFF) << 8 | (buf[1] & 0xFF);
  }

  /**
   * Reads an unsigned 32-bit integer value
   *
   * @return value the read value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  private long readUInt32() throws IOException {
    byte[] buf = readFully(new byte[4]);
    return ((long) (buf[0] & 0xFF) << 24 | (buf[1] & 0xFF) << 16 | (buf[2] & 0xFF) << 8 | (buf[3] & 0xFF)) & 0xffffffffL;
  }

  /**
   * Reads an unsigned 64-bit integer value
   *
   * @return value the read value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  private long readUInt64() throws IOException {
    byte[] buf = readFully(new byte[8]);
    return (buf[0] & 0xFFL) << 56 | (buf[1] & 0xFFL) << 48 | (buf[2] & 0xFFL) << 40 | (buf[3] & 0xFFL) << 32 | (buf[4] & 0xFFL) << 24 | (buf[5] & 0xFFL) << 16 | (buf[6] & 0xFFL) << 8 | (buf[7] & 0xFFL);
  }

  /**
   * Reads an unsigned 8-bit integer value
   *
   * @return value the read value, values from {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE} are supported.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  private int readUInt8() throws IOException {
    return m_is.read() & 0xff;
  }

  /**
   * Reads an unsigned integer with a given length-indicator.
   *
   * @param length the length indicator to use;
   * @return the read unsigned integer, as long value.
   * @throws IOException in case of I/O problems reading the unsigned integer from the underlying input stream.
   */
  private long readUIntExact(int expectedLength, int length) throws IOException {
    if (((expectedLength == -1) && (length >= ONE_BYTE)) || ((expectedLength >= 0) && (length != expectedLength))) {
      throw new IOException("Unexpected payload/length! Expected [" + expectedLength + "], but got [" + length + "].");
    }
    return readUInt(length, false /* breakAllowed */);
  }

  private byte[] readFully(byte[] buf) throws IOException {
    int len = buf.length;
    int n = 0, off = 0;
    while (n < len) {
      int count = m_is.read(buf, off + n, len - n);
      if (count < 0) {
        throw new EOFException();
      }
      n += count;
    }
    return buf;
  }

  /**
   * Reads any given item in CBOR-encoded format by introspecting its type.
   *
   * @return the read item, can be <code>null</code> in case a {@link CBOR#NULL} value is found.
   * @throws IOException in case of I/O problems writing the CBOR-encoded value to the underlying output stream.
   */
  @SuppressWarnings("unchecked")
  public <T> T readObject() throws IOException {
    // Peek at the next type...
    int p = m_is.read();
    if (p < 0) {
      // EOF, nothing to peek at...
      throw new EOFException("end of CBOR data");
    }
    m_is.unread(p);

    int mt = (p & 0xff) >>> 5;
    int subtype = p & 0x1f;

    switch (mt) {
      case TYPE_UNSIGNED_INTEGER:
      case TYPE_NEGATIVE_INTEGER:
        return (T) readInt();
      case TYPE_BYTE_STRING:
        return (T) readByteString();
      case TYPE_TEXT_STRING:
        return (T) readTextString();
      case TYPE_ARRAY: {
        long len = readArrayLength();

        List<Object> result = new ArrayList<>();
        for (int i = 0; len < 0 || i < len; i++) {
          Object item = readObject();
          if (len < 0 && (item == null)) {
            // break read...
            break;
          }
          result.add(item);
        }
        return (T) result;
      }
      case TYPE_MAP: {
        long len = readMapLength();

        Map<String, Object> result = new HashMap<>();
        for (long i = 0; len < 0 || i < len; i++) {
          Object key = readObject();
          if (len < 0 && (key == null)) {
            // break read...
            break;
          }
          // force key to be String (compatibility with JSON)
          result.put(key.toString(), readObject());
        }
        return (T) result;
      }
      case TYPE_TAG:
        return (T) readTag();
      case TYPE_FLOAT_SIMPLE:
        if (subtype < ONE_BYTE) {
          if (subtype == FALSE || subtype == TRUE) {
            return (T) readBoolean();
          } else if (subtype == NULL) {
            return (T) readNull();
          } else if (subtype == UNDEFINED) {
            return (T) readUndefined();
          }
        } else if (subtype == ONE_BYTE) {
          return (T) readSimpleValue();
        } else if (subtype == HALF_PRECISION_FLOAT) {
          return (T) readHalfPrecisionFloat();
        } else if (subtype == SINGLE_PRECISION_FLOAT) {
          return (T) readFloat();
        } else if (subtype == DOUBLE_PRECISION_FLOAT) {
          return (T) readDouble();
        } else if (subtype == BREAK) {
          return (T) readBreak();
        }
        break;
    }

    throw new IllegalStateException("Unsupported type: " + mt);
  }

  public int offset() throws IOException {
    return length - m_is.available();
  }
}
