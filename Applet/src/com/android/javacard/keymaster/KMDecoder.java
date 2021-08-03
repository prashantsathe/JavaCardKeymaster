/*
 * Copyright(C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class KMDecoder {

  // major types
  public static final short UINT_TYPE = 0x00;
  public static final short BYTES_TYPE = 0x40;
  public static final short ARRAY_TYPE = 0x80;
  public static final short MAP_TYPE = 0xA0;

  // masks
  private static final short ADDITIONAL_MASK = 0x1F;
  private static final short MAJOR_TYPE_MASK = 0xE0;

  // value length
  private static final short UINT8_LENGTH = 0x18;
  private static final short UINT16_LENGTH = 0x19;
  private static final short UINT32_LENGTH = 0x1A;
  private static final short UINT64_LENGTH = 0x1B;

  private byte[] buffer;
  private short startOff;
  private short length;
  private short tagType;
  private short tagKey;

  public KMDecoder() {
    buffer = null;
    startOff = 0;
    length = 0;
  }

  public short decode(short expression, byte[] buffer, short startOff, short length) {
    this.buffer = buffer;
    this.startOff = startOff;
    this.length = (short) (startOff + length);
    return decode(expression);
  }

  public short decodeArray(short exp, byte[] buffer, short startOff, short length) {
    this.buffer = buffer;
    this.startOff = startOff;
    this.length = (short) (startOff + length);
    short payloadLength = readMajorTypeWithPayloadLength(ARRAY_TYPE);
    short expLength = KMArray.cast(exp).length();
    if (payloadLength > expLength) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    short index = 0;
    short obj;
    short type;
    short arrPtr = KMArray.instance(payloadLength);
    while (index < payloadLength) {
      type = KMArray.cast(exp).get(index);
      obj = decode(type);
      KMArray.cast(arrPtr).add(index, obj);
      index++;
    }
    return arrPtr;
  }

  private short decode(short exp) {
    byte type = KMType.getType(exp);
    switch (type) {
      case KMType.BYTE_BLOB_TYPE:
        return decodeByteBlob(exp);
      case KMType.INTEGER_TYPE:
        return decodeInteger(exp);
      case KMType.ARRAY_TYPE:
        return decodeArray(exp);
      case KMType.ENUM_TYPE:
        return decodeEnum(exp);
      case KMType.KEY_PARAM_TYPE:
        return decodeKeyParam(exp);
      case KMType.KEY_CHAR_TYPE:
        return decodeKeyChar(exp);
      case KMType.VERIFICATION_TOKEN_TYPE:
        return decodeVerificationToken(exp);
      case KMType.HMAC_SHARING_PARAM_TYPE:
        return decodeHmacSharingParam(exp);
      case KMType.HW_AUTH_TOKEN_TYPE:
        return decodeHwAuthToken(exp);
      case KMType.TAG_TYPE:
        short tagType = KMTag.getTagType(exp);
        return decodeTag(tagType, exp);
      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return 0;
    }
  }

  private short decodeTag(short tagType, short exp) {
    switch (tagType) {
      case KMType.BIGNUM_TAG:
        return decodeBignumTag(exp);
      case KMType.BYTES_TAG:
        return decodeBytesTag(exp);
      case KMType.BOOL_TAG:
        return decodeBoolTag(exp);
      case KMType.UINT_TAG:
      case KMType.ULONG_TAG:
      case KMType.DATE_TAG:
        return decodeIntegerTag(exp);
      case KMType.ULONG_ARRAY_TAG:
      case KMType.UINT_ARRAY_TAG:
        return decodeIntegerArrayTag(exp);
      case KMType.ENUM_TAG:
        return decodeEnumTag(exp);
      case KMType.ENUM_ARRAY_TAG:
        return decodeEnumArrayTag(exp);
      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return 0;
    }
  }

  private short decodeVerificationToken(short exp) {
    short vals = decode(KMVerificationToken.cast(exp).getVals());
    return KMVerificationToken.instance(vals);
  }

  private short decodeHwAuthToken(short exp) {
    short vals = decode(KMHardwareAuthToken.cast(exp).getVals());
    return KMHardwareAuthToken.cast(exp).instance(vals);
  }

  private short decodeHmacSharingParam(short exp) {
    short vals = decode(KMHmacSharingParameters.cast(exp).getVals());
    return KMHmacSharingParameters.instance(vals);
  }

  private short decodeKeyChar(short exp) {
    short vals = decode(KMKeyCharacteristics.cast(exp).getVals());
    return KMKeyCharacteristics.instance(vals);
  }

  private short decodeKeyParam(short exp) {
    short payloadLength = readMajorTypeWithPayloadLength(MAP_TYPE);
    // allowed tags
    short allowedTags = KMKeyParameters.cast(exp).getVals();
    short tagRule = KMArray.cast(allowedTags).get((short)0);
    boolean ignoreInvalidTags = KMEnum.cast(tagRule).getVal() == KMType.IGNORE_INVALID_TAGS;
    short vals = KMArray.instance(payloadLength);
    short length = KMArray.cast(allowedTags).length();
    short index = 0;
    boolean tagFound;
    short tagInd;
    short tagType;
    short tagClass;
    short allowedType;
    short obj;
    // For each tag in payload ...
    while (index < payloadLength) {
      tagFound = false;
      tagInd = 1;
      tagType = peekTagType();
      // Check against the allowed tags ...
      while (tagInd < length) {
        tagClass = KMArray.cast(allowedTags).get(tagInd);
        allowedType = KMTag.getTagType(tagClass);
        // If it is part of allowed tags ...
        if (tagType == allowedType) {
          // then decodeByteBlob and add that to the array.
          try {
            tagFound = true;
            obj = decode(tagClass);
            KMArray.cast(vals).add(index, obj);
            break;
          }catch(KMException e){
            if(KMException.reason() == KMError.INVALID_TAG &&
            !ignoreInvalidTags){
              KMException.throwIt(KMError.INVALID_TAG);
            }
          }
        }
        tagInd++;
      }
      if (!tagFound) {
        KMException.throwIt(KMError.INVALID_TAG);
      } else {
        index++;
      }
    }
    return KMKeyParameters.instance(vals);
  }

  private short decodeEnumArrayTag(short exp) {
    readTagKey(KMEnumArrayTag.cast(exp).getTagType());
    return KMEnumArrayTag.instance(this.tagKey, decode(KMEnumArrayTag.cast(exp).getValues()));
  }

  private short decodeIntegerArrayTag(short exp) {
    readTagKey(KMIntegerArrayTag.cast(exp).getTagType());
    // the values are array of integers.
    return KMIntegerArrayTag.instance(KMIntegerArrayTag.cast(exp).getTagType(),
        this.tagKey, decode(KMIntegerArrayTag.cast(exp).getValues()));
  }

  private short decodeIntegerTag(short exp) {
    readTagKey(KMIntegerTag.cast(exp).getTagType());
    // the value is an integer
    return KMIntegerTag.instance(KMIntegerTag.cast(exp).getTagType(),
        this.tagKey, decode(KMIntegerTag.cast(exp).getValue()));
  }

  private short decodeBytesTag(short exp) {
    readTagKey(KMByteTag.cast(exp).getTagType());
    // The value must be byte blob
    return KMByteTag.instance(this.tagKey, decode(KMByteTag.cast(exp).getValue()));
  }

  private short decodeBignumTag(short exp) {
    readTagKey(KMBignumTag.cast(exp).getTagType());
    // The value must be byte blob
    return KMBignumTag.instance(this.tagKey, decode(KMBignumTag.cast(exp).getValue()));
  }

  private short decodeArray(short exp) {
    short payloadLength = readMajorTypeWithPayloadLength(ARRAY_TYPE);
    short arrPtr = KMArray.cast(exp).instance(payloadLength);
    short index = 0;
    short type;
    short obj;
    // check whether array contains one type of objects or multiple types
    if (KMArray.cast(exp).containedType() == 0) {// multiple types specified by expression.
      if (KMArray.cast(exp).length() != KMArray.ANY_ARRAY_LENGTH) {
        if (KMArray.cast(exp).length() != payloadLength) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
      }
      while (index < payloadLength) {
        type = KMArray.cast(exp).get(index);
        obj = decode(type);
        KMArray.cast(arrPtr).add(index, obj);
        index++;
      }
    } else { // Array is a Vector containing objects of one type
      type = KMArray.cast(exp).containedType();
      while (index < payloadLength) {
        obj = decode(type);
        KMArray.cast(arrPtr).add(index, obj);
        index++;
      }
    }
    return arrPtr;
  }

  private short decodeEnumTag(short exp) {
    readTagKey(KMEnumTag.cast(exp).getTagType());
    // Enum Tag value will always be integer with max 1 byte length.
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != UINT_TYPE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short len = (short) (buffer[startOff] & ADDITIONAL_MASK);
    byte enumVal = 0;
    if (len > UINT8_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (len < UINT8_LENGTH) {
      enumVal = (byte) (len & ADDITIONAL_MASK);
      incrementStartOff((short) 1);
    } else if (len == UINT8_LENGTH) {
      incrementStartOff((short) 1);
      enumVal = buffer[startOff];
      incrementStartOff((short) 1);
    }
    return KMEnumTag.instance(tagKey, enumVal);
  }

  private short decodeBoolTag(short exp) {
    readTagKey(KMBoolTag.cast(exp).getTagType());
    // BOOL Tag is a leaf node and it must always have tiny encoded uint value = 1.
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != UINT_TYPE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    if ((byte) (buffer[startOff] & ADDITIONAL_MASK) != 0x01) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    incrementStartOff((short) 1);
    return KMBoolTag.instance(tagKey);
  }

  private short decodeEnum(short exp) {
    // Enum value will always be integer with max 1 byte length.
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != UINT_TYPE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short len = (short) (buffer[startOff] & ADDITIONAL_MASK);
    byte enumVal;
    if (len > UINT8_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (len < UINT8_LENGTH) {
      enumVal = (byte) (len & ADDITIONAL_MASK);
      incrementStartOff((short) 1);
    } else {
      incrementStartOff((short) 1);
      enumVal = buffer[startOff];
      incrementStartOff((short) 1);
    }
    return KMEnum.instance(KMEnum.cast(exp).getEnumType(), enumVal);
  }

  private short decodeInteger(short exp) {
    short inst;
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != UINT_TYPE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short len = (short) (buffer[startOff] & ADDITIONAL_MASK);
    if (len > UINT64_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    incrementStartOff((short) 1);
    if (len < UINT8_LENGTH) {
      inst = KMInteger.uint_8((byte) (len & ADDITIONAL_MASK));
    } else if (len == UINT8_LENGTH) {
      inst = KMInteger.instance(buffer, startOff, (short) 1);
      incrementStartOff((short) 1);
    } else if (len == UINT16_LENGTH) {
      inst = KMInteger.instance(buffer, startOff, (short) 2);
      incrementStartOff((short) 2);
    } else if (len == UINT32_LENGTH) {
      inst = KMInteger.instance(buffer, startOff, (short) 4);
      incrementStartOff((short) 4);
    } else {
      inst = KMInteger.instance(buffer, startOff, (short) 8);
      incrementStartOff((short) 8);
    }
    return inst;
  }

  private short decodeByteBlob(short exp) {
    short payloadLength = readMajorTypeWithPayloadLength(BYTES_TYPE);
    short inst = KMByteBlob.instance(buffer, startOff, payloadLength);
    incrementStartOff(payloadLength);
    return inst;
  }

  private short peekTagType() {
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != UINT_TYPE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    if ((short) (buffer[startOff] & ADDITIONAL_MASK) != UINT32_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    return (short)
        ((Util.makeShort(buffer[(short) (startOff + 1)], buffer[(short) (startOff + 2)]))
            & KMType.TAG_TYPE_MASK);
  }

  private void readTagKey(short expectedTagType) {
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != UINT_TYPE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    if ((byte) (buffer[startOff] & ADDITIONAL_MASK) != UINT32_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    incrementStartOff((short) 1);
    this.tagType = readShort();
    this.tagKey = readShort();
    if (tagType != expectedTagType) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  // payload length cannot be more then 16 bits.
  private short readMajorTypeWithPayloadLength(short majorType) {
    short payloadLength = 0;
    byte val = readByte();
    if ((short) (val & MAJOR_TYPE_MASK) != majorType) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short lenType = (short) (val & ADDITIONAL_MASK);
    if (lenType > UINT16_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (lenType < UINT8_LENGTH) {
      payloadLength = lenType;
    } else if (lenType == UINT8_LENGTH) {
      payloadLength = (short) (readByte() & 0xFF);
    } else {
      payloadLength = readShort();
    }
    return payloadLength;
  }

  private short readShort() {
    short val = Util.makeShort(buffer[startOff], buffer[(short) (startOff + 1)]);
    incrementStartOff((short) 2);
    return val;
  }

  private byte readByte() {
    byte val = buffer[startOff];
    incrementStartOff((short) 1);
    return val;
  }

  private void incrementStartOff(short inc) {
    startOff += inc;
    if (startOff > this.length) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  public short readCertificateChainLengthAndHeaderLen(byte[] buf, short bufOffset,
      short bufLen) {
    this.buffer = buf;
    this.startOff = bufOffset;
    this.length = (short) (bufOffset + bufLen);
    short totalLen = readMajorTypeWithPayloadLength(BYTES_TYPE);
    totalLen += (short) (startOff - bufOffset);
    return totalLen;
  }
}
