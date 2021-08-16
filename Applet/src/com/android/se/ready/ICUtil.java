/*
**
** Copyright 2019, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

package com.android.se.ready;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.MessageDigest;

public class ICUtil {

    /**
     * Get the sign bit of a given short (returns 0 or 1)
     */
    public static short sign(short a) {
        return (byte) ((a >>> (short) 15) & 1);
    }

    /**
     * Return the smaller short of two given values
     */
    public static short min(short a, short b) {
        if (a < b) {
            return a;
        }
        return b;
    }

    /**
     * Return the bigger short of two given values
     */
    public static short max(short a, short b) {
        if (a > b) {
            return a;
        }
        return b;
    }

    /**
     * Set the bit in a given bitfield array
     * 
     * @param bitField The bitfield array
     * @param flag     Index in the bitfield where the bit should be set
     * @param value    Sets bit to 0 or 1
     */
    public static void setBit(byte[] bitField, short flag, boolean value) {
        short byteIndex = (short) (flag >>> (short) 3);
        byte bitMask = (byte) ((byte) 1 << (short) (flag & (short) 0x0007));
        if (value) {
            bitField[byteIndex] |= bitMask;
        } else {
            bitField[byteIndex] &= ~bitMask;
        }
    }

    /**
     * Get the value of a bit inside a bitfield
     * 
     * @param bitField The bitfield 
     * @param flag     Index in the bitfield that should be read
     * @return Value at the index (0 or 1)
     */
    public static boolean getBit(byte bitField, byte flag) {
        byte bitMask = (byte) ((byte) 1 << (short) (flag & 0x07));
        return bitMask == (byte) (bitField & bitMask);
    }

    /**
     * Set the bit in a given bitfield 
     * 
     * @param bitField The bitfield 
     * @param flag     Index in the bitfield where the bit should be set
     * @param value    Sets bit to 0 or 1
     */
    public static byte setBit(byte bitField, byte flag, boolean value) {
        byte bitMask = (byte) ((byte) 1 << (short) (flag & 0x07));
        if (value) {
            bitField |= bitMask;
        } else {
            bitField &= ~bitMask;
        }
        return bitField;
    }

    /**
     * Get the value of a bit inside a bitfield
     * 
     * @param bitField The bitfield array
     * @param flag     Index in the bitfield that should be read
     * @return Value at the index (0 or 1)
     */
    public static boolean getBit(byte[] bitField, short flag) {
        short byteIndex = (short) (flag >>> (short) 3);
        byte bitMask = (byte) ((byte) 1 << (short) (flag & (short) 0x0007));
        return bitMask == (byte) (bitField[byteIndex] & bitMask);
    }

    /**
     * Compare two signed shorts as unsigned value. Returns true if n1 is truly
     * smaller, false otherwise.
     */
    public static boolean isLessThanAsUnsignedShort(short n1, short n2) {
        return (n1 < n2) ^ ((n1 < 0) != (n2 < 0));
    }
    
    /**
     * Fill a provided short array with a given value.
     */
    public static short shortArrayFillNonAtomic(short[] buffer, short offset, short len, short value) {
        len += offset;
        for (; offset < len; offset++) {
            buffer[offset] = value;
        }
        return offset;
    }
    
    /**
     * Increment a byte array by adding another byte array of same size or less than first byte array.
     * The addition is incremented in first byte array itself.
     * @param first byte array of short/integer/long value where addition will be updated
     * @param firstOffset start offset of first byte array
     * @param firstLen length of first byte array
     * @param second byte array of short/integer/long value
     * @param secondOffset start offset of second byte array
     * @param secondLen length of second byte array
     */
    public static void incrementByteArray(byte[] first, short firstOffset, byte firstLen, byte[] second, short secondOffset, byte secondLen) {
        byte index = (byte)(firstLen - 1);
        short sum;
        byte carry = (byte)0;
        while(index > (byte)0) {
            if(index >= (firstLen - secondLen)) {
                short a1 = (short)(first[(short)(firstOffset + index)] & 0x00FF);
                short a2 = (short)(second[(short)(secondOffset + index - (short)(firstLen - secondLen))] & 0x00FF);
                sum = (short)(carry + a1 + a2);
            } else {
                short a1 = (short)(first[(short)(firstOffset + index)] & 0x00FF);
                sum = (short)(carry + a1);
            }
            first[(short)(firstOffset + index)] = (byte)sum;
            carry = (byte) (sum > 255 ? 1 : 0);
            index--;
        }
    }

    public static short constructCBORAccessControl(CBORDecoder cborDecoder, CBOREncoder cborEncoder,
                                             byte[] inBuff, short inOffset, short inLen,
                                             byte[] outBuff, short outOffset, short outLen,
                                             boolean withSecureUserId) {
        short numPairs = (short) 1;

        cborDecoder.init(inBuff, inOffset, inLen);
        cborEncoder.init(outBuff, outOffset, outLen);

        cborDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        short id = cborDecoder.readInt8();
        boolean userAuthRequired = cborDecoder.readBoolean();
        cborDecoder.skipEntry(); //TimeoutMilis
        boolean secureUserIdPresent = false;
        if(userAuthRequired) {
            numPairs += 2;
            if(withSecureUserId) {
                byte intSize = cborDecoder.getIntegerSize();
                if(intSize == ICConstants.BYTE_SIZE) {
                    short secureUserId = cborDecoder.readInt8();
                    if(secureUserId > (short)0) {
                        secureUserIdPresent = true;
                        numPairs += 1;
                    }
                } else {
                    cborDecoder.skipEntry();
                    secureUserIdPresent = true;
                    numPairs += 1;
                }
            } else {
                cborDecoder.skipEntry();
            }
        } else {
            cborDecoder.skipEntry();
        }
        short readerCertSize = cborDecoder.readLength();
        if(readerCertSize > (short)0) {
            numPairs += 1;
        }
        cborEncoder.startMap(numPairs);
        cborEncoder.encodeTextString(ICConstants.STR_ID, (short)0, (short) ICConstants.STR_ID.length);
        if(id < (short)256) {
            cborEncoder.encodeUInt8((byte)id);
        } else {
            cborEncoder.encodeUInt16((short)id);
        }
        if(readerCertSize > (short)0) {
            //We have already traversed up to readerCertificate, so encode it from decoder
            cborEncoder.encodeTextString(ICConstants.STR_READER_CERTIFICATE, (short)0, (short) ICConstants.STR_READER_CERTIFICATE.length);
            //short encodeReaderCertOffset = cborEncoder.startByteString(readerCertSize);
            //Util.arrayCopyNonAtomic(cborDecoder.getBuffer(), cborDecoder.getCurrentOffset(), outBuff, encodeReaderCertOffset, readerCertSize);
            //cborEncoder.increaseOffset(readerCertSize);
            cborEncoder.encodeByteString(cborDecoder.getBuffer(), cborDecoder.getCurrentOffset(), readerCertSize);
        }
        cborDecoder.reset();
        //Lets init decoder again to read timeoutMilis and secureUserId
        cborDecoder.init(inBuff, inOffset, inLen);
        cborDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        cborDecoder.skipEntry();//id
        userAuthRequired = cborDecoder.readBoolean();//userAuthRequired
        if(userAuthRequired) {
            cborEncoder.encodeTextString(ICConstants.STR_USER_AUTH_REQUIRED, (short)0, (short) ICConstants.STR_USER_AUTH_REQUIRED.length);
            cborEncoder.encodeBoolean(userAuthRequired);
            cborEncoder.encodeTextString(ICConstants.STR_TIMEOUT_MILIS, (short)0, (short) ICConstants.STR_TIMEOUT_MILIS.length);
            byte intSize = cborDecoder.getIntegerSize();
            if(intSize == ICConstants.BYTE_SIZE) {
                //outBuffer[cborEncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_BYTE_STRING << 5) | CBORBase.ENCODED_ONE_BYTE;
                cborEncoder.encodeUInt8(cborDecoder.readInt8());
            } else if (intSize == ICConstants.SHORT_SIZE) {
                outBuff[cborEncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_UNSIGNED_INTEGER << 5) | CBORBase.ENCODED_TWO_BYTES;
                Util.arrayCopyNonAtomic(inBuff, (short)(cborDecoder.getCurrentOffset() + 1), outBuff, cborEncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
            } else if(intSize == ICConstants.INT_SIZE) {
                outBuff[cborEncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_UNSIGNED_INTEGER << 5) | CBORBase.ENCODED_FOUR_BYTES;
                Util.arrayCopyNonAtomic(inBuff, (short)(cborDecoder.getCurrentOffset() + 1), outBuff, cborEncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
            } else if(intSize == ICConstants.LONG_SIZE) {
                outBuff[cborEncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_UNSIGNED_INTEGER << 5) | CBORBase.ENCODED_EIGHT_BYTES;
                Util.arrayCopyNonAtomic(inBuff, (short)(cborDecoder.getCurrentOffset() + 1), outBuff, cborEncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
            }

            if(withSecureUserId && secureUserIdPresent) {
                cborEncoder.encodeTextString(ICConstants.STR_SECURE_USER_ID, (short)0, (short) ICConstants.STR_SECURE_USER_ID.length);
                intSize = cborDecoder.getIntegerSize();
                if(intSize == ICConstants.BYTE_SIZE) {
                    //outBuffer[cborEncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_BYTE_STRING << 5) | CBORBase.ENCODED_ONE_BYTE;
                    cborEncoder.encodeUInt8(cborDecoder.readInt8());
                } else if (intSize == ICConstants.SHORT_SIZE) {
                    outBuff[cborEncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_UNSIGNED_INTEGER << 5) | CBORBase.ENCODED_TWO_BYTES;
                    Util.arrayCopyNonAtomic(inBuff, (short)(cborDecoder.getCurrentOffset() + 1), outBuff, cborEncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
                } else if(intSize == ICConstants.INT_SIZE) {
                    outBuff[cborEncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_UNSIGNED_INTEGER << 5) | CBORBase.ENCODED_FOUR_BYTES;
                    Util.arrayCopyNonAtomic(inBuff, (short)(cborDecoder.getCurrentOffset() + 1), outBuff, cborEncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
                } else if(intSize == ICConstants.LONG_SIZE) {
                    outBuff[cborEncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_UNSIGNED_INTEGER << 5) | CBORBase.ENCODED_EIGHT_BYTES;
                    Util.arrayCopyNonAtomic(inBuff, (short)(cborDecoder.getCurrentOffset() + 1), outBuff, cborEncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
                }
            } else {
                cborDecoder.skipEntry();
            }
        }

        return cborEncoder.getCurrentOffset();
    }

    public static short constAndCalcCBOREntryAdditionalData(CBORDecoder cborDecoder, CBOREncoder cborEncoder,
                                                            MessageDigest messageDigest,
                                                   byte[] inBuff, short inOffset, short inLen,
                                                   byte[] outBuff, short outOffset, short outLen,
                                                   byte[] shaOut, short shaOutOff,
                                                   byte[] tempBuffer, short tempBuffOffset) {

        cborDecoder.init(inBuff, inOffset, inLen);
        cborEncoder.init(outBuff, outOffset, outLen);
        cborDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        cborEncoder.startMap((short) 3);
        //encode key as Namespace string
        cborEncoder.encodeTextString(ICConstants.STR_NAME_SPACE, (short)0, (short) ICConstants.STR_NAME_SPACE.length);
        //Hold nameSpace in temp variable
        short nameSpaceLen = cborDecoder.readByteString(tempBuffer, tempBuffOffset);
        //encode nameSpace string
        cborEncoder.encodeTextString(tempBuffer, tempBuffOffset, nameSpaceLen);
        //encode key as Name string, lets use it from Namespace string
        cborEncoder.encodeTextString(ICConstants.STR_NAME_SPACE, (short)0, (short)4);
        //read name parameter
        short nameLen = cborDecoder.readByteString(tempBuffer, tempBuffOffset);
        cborEncoder.encodeTextString(tempBuffer, tempBuffOffset, nameLen);

        //encode key as AccessControlProfileIds string
        cborEncoder.encodeTextString(ICConstants.STR_ACCESS_CONTROL_PROFILE_IDS, (short)0, (short) ICConstants.STR_ACCESS_CONTROL_PROFILE_IDS.length);
        short acpIdLen = cborDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        cborEncoder.startArray(acpIdLen);
        for(short i = (short)0; i < acpIdLen; i++) {
            byte intSize = cborDecoder.getIntegerSize();
            if(intSize == ICConstants.BYTE_SIZE) {
                cborEncoder.encodeUInt8(cborDecoder.readInt8());
            } else if(intSize == ICConstants.SHORT_SIZE) {
                cborEncoder.encodeUInt16(cborDecoder.readInt16());
            } else {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
        }
        messageDigest.doFinal(outBuff, outOffset, (short)(cborEncoder.getCurrentOffset() - outOffset), shaOut, shaOutOff);

        return (short)(cborEncoder.getCurrentOffset() - outOffset);
    }

    /**
     * Reads unsigned integer value of any size from CBORDecoder and copy in out buffer.
     * @param cborDecoder CBOR decoder to read UInt from
     * @param outBuff Out put UInt value.
     * @param outBuffOffset Out buffer offset
     * @return length of UInt
     */
    public static short readUInt(CBORDecoder cborDecoder, byte[] outBuff, short outBuffOffset) {
        if(cborDecoder.getMajorType() != CBORBase.TYPE_UNSIGNED_INTEGER) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        byte intSize = cborDecoder.getIntegerSize();
        if(intSize == ICConstants.BYTE_SIZE) {
            outBuff[outBuffOffset] = cborDecoder.readInt8();
        } else if (intSize == ICConstants.SHORT_SIZE) {
            Util.arrayCopyNonAtomic(cborDecoder.getBuffer(), (short)(cborDecoder.getCurrentOffset() + 1), outBuff, outBuffOffset, intSize);
            cborDecoder.increaseOffset((short)(intSize + 1));
        } else if(intSize == ICConstants.INT_SIZE) {
            Util.arrayCopyNonAtomic(cborDecoder.getBuffer(), (short)(cborDecoder.getCurrentOffset() + 1), outBuff, outBuffOffset, intSize);
            cborDecoder.increaseOffset((short)(intSize + 1));
        } else if(intSize == ICConstants.LONG_SIZE) {
            Util.arrayCopyNonAtomic(cborDecoder.getBuffer(), (short)(cborDecoder.getCurrentOffset() + 1), outBuff, outBuffOffset, intSize);
            cborDecoder.increaseOffset((short)(intSize + 1));
        }
        return intSize;
    }

    /**
     * Calculates size of required bytes to encode given size of data
     * @param size of data.
     * @return size of required bytes to encode given size of data.
     */
    public static byte calCborAdditionalLengthBytesFor(short size) {
        if (size < 24) {
            return (byte)0;
        } else if (size <= 0xff) {
            return ICConstants.BYTE_SIZE;
        }
        return ICConstants.SHORT_SIZE;
    }

    /**
     * Calculates size of required bytes to encode given size of data
     * @param valueBuff size of data in byte array
     * @param valueOffset size byte array offset
     * @param valueSize size byte array length
     * @return size of required bytes to encode given size of data.
     */
    public static byte calCborAdditionalLengthBytesFor(byte[] valueBuff, short valueOffset, short valueSize) {
        if(valueSize <= 0 || valueSize > 8) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        byte i = 0;
        for (; valueBuff[(short)(valueOffset + i)] == 0x0 && i < valueSize; i++);
        if(i > 0) {
            valueSize = (short) (valueSize - i);
        }
        return  valueSize > ICConstants.INT_SIZE ? ICConstants.LONG_SIZE : valueSize > ICConstants.SHORT_SIZE ? ICConstants.INT_SIZE : valueSize > ICConstants.BYTE_SIZE ? ICConstants.SHORT_SIZE : (short)(valueBuff[(short)(valueOffset + i)] & 0x00FF) > (short)24 ? ICConstants.BYTE_SIZE : (byte)0;
    }

    public static byte arrayCompare(byte src[], short srcOff, byte dest[], short destOff, short length) {
        if (length < 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        for (short i = 0; i < length; i++) {
            if (src[(short)(srcOff + i)] != dest[(short)(destOff + i)]) {
                short thisSrc = (short) (src[(short)(srcOff + i)] & 0x00ff);
                short thisDest = (short) (dest[(short)(destOff + i)] & 0x00ff);
                return (byte) (thisSrc > thisDest ? 1 : -1);
            }
        }

        return 0;
    }
}
