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

public interface ISO7816 extends javacard.framework.ISO7816 {
    /**
     * Instructions for the Identity Credential Store
     */
    byte INS_ICS_GET_VERSION = (byte) 0x50;
    byte INS_ICS_PING = (byte) 0x51;
    byte INS_ICS_TEST_CBOR = (byte) 0x53;
    byte INS_ICS_GET_HARDWARE_INFO = (byte) 0x54;

    /**
     * Credential provisioning instructions
     */
    byte INS_ICS_PROVISIONING_INIT = (byte) 0x10;
    byte INS_ICS_CREATE_CREDENTIAL_KEY = (byte) 0x11;
    byte INS_ICS_START_PERSONALIZATION = (byte) 0x12;
    byte INS_ICS_ADD_ACCESS_CONTROL_PROFILE = (byte) 0x13;
    byte INS_ICS_BEGIN_ADD_ENTRY = (byte) 0x14;
    byte INS_ICS_ADD_ENTRY_VALUE = (byte) 0x15;
    byte INS_ICS_FINISH_ADDING_ENTRIES = (byte) 0x16;
    byte INS_ICS_FINISH_GET_CREDENTIAL_DATA = (byte) 0x17;
     

    /**
     * Credential Presentation instructions
     */
    byte INS_ICS_PRESENTATION_INIT = (byte) 0x30;
    byte INS_ICS_CREATE_EPHEMERAL_KEY_PAIR = (byte) 0x31;
    byte INS_ICS_CREATE_AUTH_CHALLENGE = (byte) 0x32;
    byte INS_ICS_START_RETRIEVAL = (byte) 0x33;
    byte INS_ICS_SET_AUTH_TOKEN = (byte) 0x34;
    byte INS_ICS_PUSH_READER_CERT = (byte) 0x35;
    byte INS_ICS_VALIDATE_ACCESS_CONTROL_PROFILES = (byte) 0x36;
    byte INS_ICS_VALIDATE_REQUEST_MESSAGE = (byte) 0x37;
    byte INS_ICS_CAL_MAC_KEY = (byte) 0x38;
    byte INS_ICS_START_RETRIEVE_ENTRY_VALUE = (byte) 0x39;
    byte INS_ICS_RETRIEVE_ENTRY_VALUE = (byte) 0x3A;
    byte INS_ICS_FINISH_RETRIEVAL = (byte) 0x3B;
    byte INS_ICS_GENERATE_SIGNING_KEY_PAIR = (byte) 0x3C;
    byte INS_ICS_PROVE_OWNERSHIP  = (byte) 0x3D;
    byte INS_ICS_DELETE_CREDENTIAL = (byte) 0x3E;
    byte INS_ICS_UPDATE_CREDENTIAL = (byte) 0x3F;
    
    /**
     * Instruction bytes for standard ISO7816-4 commands 
     */
    byte INS_GET_RESPONSE = (byte) 0xC0;
    
    /**
     * Error messages
     */
    short SW_INSUFFICIENT_MEMORY = (short) 0x6A84;

    interface AccessCheckResult {
        // Returned if access is granted.
        short ERR_ACCESS_CHECK_RESULT_OK = (short) 0;

        // Returned if an error occurred checking for access.
        short ERR_ACCESS_CHECK_RESULT_FAILED = (short) 1;

        // Returned if access was denied because item is configured without any
        // access control profiles.
        short ERR_ACCESS_CHECK_RESULT_NO_ACCESS_CONTROL_PROFILES = (short) 2;

        // Returned if access was denied because of user authentication.
        short ERR_ACCESS_CHECK_RESULT_USER_AUTHENTICATION_FAILED = (short) 3;

        // Returned if access was denied because of reader authentication.
        short ERR_ACCESS_CHECK_RESULT_READER_AUTHENTICATION_FAILED = (short) 4;
    }
}
