package com.android.se.ready;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;

import static com.android.se.ready.ICConstants.*;

/**
 * A class to handle all provisioning related operations
 * with the help of CryptoManager and CBOR encoder and decoder.
 *
 */
final class JCICProvisioning {
	// Reference to internal Crypto Manager instance
	private CryptoManager mCryptoManager;

    // Reference to the internal CBOR decoder instance
    private final CBORDecoder mCBORDecoder;
    
    // Reference to the internal CBOR encoder instance
    private final CBOREncoder mCBOREncoder;

    // Digester object for calculating provisioned data digest 
    private final MessageDigest mDigest;
    // Digester object for calculating proof of provisioning data digest 
    private final MessageDigest mSecondaryDigest;
    // Digester object for calculating addition data digest
    private final MessageDigest mAdditionalDataDigester;

    private final short[] mEntryCounts;

    private final byte[] mIntExpectedCborSizeAtEnd;
    private final byte[] mIntCurrentCborSize;
    private final byte[] mIntCurrentEntrySize;
    private final byte[] mIntCurrentEntryNumBytesReceived;

    private final byte[] mAdditionalDataSha256;

    private final short[] mStatusWords;

	public JCICProvisioning(CryptoManager cryptoManager, CBORDecoder decoder, CBOREncoder encoder) {
		mCryptoManager = cryptoManager;
        mCBORDecoder = decoder;
        mCBOREncoder = encoder;
        
        mEntryCounts = JCSystem.makeTransientShortArray(MAX_NUM_NAMESPACES, JCSystem.CLEAR_ON_DESELECT);
        mStatusWords = JCSystem.makeTransientShortArray(STATUS_WORDS, JCSystem.CLEAR_ON_DESELECT);

        mAdditionalDataSha256 = JCSystem.makeTransientByteArray(ICConstants.SHA256_DIGEST_SIZE, JCSystem.CLEAR_ON_DESELECT);

        mDigest = mCryptoManager.mDigest;
        mSecondaryDigest = mCryptoManager.mSecondaryDigest;
        mAdditionalDataDigester = mCryptoManager.mAdditionalDataDigester;

        mIntExpectedCborSizeAtEnd = JCSystem.makeTransientByteArray(INT_SIZE, JCSystem.CLEAR_ON_RESET);
        mIntCurrentCborSize = JCSystem.makeTransientByteArray((short) (INT_SIZE + SHORT_SIZE), JCSystem.CLEAR_ON_RESET);
        mIntCurrentEntrySize = JCSystem.makeTransientByteArray(INT_SIZE, JCSystem.CLEAR_ON_RESET);
        mIntCurrentEntryNumBytesReceived = JCSystem.makeTransientByteArray((short) (INT_SIZE + SHORT_SIZE), JCSystem.CLEAR_ON_RESET);
	}

	public void reset() {
	    Util.arrayFillNonAtomic(mIntExpectedCborSizeAtEnd, (short)0, INT_SIZE, (byte)0);
	    Util.arrayFillNonAtomic(mIntCurrentCborSize, (short)0, (short)(INT_SIZE + SHORT_SIZE), (byte)0);
	    Util.arrayFillNonAtomic(mIntCurrentEntrySize, (short)0, INT_SIZE, (byte)0);
	    Util.arrayFillNonAtomic(mIntCurrentEntryNumBytesReceived, (short)0, (short)(INT_SIZE + SHORT_SIZE), (byte)0);
        Util.arrayFillNonAtomic(mAdditionalDataSha256, (short)0, ICConstants.SHA256_DIGEST_SIZE, (byte)0);

        mDigest.reset();
	    mSecondaryDigest.reset();
	    mAdditionalDataDigester.reset();
	    
        ICUtil.shortArrayFillNonAtomic(mEntryCounts, (short) 0, MAX_NUM_NAMESPACES, (short) 0);
        ICUtil.shortArrayFillNonAtomic(mStatusWords, (short) 0, STATUS_WORDS, (short) 0);
	}
	
	private void updatePrimaryDigest(byte[] data, short dataStart, short dataLen) {
		mDigest.update(data, dataStart, dataLen);

		Util.setShort(mIntCurrentCborSize, (short) INT_SIZE, dataLen);
		ICUtil.incrementByteArray(mIntCurrentCborSize, (short)0, INT_SIZE, mIntCurrentCborSize, (short) INT_SIZE, SHORT_SIZE);
	}
	private void updatePrimaryAndSecondaryDigest(byte[] data, short dataStart, short dataLen) {
		updatePrimaryDigest(data, dataStart, dataLen);
		mSecondaryDigest.update(data, dataStart, dataLen);
	}

	public void processAPDU(APDUManager apduManager) {
        apduManager.receiveAll();
        byte[] receiveBuffer = apduManager.getReceiveBuffer();
        short receivingDataOffset = apduManager.getOffsetIncomingData();
        short receivingDataLength = apduManager.getReceivingLength();
        short le = apduManager.setOutgoing(true);
        byte[] outBuffer = apduManager.getSendBuffer();
		byte[] tempBuffer = KMByteBlob.cast(JCICStoreApplet.getTempByteBlob()).getBuffer();
		short tempBufferOffset = KMByteBlob.cast(JCICStoreApplet.getTempByteBlob()).getStartOff();
		short tempBufferLen = KMByteBlob.cast(JCICStoreApplet.getTempByteBlob()).length();
        short outGoingLength = (short)0;

        switch(receiveBuffer[ISO7816.OFFSET_INS]) {
	        case ISO7816.INS_ICS_PROVISIONING_INIT:
                outGoingLength = processProvisioningInit(receiveBuffer, receivingDataOffset, receivingDataLength,
                        outBuffer, le, tempBuffer, tempBufferOffset, tempBufferLen);
	            break;
	        case ISO7816.INS_ICS_CREATE_CREDENTIAL_KEY:
	            //TODO need to create Remote Key Provisioning API
                outGoingLength = processCreateCredentialKey(receiveBuffer, receivingDataOffset, receivingDataLength,
                        outBuffer, le, tempBuffer, tempBufferOffset, tempBufferLen);
	            break;
	        case ISO7816.INS_ICS_START_PERSONALIZATION:
                outGoingLength = processStartPersonalization(receiveBuffer, receivingDataOffset, receivingDataLength,
                        outBuffer, le, tempBuffer, tempBufferOffset, tempBufferLen);
	            break;
	        case ISO7816.INS_ICS_ADD_ACCESS_CONTROL_PROFILE:
                outGoingLength = processAddAccessControlProfile(receiveBuffer, receivingDataOffset, receivingDataLength,
                        outBuffer, le, tempBuffer, tempBufferOffset, tempBufferLen);
	            break;
	        case ISO7816.INS_ICS_BEGIN_ADD_ENTRY:
                outGoingLength = processBeginAddEntry(receiveBuffer, receivingDataOffset, receivingDataLength,
                        outBuffer, le, tempBuffer, tempBufferOffset, tempBufferLen);
	            break;
	        case ISO7816.INS_ICS_ADD_ENTRY_VALUE:
                outGoingLength = processAddEntryValue(receiveBuffer, receivingDataOffset, receivingDataLength,
                        outBuffer, le, tempBuffer, tempBufferOffset, tempBufferLen);
	            break;
	        case ISO7816.INS_ICS_FINISH_ADDING_ENTRIES:
                outGoingLength = processFinishAddingEntries(receiveBuffer, receivingDataOffset, receivingDataLength,
                        outBuffer, le, tempBuffer, tempBufferOffset, tempBufferLen);
	            break;
	        case ISO7816.INS_ICS_FINISH_GET_CREDENTIAL_DATA:
                outGoingLength = processFinishGetCredentialData(receiveBuffer, receivingDataOffset, receivingDataLength,
                        outBuffer, le, tempBuffer, tempBufferOffset, tempBufferLen);
	            break;
            case ISO7816.INS_ICS_UPDATE_CREDENTIAL:
                outGoingLength = processUpdateCredential(receiveBuffer, receivingDataOffset, receivingDataLength,
                        outBuffer, le, tempBuffer, tempBufferOffset, tempBufferLen);
                break;
	        default: 
	            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        apduManager.setOutgoingLength(outGoingLength);
	}

    private short processProvisioningInit(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
                                         byte[] outBuffer, short le, byte[] tempBuffer, short tempBufferOffset, short tempBuffLen) {
        //If P1P2 other than 0000 and 0001 throw exception
        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        reset();

        mCBORDecoder.init(receiveBuffer, receivingDataOffset, receivingDataLength);
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        boolean isTestCredential = mCBORDecoder.readBoolean();
        mCryptoManager.setStatusFlag(CryptoManager.FLAG_TEST_CREDENTIAL, isTestCredential);


        mCryptoManager.createCredentialStorageKey(isTestCredential);

        mCryptoManager.setStatusFlag(CryptoManager.FLAG_PROVISIONING_CREDENTIAL_STATE, false);
        // Credential keys are loaded
        mCryptoManager.setStatusFlag(CryptoManager.FLAG_PROVISIONING_INITIALIZED, true);

        mCryptoManager.setStatusFlag(CryptoManager.FLAG_UPDATE_CREDENTIAL, false);

        mCBOREncoder.init(outBuffer, (short) 0, le);
        mCBOREncoder.startArray((short)1);
        mCBOREncoder.encodeUInt8((byte)0); //Success
        return mCBOREncoder.getCurrentOffset();
    }

    private short processUpdateCredential(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
                                          byte[] outBuffer, short le, byte[] tempBuffer, short tempBufferOffset, short tempBuffLen) {

        //If P1P2 other than 0000 throw exception
        if (Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        reset();
        mCBORDecoder.init(receiveBuffer, receivingDataOffset, receivingDataLength);
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        boolean isTestCredential = mCBORDecoder.readBoolean();
        short docTypeOffset = tempBufferOffset;
        short docTypeLen = mCBORDecoder.readByteString(tempBuffer, docTypeOffset);
        short encryptedCredentialKeyOffset = (short)(docTypeOffset + docTypeLen);
        short encryptedCredentialKeysSize = mCBORDecoder.readByteString(tempBuffer, encryptedCredentialKeyOffset);

        // For feature version 202009 it's 52 bytes long and for feature version 202101 it's 86
        // bytes (the additional data is the ProofOfProvisioning SHA-256). We need
        // to support loading all feature versions.
        //
        boolean expectPopSha256 = false;
        if(encryptedCredentialKeysSize == (short)(52 + 28)) {

        } else if (encryptedCredentialKeysSize == (short)(86 + 28)) {
            expectPopSha256 = true;
        } else {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        short outDataOffset = (short)(encryptedCredentialKeyOffset + encryptedCredentialKeysSize);
        //encrypted data is in format {nonce|encryptedKeys|tag}
        if(!mCryptoManager.decryptCredentialData(isTestCredential,
                tempBuffer, (short)(encryptedCredentialKeyOffset + ICConstants.AES_GCM_IV_SIZE), (short)(encryptedCredentialKeysSize - (ICConstants.AES_GCM_IV_SIZE + ICConstants.AES_GCM_TAG_SIZE)),
                tempBuffer, outDataOffset,
                tempBuffer, encryptedCredentialKeyOffset, ICConstants.AES_GCM_IV_SIZE,
                tempBuffer, docTypeOffset, docTypeLen,
                tempBuffer, (short)(encryptedCredentialKeyOffset + encryptedCredentialKeysSize - ICConstants.AES_GCM_TAG_SIZE), ICConstants.AES_GCM_TAG_SIZE)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }


        // It's supposed to look like this;
        //
        // Feature version 202009:
        //
        //         CredentialKeys = [
        //              bstr,   ; storageKey, a 128-bit AES key
        //              bstr,   ; credentialPrivKey, the private key for credentialKey
        //         ]
        //
        // Feature version 202101:
        //
        //         CredentialKeys = [
        //              bstr,   ; storageKey, a 128-bit AES key
        //              bstr,   ; credentialPrivKey, the private key for credentialKey
        //              bstr    ; proofOfProvisioning SHA-256
        //         ]
        //
        // where storageKey is 16 bytes, credentialPrivateKey is 32 bytes, and proofOfProvisioning
        // SHA-256 is 32 bytes.
        //
        if (tempBuffer[outDataOffset] != (byte)(expectPopSha256 ? 0x83 : 0x82) ||  // array of two or three elements
                tempBuffer[(short)(outDataOffset + (short)1)] != 0x50 ||                             // 16-byte bstr
                tempBuffer[(short)(outDataOffset + (short)18)] != 0x58 || tempBuffer[(short)(outDataOffset + (short)19)] != 0x20) {  // 32-byte bstr
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if (expectPopSha256) {
            if (tempBuffer[(short)(outDataOffset + (short)52)] != 0x58 || tempBuffer[(short)(outDataOffset + (short)53)] != 0x20) {  // 32-byte bstr
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
        }

        mCryptoManager.setCredentialStorageKey(tempBuffer, (short)(outDataOffset + 2));
        mCryptoManager.setCredentialEcKey(tempBuffer, (short)(outDataOffset + 20));
        mCryptoManager.setStatusFlag(CryptoManager.FLAG_TEST_CREDENTIAL, isTestCredential);
        // Note: We don't care about the previous ProofOfProvisioning SHA-256
        mCryptoManager.setStatusFlag(CryptoManager.FLAG_UPDATE_CREDENTIAL, true);

        mCryptoManager.setStatusFlag(CryptoManager.FLAG_PROVISIONING_CREDENTIAL_STATE, false);
        // Credential keys are loaded
        mCryptoManager.setStatusFlag(CryptoManager.FLAG_PROVISIONING_KEYS_INITIALIZED, true);
        mCryptoManager.setStatusFlag(CryptoManager.FLAG_PROVISIONING_INITIALIZED, true);

        mCBOREncoder.init(outBuffer, (short) 0, le);
        mCBOREncoder.startArray((short)1);
        mCBOREncoder.encodeUInt8((byte)0); //Success
        return mCBOREncoder.getCurrentOffset();
    }

	private short processCreateCredentialKey(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
                                            byte[] outBuffer, short le, byte[] tempBuffer, short tempBufferOffset, short tempBuffLen) {
        mCryptoManager.assertStatusFlagNotSet(CryptoManager.FLAG_PROVISIONING_KEYS_INITIALIZED);

        //If P1P2 other than 0000 and 0001 throw exception
        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if(mCryptoManager.getStatusFlag(CryptoManager.FLAG_UPDATE_CREDENTIAL)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        mCBORDecoder.init(receiveBuffer, receivingDataOffset, receivingDataLength);
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        short challengeOffset = tempBufferOffset;
        Util.arrayFillNonAtomic(tempBuffer, challengeOffset, tempBuffLen, (byte)0);
        short challengeLen = mCBORDecoder.readByteString(tempBuffer, challengeOffset);
        short appIdOffset = (short)(challengeOffset + challengeLen);
        short appIdLen = mCBORDecoder.readByteString(tempBuffer, appIdOffset);
        short nowMsOffset = (short)(appIdOffset + appIdLen);
        short intSize = mCBORDecoder.getIntegerSize();
        ICUtil.readUInt(mCBORDecoder, tempBuffer, (short)(nowMsOffset + LONG_SIZE - intSize));
        short expireTimeOffset = (short)(nowMsOffset + LONG_SIZE);
        intSize = mCBORDecoder.getIntegerSize();
        ICUtil.readUInt(mCBORDecoder, tempBuffer, (short)(expireTimeOffset + LONG_SIZE - intSize));
        short pubKeyOffset = (short)(expireTimeOffset + LONG_SIZE);

        mCryptoManager.createEcKeyPairAndAttestation(mCryptoManager.getStatusFlag(CryptoManager.FLAG_TEST_CREDENTIAL),
        		tempBuffer, challengeOffset, challengeLen,
        		appIdOffset, appIdLen,
        		nowMsOffset, LONG_SIZE,
        		expireTimeOffset, LONG_SIZE,
        		receiveBuffer, (short)0);
        short pubKeyLen = mCryptoManager.getCredentialEcPubKey(tempBuffer, pubKeyOffset);
        
        short certLen = KMAndroidSEApplet.getInstance().createAttestationForEcPublicKey(mCryptoManager.getStatusFlag(CryptoManager.FLAG_TEST_CREDENTIAL),
        			tempBuffer, pubKeyOffset, pubKeyLen,
        			appIdOffset, appIdLen,
        			challengeOffset, challengeLen,
        			nowMsOffset, LONG_SIZE,
        			expireTimeOffset, LONG_SIZE,
        			outBuffer, (short)0);
        Util.arrayCopyNonAtomic(outBuffer, (short)0, tempBuffer, (short)0, certLen);
        mCBOREncoder.init(outBuffer, (short) 0, le);
        mCBOREncoder.startArray((short)2);
        mCBOREncoder.encodeUInt8((byte)0); //Success
        mCBOREncoder.startArray((short)1);
        mCBOREncoder.encodeByteString(tempBuffer, (short)0, certLen);
        return mCBOREncoder.getCurrentOffset();
	}
	
	private short processStartPersonalization(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
                                             byte[] outBuffer, short le, byte[] tempBuffer, short tempBufferOffset, short tempBuffLen) {
        mCryptoManager.assertCredentialInitialized();
        mCryptoManager.assertStatusFlagNotSet(CryptoManager.FLAG_PROVISIONING_CREDENTIAL_STATE);

        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != (short)0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        mCBORDecoder.init(receiveBuffer, receivingDataOffset, receivingDataLength);
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        short docTypeOffset = tempBufferOffset;
        short docTypeLength = mCBORDecoder.readByteString(tempBuffer, docTypeOffset);
        short accessControlProfileCount = (short)(mCBORDecoder.readInt8() & 0x00FF);
        if(accessControlProfileCount >= MAX_NUM_ACCESS_CONTROL_PROFILE_IDS) {
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        mStatusWords[STATUS_NUM_ACP_COUNTS] = accessControlProfileCount;

        short numEntryCounts = mCBORDecoder.readLength();
        if(numEntryCounts >= MAX_NUM_NAMESPACES) {
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        mStatusWords[STATUS_NUM_NAMESPACE_COUNTS] = numEntryCounts;
        //Check each entry count should not exceed 255 and preserve entry counts
        for(short i = 0; i < numEntryCounts; i++) {
        	short entryCount = 0;
        	byte intSize = mCBORDecoder.getIntegerSize();
	        if(intSize  == BYTE_SIZE) {
	        	//One byte integer = max 255
	        	entryCount = (short)(mCBORDecoder.readInt8() & 0x00FF);
	        	mEntryCounts[i] = entryCount;
                mStatusWords[STATUS_NUM_ENTRY_COUNTS] += entryCount;
	        } else {
	        	//Entry count should not exceed 255
	        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
	        }
        }
        
        mStatusWords[STATUS_CURRENT_NAMESPACE] = (short) -1;
        mStatusWords[STATUS_CURRENT_NAMESPACE_NUM_PROCESSED] = (short) 0;


        // What we're going to sign is the COSE ToBeSigned structure which
        // looks like the following:
        //
        // Sig_structure = [
        //   context : "Signature" / "Signature1" / "CounterSignature",
        //   body_protected : empty_or_serialized_map,
        //   ? sign_protected : empty_or_serialized_map,
        //   external_aad : bstr,
        //   payload : bstr
        //  ]
        //
        mDigest.reset();
        mCBOREncoder.init(outBuffer, (short) 0, le);
        mCBOREncoder.startArray((short) 4);
        mCBOREncoder.encodeTextString(STR_SIGNATURE1, (short) 0, (short) STR_SIGNATURE1.length);
        // The COSE Encoded protected headers is just a single field with
        // COSE_LABEL_ALG (1) -> COSE_ALG_ECSDA_256 (-7). For simplicitly we just
        // hard-code the CBOR encoding:
        mCBOREncoder.encodeByteString(COSE_ENCODED_PROTECTED_HEADERS_ECDSA, (short) 0, (short) COSE_ENCODED_PROTECTED_HEADERS_ECDSA.length);
        // We currently don't support Externally Supplied Data (RFC 8152 section 4.3)
        // so external_aad is the empty bstr
        mCBOREncoder.encodeByteString(tempBuffer, (short)0, (short)0); // byte string of 0 length
        // For the payload, the _encoded_ form follows here. We handle this by simply
        // opening a bstr, and then writing the CBOR. This requires us to know the
        // size of said bstr, ahead of time.
        // Encode byteString of received length (expectedProofOfProvisioningSize) without actual byteString
    	byte intSize = mCBORDecoder.getIntegerSize();
    	if(intSize == BYTE_SIZE) {
    		byte expectedLen = mCBORDecoder.readInt8();
    		mCBOREncoder.startByteString((short)(expectedLen & 0x00FF));
    		mIntExpectedCborSizeAtEnd[3] = expectedLen;
    	} else if (intSize == SHORT_SIZE) {
    		short expectedLen = mCBORDecoder.readInt16();
    		mCBOREncoder.startByteString(expectedLen);
    		Util.setShort(mIntExpectedCborSizeAtEnd, (short)2, expectedLen);
    	} else if(intSize == INT_SIZE) {
    		mCBORDecoder.readInt32(tempBuffer, (short)(docTypeOffset + docTypeLength));
    		mCBOREncoder.startByteString(tempBuffer, (short)(docTypeOffset + docTypeLength), intSize);
    		Util.arrayCopyNonAtomic(tempBuffer, (short)(docTypeOffset + docTypeLength), mIntExpectedCborSizeAtEnd, (short) 0, intSize);
    	} else {
    		ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    	}
		Util.setShort(tempBuffer, (short)(docTypeOffset + docTypeLength), mCBOREncoder.getCurrentOffset());
		ICUtil.incrementByteArray(mIntExpectedCborSizeAtEnd, (short)0, INT_SIZE, tempBuffer, (short)(docTypeOffset + docTypeLength), SHORT_SIZE);
		updatePrimaryDigest(outBuffer, (short) 0, mCBOREncoder.getCurrentOffset());
    	mCBOREncoder.reset();
    	// Reseting encoder just to make sure docType should not overflow it
    	mCBOREncoder.init(outBuffer, (short) 0, le);
		
    	mCBOREncoder.startArray((short) 5);
    	mCBOREncoder.encodeTextString(STR_PROOF_OF_PROVISIONING, (short) 0, (short)STR_PROOF_OF_PROVISIONING.length);
        mCBOREncoder.encodeTextString(tempBuffer, docTypeOffset, docTypeLength);
    	mCBOREncoder.startArray(accessControlProfileCount);
    	
    	updatePrimaryAndSecondaryDigest(outBuffer, (short) 0, mCBOREncoder.getCurrentOffset());

        // Set the Applet in the PERSONALIZATION state
        mCryptoManager.setStatusFlag(CryptoManager.FLAG_PROVISIONING_CREDENTIAL_STATE, true);

        mCBOREncoder.reset();
        mCBOREncoder.init(outBuffer, (short) 0, le);
        mCBOREncoder.startArray((short)1);
        mCBOREncoder.encodeUInt8((byte)0); //Success
        return mCBOREncoder.getCurrentOffset();
    }

	private short processAddAccessControlProfile(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
                                                byte[] outBuffer, short le, byte[] tempBuffer, short tempBufferOffset, short tempBuffLen) {
        mCryptoManager.assertInPersonalizationState();
        mCryptoManager.assertStatusFlagNotSet(CryptoManager.FLAG_PERSONALIZING_ENTRIES);

        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != (short)0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        short outLength = ICUtil.constructCBORAccessControl(mCBORDecoder, mCBOREncoder, receiveBuffer, receivingDataOffset, receivingDataLength,
        										outBuffer, (short)0, le, true);

        // Calculate and return MAC
        //Encrypt constructed CBOR using AES-GCM and get generated MAC and return it.
        mCryptoManager.aesGCMEncrypt(outBuffer, (short)0, (short)0,
        		tempBuffer, tempBufferOffset,
        		outBuffer, (short)0, outLength,
        		tempBuffer, (short)(tempBufferOffset + ICConstants.TEMP_BUFFER_IV_POS));

        // The ACP CBOR in the provisioning receipt doesn't include secureUserId so build
        // it again.
        outLength = ICUtil.constructCBORAccessControl(mCBORDecoder, mCBOREncoder, receiveBuffer, receivingDataOffset, receivingDataLength,
        									outBuffer, (short)0, le, false);
        updatePrimaryAndSecondaryDigest(outBuffer, (short)0, outLength);
        mStatusWords[STATUS_ACP_PROCESSED] += (short)1;
        if(mStatusWords[STATUS_ACP_PROCESSED] == mStatusWords[STATUS_NUM_ACP_COUNTS]) {
            mCryptoManager.setStatusFlag(CryptoManager.FLAG_PERSONALIZING_ENTRIES, true);
        }

        mCBOREncoder.reset();
        mCBOREncoder.init(outBuffer, (short) 0, le);
        mCBOREncoder.startArray((short)2);
        mCBOREncoder.encodeUInt8((byte)0); //Success
        mCBOREncoder.startArray((short)1);
        mCBOREncoder.encodeByteString(tempBuffer, (short)(tempBufferOffset + ICConstants.TEMP_BUFFER_IV_POS), (short)(ICConstants.AES_GCM_IV_SIZE + ICConstants.AES_GCM_TAG_SIZE));
        return mCBOREncoder.getCurrentOffset();
	}

	private short processBeginAddEntry(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
                                      byte[] outBuffer, short le, byte[] tempBuffer, short tempBufferOffset, short tempBuffLen) {
        mCryptoManager.assertStatusFlagSet(CryptoManager.FLAG_PERSONALIZING_ENTRIES);
        mCryptoManager.assertStatusFlagNotSet(CryptoManager.FLAG_PERSONALIZING_FINISH_ENTRIES);

        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != (short)0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        ICUtil.constAndCalcCBOREntryAdditionalData(mCBORDecoder, mCBOREncoder, mAdditionalDataDigester, receiveBuffer, receivingDataOffset, receivingDataLength,
        		outBuffer, (short)0, le, mAdditionalDataSha256, (short) 0, tempBuffer, tempBufferOffset);

        mCBORDecoder.init(receiveBuffer, receivingDataOffset, receivingDataLength);
        mCBOREncoder.init(outBuffer, (short)0, le);
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        //Hold nameSpace in temp variable
        short nameSpaceLen = mCBORDecoder.readByteString(tempBuffer, tempBufferOffset);
        if(mStatusWords[STATUS_CURRENT_NAMESPACE] == (short)-1) {
        	mStatusWords[STATUS_CURRENT_NAMESPACE] = (short)0;
            mStatusWords[STATUS_CURRENT_NAMESPACE_NUM_PROCESSED] = (short) 0;
            // Opens the main map: { * Namespace => [ + Entry ] }
            mCBOREncoder.startMap(mStatusWords[STATUS_NUM_NAMESPACE_COUNTS]);
            //encode nameSpace string
            mCBOREncoder.encodeTextString(tempBuffer, tempBufferOffset, nameSpaceLen);
            // Opens the per-namespace array: [ + Entry ]
            mCBOREncoder.startArray(mEntryCounts[mStatusWords[STATUS_CURRENT_NAMESPACE]]);
        }

        if(mStatusWords[STATUS_CURRENT_NAMESPACE_NUM_PROCESSED] == mEntryCounts[mStatusWords[STATUS_CURRENT_NAMESPACE]]) {
        	mStatusWords[STATUS_CURRENT_NAMESPACE] += (short)1;
        	mStatusWords[STATUS_CURRENT_NAMESPACE_NUM_PROCESSED] = (short) 0;
            //encode nameSpace string
            mCBOREncoder.encodeTextString(tempBuffer, tempBufferOffset, nameSpaceLen);
            // Opens the per-namespace array: [ + Entry ]
            mCBOREncoder.startArray(mEntryCounts[mStatusWords[STATUS_CURRENT_NAMESPACE]]);
        }
        mCBOREncoder.startMap((short) 3);
        //encode key as name string
        mCBOREncoder.encodeTextString(STR_NAME, (short)0, (short)STR_NAME.length);
        //read name parameter
        short nameLen = mCBORDecoder.readByteString(tempBuffer, tempBufferOffset);
        mCBOREncoder.encodeTextString(tempBuffer, tempBufferOffset, nameLen);
        
        mCBORDecoder.skipEntry();//AccessControlProfileIds
	    Util.arrayFillNonAtomic(mIntCurrentEntrySize, (short)0, (short) INT_SIZE, (byte)0); //Reset currentEntrySize before getting it from parameters
        byte intSize = mCBORDecoder.getIntegerSize();
    	if(intSize == BYTE_SIZE) {
    		byte expectedLen = mCBORDecoder.readInt8();
    		mIntCurrentEntrySize[3] = expectedLen;
    	} else if (intSize == SHORT_SIZE) {
    		short expectedLen = mCBORDecoder.readInt16();
    		Util.setShort(mIntCurrentEntrySize, (short)2, expectedLen);
    	} else if(intSize == INT_SIZE) {
    		mCBORDecoder.readInt32(mIntCurrentEntrySize, (short)0);
    	} else {
    		ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    	}
	    Util.arrayFillNonAtomic(mIntCurrentEntryNumBytesReceived, (short)0, (short)(INT_SIZE + SHORT_SIZE), (byte)0);

        //encode key as value string
        mCBOREncoder.encodeTextString(STR_VALUE, (short)0, (short)STR_VALUE.length);

        updatePrimaryAndSecondaryDigest(outBuffer, (short) 0, mCBOREncoder.getCurrentOffset());
    	
    	mStatusWords[STATUS_CURRENT_NAMESPACE_NUM_PROCESSED] += (short) 1;
    	if(mStatusWords[STATUS_NUM_ENTRY_COUNTS] == mStatusWords[STATUS_CURRENT_ENTRY]) {
            mCryptoManager.setStatusFlag(CryptoManager.FLAG_PERSONALIZING_FINISH_ENTRIES, true);
        } else {
            mStatusWords[STATUS_CURRENT_ENTRY] += (short)1;
        }

        mCBOREncoder.reset();
        mCBOREncoder.init(outBuffer, (short) 0, le);
        mCBOREncoder.startArray((short)1);
        mCBOREncoder.encodeUInt8((byte)0); //Success
        return mCBOREncoder.getCurrentOffset();
	}

	private short processAddEntryValue(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
                                      byte[] outBuffer, short le, byte[] tempBuffer, short tempBufferOffset, short tempBuffLen) {
        mCryptoManager.assertInPersonalizationState();
        mCryptoManager.assertStatusFlagNotSet(CryptoManager.FLAG_PERSONALIZING_FINISH_ENTRIES_VALUES);

        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != (short)0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        mCBORDecoder.init(receiveBuffer, receivingDataOffset, receivingDataLength);
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        short additionalDataLen = ICUtil.constAndCalcCBOREntryAdditionalData(mCBORDecoder, mCBOREncoder, mAdditionalDataDigester, receiveBuffer, mCBORDecoder.getCurrentOffset(), receivingDataLength,
        		outBuffer, (short)0, le, tempBuffer, tempBufferOffset, tempBuffer, (short) (tempBufferOffset + ICConstants.SHA256_DIGEST_SIZE));

        //Compare calculated hash of additional data with preserved hash from addEntry
        if(Util.arrayCompare(tempBuffer, tempBufferOffset, mAdditionalDataSha256, (short) 0, ICConstants.SHA256_DIGEST_SIZE) != (byte)0) {
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        
        //We need to reset decoder
        mCBORDecoder.init(receiveBuffer, receivingDataOffset, receivingDataLength);
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        mCBORDecoder.skipEntry(); //Skip additionalData

        //read content
        short contentOffset = tempBufferOffset;
        short contentLen = mCBORDecoder.readByteString(tempBuffer, contentOffset);
        updatePrimaryAndSecondaryDigest(tempBuffer, contentOffset, contentLen);
        
        if((short)(contentLen * 2) > ICConstants.TEMP_BUFFER_SIZE) {
        	ISOException.throwIt(ISO7816.SW_INSUFFICIENT_MEMORY);
        }
        //Encrypt content and additional data as aad
        short outEncryptedDataOffset = (short)(contentOffset + contentLen);
        mCryptoManager.aesGCMEncrypt(
        		tempBuffer, contentOffset, contentLen, //in data
        		tempBuffer, outEncryptedDataOffset, //Out encrypted data
        		outBuffer, (short)0, additionalDataLen, //Auth data
        		tempBuffer, (short)(tempBufferOffset + ICConstants.TEMP_BUFFER_IV_POS)); //nonce and tag

        mCBOREncoder.reset();
        mCBOREncoder.init(outBuffer, (short)0, le);
        mCBOREncoder.startArray((short)2);
        mCBOREncoder.encodeUInt8((byte)0); //Success
        mCBOREncoder.startArray((short)1);
        mCBOREncoder.startByteString((short) (ICConstants.AES_GCM_IV_SIZE + contentLen + ICConstants.AES_GCM_TAG_SIZE));
        //Output will be nonce|encryptedData|tag
        Util.arrayCopyNonAtomic(tempBuffer, (short)(tempBufferOffset + ICConstants.TEMP_BUFFER_IV_POS), outBuffer, mCBOREncoder.getCurrentOffset(), ICConstants.AES_GCM_IV_SIZE);
        Util.arrayCopyNonAtomic(tempBuffer, outEncryptedDataOffset, outBuffer, (short)(mCBOREncoder.getCurrentOffset() + ICConstants.AES_GCM_IV_SIZE), contentLen);
        Util.arrayCopyNonAtomic(tempBuffer, (short) (tempBufferOffset + ICConstants.TEMP_BUFFER_GCM_TAG_POS), outBuffer, (short) (mCBOREncoder.getCurrentOffset() + ICConstants.AES_GCM_IV_SIZE + contentLen), ICConstants.AES_GCM_TAG_SIZE);
        // nonce, encrypted content and tag are already copied to outBuffer
        short returnLen = (short) (mCBOREncoder.getCurrentOffset() + ICConstants.AES_GCM_IV_SIZE + contentLen + ICConstants.AES_GCM_TAG_SIZE);

        // If done with this entry, close the map
        Util.setShort(mIntCurrentEntryNumBytesReceived, (short) INT_SIZE, contentLen);
        ICUtil.incrementByteArray(mIntCurrentEntryNumBytesReceived, (short)0, INT_SIZE, mIntCurrentEntryNumBytesReceived, (short) INT_SIZE, SHORT_SIZE);
        if(Util.arrayCompare(mIntCurrentEntryNumBytesReceived, (short) 0, mIntCurrentEntrySize, (short) 0, INT_SIZE) == 0) {
            //We need to reset decoder and encoder
            mCBORDecoder.init(receiveBuffer, receivingDataOffset, receivingDataLength);
        	mCBOREncoder.init(tempBuffer, tempBufferOffset, ICConstants.TEMP_BUFFER_SIZE);
        	
        	mCBOREncoder.encodeTextString(STR_ACCESS_CONTROL_PROFILES, (short)0, (short)STR_ACCESS_CONTROL_PROFILES.length);
            mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
            //Get Additional
            mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
            mCBORDecoder.skipEntry(); //NameSpace
            mCBORDecoder.skipEntry(); //Name
            short acpIdLen = mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY); //ACP Ids count
            mCBOREncoder.startArray(acpIdLen);
            for(short i = (short)0; i < acpIdLen; i++) {
            	byte intSize = mCBORDecoder.getIntegerSize();
            	if(intSize == BYTE_SIZE) {
            		mCBOREncoder.encodeUInt8(mCBORDecoder.readInt8());
            	} else if(intSize == SHORT_SIZE) {
            		mCBOREncoder.encodeUInt16(mCBORDecoder.readInt16());
            	} else {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
            }
            updatePrimaryAndSecondaryDigest(tempBuffer, tempBufferOffset, (short)(mCBOREncoder.getCurrentOffset() - tempBufferOffset));

            if(mStatusWords[STATUS_NUM_ENTRY_COUNTS] == mStatusWords[STATUS_CURRENT_ENTRY]) {
                mCryptoManager.setStatusFlag(CryptoManager.FLAG_PERSONALIZING_FINISH_ENTRIES_VALUES, true);
            }
        }
        return returnLen;
	}

	private short processFinishAddingEntries(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
                                            byte[] outBuffer, short le, byte[] tempBuffer, short tempBufferOffset, short tempBuffLen) {
        mCryptoManager.assertStatusFlagSet(CryptoManager.FLAG_PERSONALIZING_FINISH_ENTRIES_VALUES);
        mCryptoManager.assertStatusFlagNotSet(CryptoManager.FLAG_PERSONALIZING_FINISH_ADDING_ENTRIES);

        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != (short)0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        mCBOREncoder.init(tempBuffer, tempBufferOffset, ICConstants.TEMP_BUFFER_SIZE);
        mCBOREncoder.encodeBoolean(mCryptoManager.getStatusFlag(CryptoManager.FLAG_TEST_CREDENTIAL));
        updatePrimaryAndSecondaryDigest(tempBuffer, tempBufferOffset, (short)(mCBOREncoder.getCurrentOffset() - tempBufferOffset));
        short digestOffset = mCBOREncoder.getCurrentOffset();
        short digestLen = mDigest.doFinal(tempBuffer, (short) 0, (short)0, tempBuffer, digestOffset);

        // This verifies that the correct expectedProofOfProvisioningSize value was
        // passed in at eicStartPersonalization() time.
        byte comp = Util.arrayCompare(mIntExpectedCborSizeAtEnd, (short)0, mIntCurrentCborSize, (short)0, (short) INT_SIZE);
        if(comp != 0) {
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        short signOffset = (short)(digestOffset + digestLen);
        short signLen = mCryptoManager.ecSignWithNoDigest(tempBuffer, digestOffset, tempBuffer, signOffset);
        mCryptoManager.setStatusFlag(CryptoManager.FLAG_PERSONALIZING_FINISH_ADDING_ENTRIES, true);

        mCBOREncoder.reset();
        mCBOREncoder.init(outBuffer, (short)0, le);
        mCBOREncoder.startArray((short)2);
        mCBOREncoder.encodeUInt8((byte)0); //Success
        mCBOREncoder.startArray((short)1);
        mCBOREncoder.encodeByteString(tempBuffer, signOffset, signLen);
        return mCBOREncoder.getCurrentOffset();
	}

	private short processFinishGetCredentialData(byte[] receiveBuffer, short receivingDataOffset, short receivingDataLength,
                                                byte[] outBuffer, short le, byte[] tempBuffer, short tempBufferOffset, short tempBuffLen) {
        mCryptoManager.assertStatusFlagSet(CryptoManager.FLAG_PERSONALIZING_FINISH_ADDING_ENTRIES);
        mCryptoManager.assertStatusFlagNotSet(CryptoManager.FLAG_PERSONALIZING_FINISH_GET_CREDENTIAL);

        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != (short)0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        mCBORDecoder.init(receiveBuffer, receivingDataOffset, receivingDataLength);
        mCBOREncoder.init(outBuffer, (short) 0, le);
        
		mCBOREncoder.startArray((short)3);
		mCryptoManager.getCredentialStorageKey(tempBuffer, tempBufferOffset);
		mCBOREncoder.encodeByteString(tempBuffer, tempBufferOffset, ICConstants.AES_GCM_KEY_SIZE);
		mCryptoManager.getCredentialEcKey(tempBuffer, tempBufferOffset);
		mCBOREncoder.encodeByteString(tempBuffer, tempBufferOffset, ICConstants.EC_KEY_SIZE);
		mSecondaryDigest.doFinal(tempBuffer, (short)0, (short) 0, tempBuffer, tempBufferOffset); //Data is of 0 size and collect digest in tempBuffer
		mCBOREncoder.encodeByteString(tempBuffer, tempBufferOffset, ICConstants.SHA256_DIGEST_SIZE);
		
		mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
		short docTypeLen = mCBORDecoder.readByteString(tempBuffer, tempBufferOffset);
		short dataSize = mCBOREncoder.getCurrentOffset();
		mCryptoManager.entryptCredentialData(mCryptoManager.getStatusFlag(CryptoManager.FLAG_TEST_CREDENTIAL),
				outBuffer, (short) 0, mCBOREncoder.getCurrentOffset(), //in data
				tempBuffer, tempBufferOffset, //out encrypted data
				tempBuffer, tempBufferOffset, docTypeLen, //Auth data
				tempBuffer, (short)(tempBufferOffset + ICConstants.TEMP_BUFFER_IV_POS)); //Nonce and tag

        mCryptoManager.setStatusFlag(CryptoManager.FLAG_PERSONALIZING_FINISH_GET_CREDENTIAL, true);

        mCBOREncoder.reset();
        mCBOREncoder.init(outBuffer, (short)0, le);
        mCBOREncoder.startArray((short)2);
        mCBOREncoder.encodeUInt8((byte)0); //Success
        mCBOREncoder.startArray((short)1);
        mCBOREncoder.startByteString((short)(ICConstants.AES_GCM_IV_SIZE + dataSize + ICConstants.AES_GCM_TAG_SIZE));
        //Output will be nonce|encryptedData|tag
        Util.arrayCopyNonAtomic(tempBuffer, (short)(tempBufferOffset + ICConstants.TEMP_BUFFER_IV_POS), outBuffer, mCBOREncoder.getCurrentOffset(), ICConstants.AES_GCM_IV_SIZE);
        Util.arrayCopyNonAtomic(tempBuffer, tempBufferOffset, outBuffer, (short) (mCBOREncoder.getCurrentOffset() + ICConstants.AES_GCM_IV_SIZE), dataSize);
        Util.arrayCopyNonAtomic(tempBuffer, (short) (tempBufferOffset + ICConstants.TEMP_BUFFER_GCM_TAG_POS), outBuffer, (short) (mCBOREncoder.getCurrentOffset() + ICConstants.AES_GCM_IV_SIZE + dataSize), ICConstants.AES_GCM_TAG_SIZE);
        return (short)(mCBOREncoder.getCurrentOffset() + ICConstants.AES_GCM_IV_SIZE + dataSize + ICConstants.AES_GCM_TAG_SIZE);
	}
}
