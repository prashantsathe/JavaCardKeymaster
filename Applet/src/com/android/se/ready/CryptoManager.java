package com.android.se.ready;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;

public class CryptoManager {

    public static final byte FLAG_TEST_CREDENTIAL = 0;
    public static final byte FLAG_PROVISIONING_INITIALIZED = 1;
    public static final byte FLAG_PROVISIONING_KEYS_INITIALIZED = 2;
    public static final byte FLAG_PROVISIONING_CREDENTIAL_STATE = 3;
    public static final byte FLAG_PERSONALIZING_ENTRIES = 4;
    public static final byte FLAG_PERSONALIZING_FINISH_ENTRIES = 5;
    public static final byte FLAG_PERSONALIZING_FINISH_ENTRIES_VALUES = 6;
    public static final byte FLAG_PERSONALIZING_FINISH_ADDING_ENTRIES = 7;
    public static final byte FLAG_PERSONALIZING_FINISH_GET_CREDENTIAL = 8;
    public static final byte FLAG_PRESENTING_CREATE_EPHEMERAL = 9;
    public static final byte FLAG_PRESENTING_CREATE_AUTH_CHALLENGE = 0x0A;
    public static final byte FLAG_PRESENTING_START_RETRIEVAL = 0x0B;
    public static final byte FLAG_PRESENTING_START_RETRIEVE_ENTRY = 0x0C;
    public static final byte FLAG_UPDATE_CREDENTIAL = 0x0D;
    public static final byte FLAG_HMAC_INITIALIZED = 0x0E;
    private static final byte STATUS_FLAGS_SIZE = 2;

    // Actual Crypto implementation
    private final ICryptoProvider mCryptoProvider;
    
    // Hardware bound key, initialized during Applet installation
    private final byte[] mHBK;
    
    // Storage key for a credential
    private final byte[] mCredentialStorageKey;

    // KeyPair for credential key
    private final byte[] mCredentialKeyPair;
    // Temporary buffer in memory for keyLengths
    private final short[] mCredentialKeyPairLengths;

    // Signature object for creating and verifying credential signatures 
    MessageDigest mDigest;
    // Digester object for calculating proof of provisioning data digest
    final MessageDigest mSecondaryDigest;
    // Digester object for calculating addition data digest
    final MessageDigest mAdditionalDataDigester;

    // Random data generator 
    private final RandomData mRandomData;

    // Temporary buffer in memory for status flags
    private final byte[] mStatusFlags;

    public CryptoManager(ICryptoProvider cryptoProvider) {
    	mCryptoProvider = cryptoProvider;
    	
        //mTempBuffer = JCSystem.makeTransientByteArray((short) (TEMP_BUFFER_SIZE + AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE),
        //        JCSystem.CLEAR_ON_DESELECT);
    	//mTempBuffer = KMRepository.instance().getHeap();
    	
        mStatusFlags = JCSystem.makeTransientByteArray((short)(STATUS_FLAGS_SIZE), JCSystem.CLEAR_ON_DESELECT);

        // Secure Random number generation for HBK
        mRandomData = RandomData.getInstance(RandomData.ALG_TRNG);
        mHBK = new byte[ICConstants.AES_GCM_KEY_SIZE];
        mRandomData.nextBytes(mHBK, (short)0, ICConstants.AES_GCM_KEY_SIZE);
        
        // Create the storage key byte array 
        mCredentialStorageKey = JCSystem.makeTransientByteArray(ICConstants.AES_GCM_KEY_SIZE, JCSystem.CLEAR_ON_RESET);
        mCredentialKeyPair = JCSystem.makeTransientByteArray((short)(ICConstants.EC_KEY_SIZE * 3 + 1), JCSystem.CLEAR_ON_RESET);
        mCredentialKeyPairLengths = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_RESET);

        try {
            //External access is enabled to pass VTS, after some VTS passed, remaining VTS failed while MessageDigest update if it is not exported.
            mDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, true);
        } catch (CryptoException e) {
            //External access is not supported in JCard simulator.
            mDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        }
        mSecondaryDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        mAdditionalDataDigester = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

    }

    /**
     * Reset the internal state. Resets the credential private key, the storage key
     * as well as all status flags.
     */
    public void reset() {
        Util.arrayFillNonAtomic(mStatusFlags, (short)0, STATUS_FLAGS_SIZE, (byte)0);
        Util.arrayFillNonAtomic(mCredentialStorageKey, (short)0, KeyBuilder.LENGTH_AES_128, (byte)0);
    }
    
    /**
     * Returns the used AES key size for the storage as well as hardware-bound key
     * in bit.
     */
    public static short getAESKeySize() {
        return (short) (ICConstants.AES_GCM_KEY_SIZE * 8);
    }
    
    void createCredentialStorageKey(boolean testCredential) {
        // Check if it is a test credential
        if(testCredential) { // Test credential
        	Util.arrayFillNonAtomic(mCredentialStorageKey, (short) 0, ICConstants.AES_GCM_KEY_SIZE, (byte)0x00);
        } else {
	        // Generate the AES-128 storage key 
	        generateRandomData(mCredentialStorageKey, (short) 0, ICConstants.AES_GCM_KEY_SIZE);
        }
    }
    
    short getCredentialStorageKey(byte[] storageKey, short skStart) {
        if(storageKey != null) {
            Util.arrayCopyNonAtomic(mCredentialStorageKey, (short) 0, storageKey, skStart, ICConstants.AES_GCM_KEY_SIZE);
        }
        return ICConstants.AES_GCM_KEY_SIZE;
    }

    short setCredentialStorageKey(byte[] storageKey, short skStart) {
        if(storageKey != null) {
            Util.arrayCopyNonAtomic(storageKey, skStart, mCredentialStorageKey, (short) 0, ICConstants.AES_GCM_KEY_SIZE);
        }
        return ICConstants.AES_GCM_KEY_SIZE;
    }

    void createEcKeyPair(byte[] keyPairBlob, short keyBlobStart, short[] keyPairLengths) {
        mCryptoProvider.createECKey(keyPairBlob, keyBlobStart, ICConstants.EC_KEY_SIZE, keyPairBlob, (short)(keyBlobStart + ICConstants.EC_KEY_SIZE), (short) (ICConstants.EC_KEY_SIZE * 2 + 1), keyPairLengths);
    }

    void createEcKeyPairAndAttestation(boolean isTestCredential,
    		byte[] argsBuff,
    		short challengeOffset, short challengeLen,
    		short appIdOffset, short appIdLen,
    		short nowMsOffset, short nowMsLen,
    		short expireTimeOffset, short expireTimeLen,
    		byte[] scratchPad, short scratchPadOffset) {
        createEcKeyPair(mCredentialKeyPair, (short)0, mCredentialKeyPairLengths);
        
		/*KMAndroidSEApplet.getInstance().createAttestationForEcPublicKey(
		  mCredentialKeyPair, mCredentialKeyPairLengths[0], mCredentialKeyPairLengths[1],
		  argsBuff,
		  appIdOffset, appIdLen,
		  challengeOffset, challengeLen,
		  nowMsOffset, nowMsLen,
		  expireTimeOffset, expireTimeLen,
		  scratchPad, scratchPadOffset);
		 
        if (!isTestCredential) {
        	//TODO 
        }*/
    }
    
    short getCredentialEcKey(byte[] credentialEcKey, short start) {
        if(credentialEcKey != null) {
            Util.arrayCopyNonAtomic(mCredentialKeyPair, (short) 0, credentialEcKey, start, mCredentialKeyPairLengths[0]);
        }
    	return mCredentialKeyPairLengths[0];
    }

    short setCredentialEcKey(byte[] credentialEcKey, short start) {
        if(credentialEcKey != null) {
            Util.arrayCopyNonAtomic(credentialEcKey, start, mCredentialKeyPair, (short) 0, ICConstants.EC_KEY_SIZE);
            mCredentialKeyPairLengths[0] = ICConstants.EC_KEY_SIZE;
        }
        return ICConstants.EC_KEY_SIZE;
    }

    short getCredentialEcPubKey(byte[] credentialEcPubKey, short start) {
        if(credentialEcPubKey != null) {
            Util.arrayCopyNonAtomic(mCredentialKeyPair, mCredentialKeyPairLengths[0], credentialEcPubKey, start, mCredentialKeyPairLengths[1]);
        }
        return mCredentialKeyPairLengths[1];
    }

    short ecSignWithNoDigest(byte[] sha256Hash, short hashOffset, byte[] signBuff, short signBuffOffset) {
    	return mCryptoProvider.ecSignWithNoDigest(mCredentialKeyPair, (short)0, mCredentialKeyPairLengths[0],//Private key
                sha256Hash, hashOffset, ICConstants.SHA256_DIGEST_SIZE, signBuff, signBuffOffset);
    }

    short ecSignWithSHA256Digest(byte[] data, short dataOffset, short dataLen, byte[] signBuff, short signBuffOffset) {
        return mCryptoProvider.ecSignWithSHA256Digest(
                mCredentialKeyPair, (short)0, mCredentialKeyPairLengths[0],//Private key
                data, dataOffset, dataLen, signBuff, signBuffOffset);
    }

    boolean ecVerifyWithNoDigest(byte[] pubKey, short pubKeyOffset, short pubKeyLen,
                                 byte[] data, short dataOffset, short dataLen,
                                 byte[] signBuff, short signBuffOffset, short signLength) {
        return mCryptoProvider.ecVerifyWithNoDigest(pubKey, pubKeyOffset, pubKeyLen, data, dataOffset, dataLen, signBuff, signBuffOffset, signLength);
    }

    void setStatusFlag(byte flag, boolean isSet) {
    	ICUtil.setBit(mStatusFlags, flag, isSet);
    }
    

    boolean getStatusFlag(byte flag) {
    	return ICUtil.getBit(mStatusFlags, flag);
    }
    
    void generateRandomData(byte[] tempBuffer, short offset, short length) {
        mRandomData.nextBytes(tempBuffer, offset, length);
    }
    
    public void assertStatusFlagSet(byte statusFlag) {
        if (!ICUtil.getBit(mStatusFlags, statusFlag)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
    
    public void assertCredentialInitialized() {
        assertStatusFlagSet(FLAG_PROVISIONING_INITIALIZED);
    }

    public void assertInPersonalizationState() {
        assertStatusFlagSet(FLAG_PROVISIONING_CREDENTIAL_STATE);
    }

    public void assertStatusFlagNotSet(byte statusFlag) {
        if (ICUtil.getBit(mStatusFlags, statusFlag)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
    
    public short aesGCMEncrypt(byte[] data, short dataOffset, short dataLen,
    		byte[] outData, short outDataOffset,
    		byte[] authData, short authDataOffset, short authDataLen,
    		byte[] outNonceAndTag, short outNonceAndTagOff) {

        // Generate the IV
        mRandomData.nextBytes(outNonceAndTag, outNonceAndTagOff, ICConstants.AES_GCM_IV_SIZE);
    	return mCryptoProvider.aesGCMEncrypt(mCredentialStorageKey, (short)0, (short)mCredentialStorageKey.length,
    			data, dataOffset, dataLen,
    			outData, outDataOffset,
    			outNonceAndTag, (short)outNonceAndTagOff, ICConstants.AES_GCM_IV_SIZE,
    			authData, authDataOffset, authDataLen,
    			outNonceAndTag, (short)(outNonceAndTagOff + ICConstants.AES_GCM_IV_SIZE), ICConstants.AES_GCM_TAG_SIZE);
    }

    public boolean aesGCMDecrypt(byte[] encData, short encDataOffset, short encDataLen,
                               byte[] outData, short outDataOffset,
                               byte[] authData, short authDataOffset, short authDataLen,
                               byte[] nonceAndTag, short nonceAndTagOff) {

        return mCryptoProvider.aesGCMDecrypt(mCredentialStorageKey, (short)0, (short)mCredentialStorageKey.length,
                encData, encDataOffset, encDataLen,
                outData, outDataOffset,
                nonceAndTag, nonceAndTagOff, ICConstants.AES_GCM_IV_SIZE,
                authData, authDataOffset, authDataLen,
                nonceAndTag, (short)(nonceAndTagOff + ICConstants.AES_GCM_IV_SIZE), ICConstants.AES_GCM_TAG_SIZE);
    }

    short entryptCredentialData(boolean isTestCredential,
    		byte[] data, short dataOffset, short dataLen,
    		byte[] outData, short outDataOffset,
    		byte[] authData, short authDataOffset, short authDataLen,
    		byte[] outNonceAndTag, short outNonceAndTagOff) {

        // Generate the IV
        mRandomData.nextBytes(outNonceAndTag, outNonceAndTagOff, ICConstants.AES_GCM_IV_SIZE);
        if(isTestCredential) {
        	//In case of testCredential HBK should be initialized with 0's
        	//If testCredential is true mCredentialStorageKey is already initialized with 0's so no need to create separate HBK for testCredential.
        	return mCryptoProvider.aesGCMEncrypt(mCredentialStorageKey, (short)0, (short)mCredentialStorageKey.length,
	    			data, dataOffset, dataLen,
	    			outData, outDataOffset,
	    			outNonceAndTag, (short)outNonceAndTagOff, ICConstants.AES_GCM_IV_SIZE,
	    			authData, authDataOffset, authDataLen,
	    			outNonceAndTag, (short)(outNonceAndTagOff + ICConstants.AES_GCM_IV_SIZE), ICConstants.AES_GCM_TAG_SIZE);
        } else {
	    	return mCryptoProvider.aesGCMEncrypt(mHBK, (short)0, (short)mHBK.length,
	    			data, dataOffset, dataLen,
	    			outData, outDataOffset,
	    			outNonceAndTag, (short)outNonceAndTagOff, ICConstants.AES_GCM_IV_SIZE,
	    			authData, authDataOffset, authDataLen,
	    			outNonceAndTag, (short)(outNonceAndTagOff + ICConstants.AES_GCM_IV_SIZE), ICConstants.AES_GCM_TAG_SIZE);
        }
    }

    boolean decryptCredentialData(boolean isTestCredential, byte[] encryptedCredentialKeyBlob, short keyBlobOff, short keyBlobSize,
                                            byte[] outData, short outDataOffset,
                                            byte[] nonce, short nonceOffset, short nonceLen,
                                            byte[] authData, short authDataOffset, short authDataLen,
                                            byte[] authTag, short authTagOffset, short authTagLen) {

        if(isTestCredential) {
            //In case of testCredential HBK should be initialized with 0's
            //If testCredential is true mCredentialStorageKey is already initialized with 0's so no need to create separate HBK for testCredential.
            return mCryptoProvider.aesGCMDecrypt(mCredentialStorageKey, (short)0, (short)mCredentialStorageKey.length,
                    encryptedCredentialKeyBlob, keyBlobOff, keyBlobSize,
                    outData, outDataOffset,
                    nonce, nonceOffset, nonceLen,
                    authData, authDataOffset, authDataLen,
                    authTag, authTagOffset, authTagLen);
        } else {
            return mCryptoProvider.aesGCMDecrypt(mHBK, (short)0, (short)mHBK.length,
                    encryptedCredentialKeyBlob, keyBlobOff, keyBlobSize,
                    outData, outDataOffset,
                    nonce, nonceOffset, nonceLen,
                    authData, authDataOffset, authDataLen,
                    authTag, authTagOffset, authTagLen);
        }
    }

    public short createECDHSecret(byte[] privKey, short privKeyOffset, short privKeyLen,
                                  byte[] pubKey, short pubKeyOffset, short pubKeyLen,
                                  byte[] outSecret, short outSecretOffset) {
        return mCryptoProvider.createECDHSecret(privKey, privKeyOffset, privKeyLen,
                pubKey, pubKeyOffset, pubKeyLen,
                outSecret, outSecretOffset);
    }

    public short hkdf(byte[] sharedSecret, short sharedSecretOffset, short sharedSecretLen,
                      byte[] salt, short saltOffset, short saltLen,
                      byte[] info, short infoOffset, short infoLen,
                      byte[] outDerivedKey, short outDerivedKeyOffset, short expectedKeySize) {
        return mCryptoProvider.hkdf(sharedSecret, sharedSecretOffset, sharedSecretLen,
                                    salt, saltOffset, saltLen,
                                    info, infoOffset, infoLen,
                                    outDerivedKey, outDerivedKeyOffset, expectedKeySize);
    }

    public boolean hmacVerify(byte[] key, short keyOffset, short keyLen,
                              byte[] data, short dataOffset, short dataLen,
                              byte[] mac, short macOffset, short macLen) {
        return mCryptoProvider.hmacVerify(key, keyOffset, keyLen,
                                    data, dataOffset, dataLen,
                                    mac, macOffset, macLen);
    }

    public boolean validateAuthToken(byte[] tokenBuff, short tokenOff, short tokenLen) {
        return mCryptoProvider.validateAuthToken(tokenBuff, tokenOff, tokenLen);
    }

    public boolean verifyCertByPubKey(byte[] cert, short certOffset, short certLen, byte[] pubKey, short pubKeyOffset, short pubKeyLen) {
        return mCryptoProvider.verifyCertByPubKey(cert, certOffset, certLen, pubKey, pubKeyOffset, pubKeyLen);
    }
}
