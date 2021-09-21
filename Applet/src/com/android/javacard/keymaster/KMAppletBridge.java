package com.android.javacard.keymaster;

import javacard.framework.Shareable;

/**
 * This is an interface between Identity Credential and Keymaster.
 * This interface is mainly used for operation which are not supported by SE provider.
 */
public interface KMAppletBridge extends Shareable {

	/**
	 * An API used by IdentityCredential to create an attestation certificate for given EC public key.
	 * @param isTestCredential true if it is test credential.
	 * @param argumentsBuff arguments buffer, all arguments are in same buffer only offset and their lengths passed next.
	 * @param pubKeyOffset offset of public key material
	 * @param pubKeyLen length of public key
	 * @param appIdOffset offset of application ID
	 * @param appIdLen length of application ID
	 * @param challengeOffset offset of challenge
	 * @param challengeLen length of challenge
	 * @param currentTimeOffset offset of current time
	 * @param currentTimeLen length of current time
	 * @param expireTimeOffset offset of expire time offset.
	 * @param expireTimeLen length of expire time.
	 * @param scratchPad scratchPad is expected of 256 size
	 * @param scratchPadOffset scratchPadOffset expected always 0
	 * @return
	 */
	short createAttestationForEcPublicKey(boolean isTestCredential,
	        			byte[] argumentsBuff, short pubKeyOffset, short pubKeyLen,
	        			short appIdOffset, short appIdLen,
	        			short challengeOffset, short challengeLen,
	        			short currentTimeOffset, short currentTimeLen,
	        			short expireTimeOffset, short expireTimeLen,
	        			byte[] scratchPad, short scratchPadOffset);
	
	/**
	 * An API to get certificate chain of attestation certificate.
	 * @param outCertBuffer output certificate chain buffer
	 * @param outCertBufferOffset offset of output buffer where certificate chain will start.
	 * @return length of certificate chain.
	 */
	short getCertChainExt(byte[] outCertBuffer, short outCertBufferOffset);

	/**
	 * An utility API to convert given time in X509 format.
	 * @param timeBuffer input time buffer, length of buffer has to be 8
	 * @param timeBufferOffset offset of time buffer
	 * @param outBuffer output buffer
	 * @param outBufferOffset offset of output buffer where converted date will start.
	 * @return length of converted time.
	 */
	short convertDate(byte[] timeBuffer, short timeBufferOffset,
					byte[] outBuffer, short outBufferOffset);

	/**
	 * An API to validate Hardware and Verification (Timestamp) tokens.
	 * @param argsBuff all arguments containing buffer, only offset and lengths are passed next.
	 * @param challengeOffset offset of challenge
	 * @param challengeLen length of challenge
	 * @param secureUserIdOffset offset of user ID
	 * @param secureUserIdLen length of user ID
	 * @param authenticatorIdOffset offset if Authenticator ID
	 * @param authenticatorIdLen length if Authenticator ID
	 * @param hardwareAuthenticatorTypeOffset offset if Hardware authenticator type
	 * @param hardwareAuthenticatorTypeLen length of hardware authenticator type
	 * @param timeStampOffset offset of timestamp
	 * @param timeStampLen length of timestamp
	 * @param macOffset offset of hardware auth token MAC
	 * @param macLen length of hardware auth token MAC
	 * @param verificationTokenChallengeOffset offset if verification token challenge
	 * @param verificationTokenChallengeLen length of verification token challenge
	 * @param verificationTokenTimeStampOffset offset of verification token timestamp
	 * @param verificationTokenTimeStampLen length of verification token timestamp
	 * @param parametersVerifiedOffset offset of parameter
	 * @param parametersVerifiedLen length of parameters
	 * @param verificationTokenSecurityLevelOffset offset of verification token's security level
	 * @param verificationTokenSecurityLevelLen length of verification token's security level
	 * @param verificationTokenMacOffset offset if verification token's MAC
	 * @param verificationTokenMacLen length of verification token's MAC
	 * @param scratchPad scratch pad of length 256 starting from 0
	 * @return true if both Hardware and Verification token are valid.
	 */
	boolean validateAuthTokensExt(byte[] argsBuff,
    		short challengeOffset, short challengeLen,
    		short secureUserIdOffset, short secureUserIdLen,
    		short authenticatorIdOffset, short authenticatorIdLen,
    		short hardwareAuthenticatorTypeOffset, short hardwareAuthenticatorTypeLen,
    		short timeStampOffset, short timeStampLen,
    		short macOffset, short macLen,
    		short verificationTokenChallengeOffset, short verificationTokenChallengeLen,
    		short verificationTokenTimeStampOffset, short verificationTokenTimeStampLen,
    		short parametersVerifiedOffset, short parametersVerifiedLen,
    		short verificationTokenSecurityLevelOffset, short verificationTokenSecurityLevelLen,
    		short verificationTokenMacOffset, short verificationTokenMacLen,
    		byte[] scratchPad);
}
