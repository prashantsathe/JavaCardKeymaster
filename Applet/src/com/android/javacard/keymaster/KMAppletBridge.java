package com.android.javacard.keymaster;

import javacard.framework.Shareable;

public interface KMAppletBridge extends Shareable {

	short createAttestationForEcPublicKey(boolean isTestCredential,
	        			byte[] pubKeyBuff, short pubKeyOffset, short pubKeyLen,
	        			short appIdOffset, short appIdLen,
	        			short challengeOffset, short challengeLen,
	        			short currentTimeOffset, short currentTimeLen,
	        			short expireTimeOffset, short expireTimeLen,
	        			byte[] scratchPad, short scratchPadOffset);
	
	short getCertChainExt(byte[] outCertBuffer, short outCertBufferOffset);

	short convertDate(byte[] timeBuffer, short timeBufferOffset,
					byte[] outBuffer, short outBufferOffset);
}
