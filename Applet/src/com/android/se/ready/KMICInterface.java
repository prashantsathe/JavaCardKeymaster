package com.android.se.ready;

import javacard.framework.Shareable;

public interface KMICInterface extends Shareable {

	boolean validateAuthToken(byte[] tokenData, short tokenOffset, short tokenLen);
	
}
