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
 * distributed under the License is distributed on an "AS IS" (short)0IS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.javacard.keymaster;

import org.globalplatform.upgrade.Element;
import org.globalplatform.upgrade.OnUpgradeListener;
import org.globalplatform.upgrade.UpgradeManager;

import javacard.framework.AID;
import javacard.framework.ISOException;
import javacard.framework.Shareable;

public class KMAndroidSEApplet extends KMKeymasterApplet implements OnUpgradeListener {

  KMAndroidSEApplet() {
    super(new KMAndroidSEProvider());
  }

  /**
   * Installs this applet.
   *
   * @param bArray the array containing installation parameters
   * @param bOffset the starting offset in bArray
   * @param bLength the length in bytes of the parameter data in bArray
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new KMAndroidSEApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
  }
  public Shareable getShareableInterfaceObject(AID clientID, byte parameter) {
	  
	    byte[] tempAID = {(byte)0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x02, 0x0C, 0x01, 0x02, 0x03};

	    if((clientID.equals(tempAID, (short)0, (byte)tempAID.length)) == false) {
	    	return null;
	    } else {
	    	if(parameter == 0x00) {
	    		return seProvider;
	    	} else if (parameter == 0x01) {
	    		return this;
	    	}
	    }
	    return null;
  }

  public void onCleanup() {
  }

  public void onConsolidate() {
  }

  public void onRestore(Element element) {
    element.initRead();
    provisionStatus = element.readByte();
    keymasterState = element.readByte();
    repository.onRestore(element);
    seProvider.onRestore(element);
  }

  public Element onSave() {
    // SEProvider count
    short primitiveCount = seProvider.getBackupPrimitiveByteCount();
    short objectCount = seProvider.getBackupObjectCount();
    //Repository count
    primitiveCount += repository.getBackupPrimitiveByteCount();
    objectCount += repository.getBackupObjectCount();
    //KMKeymasterApplet count
    primitiveCount += computePrimitveDataSize();
    objectCount += computeObjectCount();

    // Create element.
    Element element = UpgradeManager.createElement(Element.TYPE_SIMPLE,
        primitiveCount, objectCount);
    element.write(provisionStatus);
    element.write(keymasterState);
    repository.onSave(element);
    seProvider.onSave(element);
    return element;
  }

  private short computePrimitveDataSize() {
    // provisionStatus + keymasterState
    return (short) 2;
  }

  private short computeObjectCount() {
    return (short) 0;
  }
}

