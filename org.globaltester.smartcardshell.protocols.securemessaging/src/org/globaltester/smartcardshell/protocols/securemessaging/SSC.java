package org.globaltester.smartcardshell.protocols.securemessaging;

import de.cardcontact.tlv.HexString;

public class SSC {

	//private static int SSCLENGTH = 8; //default length for BAC/EACv1
	
	// Default length of SSC:
	private static int DFLT_SSCLENGTH = 8;
	//TODO check how to handle this for different length
	
	private byte[] ssc; 
	
	
	public SSC(){
		
	}
	
	public void set(byte[] ssc){
		this.ssc = ssc;
	}
	
	
	public void increment(){
		for (int i = ssc.length - 1; i >= 0; i--) {
			ssc[i]++;
			if (ssc[i] != (byte) 0x00)
				i=0;
		}
	}

	public void decrement(){
		boolean carryBit = false;
		for (int i = ssc.length - 1; i >= 0; i--) {
			if (ssc[i] != (byte) 0x00) {
				ssc[i]--;
				if (carryBit) {
					for (int j = i + 1; j < ssc.length; j++) {
						ssc[j]--;
					}
					carryBit = false;
				}
				i = 0;
			}
			if (ssc[i] == (byte) 0x00) {
				carryBit = true;
			}
		}
	}

	public void reset(){
	
		if (ssc != null) {
			for (int i=0; i< ssc.length; i++){
				ssc[i] = 0x0;
			}
		} else {
			ssc = new byte[DFLT_SSCLENGTH];
		}
	}
	
//	public void compute(byte[] rndICC, byte[] rndIFD){
//		
//		ssc = new byte[DFLT_SSCLENGTH];
//		System.arraycopy(rndICC, 4, ssc, 0, 4);
//		System.arraycopy(rndIFD, 4, ssc, 4, 4);
//		
//		System.out.println("Initial SSC: "+HexString.hexifyByteArray(ssc));
//	}

	public int getLength(){
		return ssc.length;
	}
	
	public byte[] getEncoded(){
		return ssc;
	}
	
	public String toString(){
		return HexString.hexifyByteArray(ssc);
	}

	
}
