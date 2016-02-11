package org.globaltester.smartcardshell.protocols.securemessaging;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import de.cardcontact.scdp.utils.ByteBuffer;
import de.cardcontact.tlv.HexString;
import de.cardcontact.tlv.PrimitiveTLV;
import de.cardcontact.tlv.TLV;
import de.cardcontact.tlv.TLVEncodingException;

public class SecureMessaging {

	private SecretKey skenc;
	private SecretKey skmac;

	private SSC ssc;

	private Cipher cipher;
	private boolean initialized;

	// private Mac mac;

	public SecureMessaging() {
		ssc = new SSC();
		java.security.Security
				.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()); // TODO
																						// check
																						// where
																						// this
																						// call
																						// should
																						// be
																						// placed
																						// best
		try {
			cipher = Cipher.getInstance("DESede/CBC/NoPadding");
			// mac = Mac.getInstance("ISO9797ALG3WITHISO7816-4PADDING",
			// BouncyCastleProvider.PROVIDER_NAME);
			// mac = Mac.getInstance("ISO9797Alg3Mac");

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} // catch (NoSuchProviderException e) {
		// // TODO Auto-generated catch block
		// e.printStackTrace();
		// }
	}
	
	public boolean isInitialized() {
		return initialized;
	}
	
	public void setInitialized(boolean initState) {
		initialized = initState;
	}

	public void setKeyEnc(SecretKey skenc) {
		this.skenc = skenc;
	}

	public SecretKey getKeyEnc() {
		return skenc;
	}

	public void setKeyMac(SecretKey skmac) {
		this.skmac = skmac;
	}

	public SecretKey getKeyMac() {
		return skmac;
	}

	public String getAlgorithm() {
		return skmac.getAlgorithm();
	}

	 public void setSendSequenceCounter(byte[] newSSC){
	 ssc.set(newSSC);
	 }
	
	 public byte[] getSendSequenceCounter(){
	 return ssc.getEncoded();
	 }
	
	// public void initialSSC(SSC ssc){
	// this.ssc = ssc;
	// }

	public byte[] wrapSM(byte[] commandAPDU) throws TLVEncodingException {

		boolean useExtendedLength = false;
		ByteBuffer command = new ByteBuffer(commandAPDU);

		String cmdDump = HexString.dump(command.getBytes());
		System.out
				.println("Wrapping following command APDU in SM:\n" + cmdDump);

		// define blocksize depending on algorithm
		int blockSize = 8;
		// if (keyEncId == 250)
		// blockSize = 16;
		//
		// //increase ssc if using AES
		// if (keyEncId == 250) {
		// se.increaseSsc();
		// }

		// Transform CLA byte and construct SM header
		ByteBuffer header = new ByteBuffer();
		header.append((byte) (command.getByteAt(0) | 0x0C));
		header.append(command.getBytes(1, 3));

		// add header to mac input
		ByteBuffer macInput = new ByteBuffer();
		macInput.append(header);
		macInput = new ByteBuffer(padding(macInput.getBytes(), blockSize));

		// init the expected length
		ByteBuffer le = new ByteBuffer();

		// init
		ByteBuffer encDataTLV = new ByteBuffer();

		if (command.length() > 4) {
			// handle following length field
			int lc = (0x000000FF & command.getByteAt(4));
			int dataOffset = 5;

			if (lc == 0 && command.length() > 5) {
				// two byte length
				int a1 = (0x000000FF & command.getByteAt(5));
				int a2 = (0x000000FF & command.getByteAt(6));
				lc = (a1 << 8) | a2;
				dataOffset += 2;
				useExtendedLength = true;
			}

			if (command.length() > dataOffset) {
				// handle data
				ByteBuffer plain = new ByteBuffer(command.getBytes(dataOffset,
						lc));

				// find out which smTag to use
				int smTag = 0x87;
				if ((command.getByteAt(1) & 1) == 1) {
					smTag = 0x85;
				}

				// get the encrypted data
				ByteBuffer cryptogram = new ByteBuffer();
				if (smTag == 0x87) {
					cryptogram.append((byte) 0x01);
				}
				// if (keyEncId == 250) {
				// cryptogram.append(se.computeCryptogramAES(plain.getBytes(),
				// keyEncId, Cipher.ENCRYPT_MODE));
				// } else {
				plain = new ByteBuffer(padding(plain.getBytes(), blockSize));
				cryptogram.append(Crypto.computeCryptogram(plain.getBytes(),
						skenc, Cipher.ENCRYPT_MODE));
				// }
				TLV tmpTLV = new PrimitiveTLV(smTag, cryptogram.getBytes());
				encDataTLV.append(tmpTLV.getBytes());

				macInput.append(encDataTLV);

				if (command.length() > dataOffset + lc) {
					le = new ByteBuffer(command.getBytes(dataOffset + lc,
							command.length() - dataOffset - lc));
				}
			} else {
				// no following data, current field must be le
				le = new ByteBuffer(command.getBytes(4, dataOffset - 4));
				// delete leading zero if extended length is used
				if (le.getByteAt(0) == 0x0 && le.length() > 1) {
					le = new ByteBuffer(le.getBytes(1, le.length() - 1));
					useExtendedLength = true;
				}
			}
		}

		// construct the expected length
		ByteBuffer leTLV = new ByteBuffer();

		if (le.length() > 0) {
			leTLV = new ByteBuffer();
			leTLV.append(new byte[] { (byte) 0x97 });
			leTLV.append((byte) le.length());
			leTLV.append(le);

			// add expected length to macInput
			macInput.append(leTLV);
		}

		// do padding and calculate the checksum
		ByteBuffer checksum = new ByteBuffer();
		if (macInput.length() > blockSize) {
			macInput = new ByteBuffer(padding(macInput.getBytes(), blockSize));
		}
		// if (keyMacId == 251) {
		// checksum.append(se.computeChecksumAES(macInput.getBytes(),
		// keyMacId, true));
		// } else {

		ssc.increment();
		System.out.println("M: "
				+ HexString.hexifyByteArray(macInput.getBytes()));
		ByteBuffer n = new ByteBuffer(ssc.getEncoded());
		n.append(macInput.getBytes());
		System.out.println("N: " + HexString.hexifyByteArray(n.getBytes()));

		checksum.append(Crypto.computeChecksum(n.getBytes(), skmac, true));

		// }

		ByteBuffer checksumTLV = new ByteBuffer();
		checksumTLV.append(new byte[] { (byte) 0x8E, 0x08 });
		checksumTLV.append(checksum);

		// calculate LC
		ByteBuffer encLC = new ByteBuffer();
		int encLCshort = encDataTLV.length() + leTLV.length()
				+ checksumTLV.length();
		if (encLCshort <= 255 && !useExtendedLength) {
			encLC.append((byte) (encLCshort));
		} else {
			encLC.append((byte) 0x00);
			encLC.append(HexString.parseHexString(HexString
					.hexifyShort(encLCshort)));
		}

		// construct the return value
		ByteBuffer smCommand = new ByteBuffer();
		smCommand.append(header);
		smCommand.append(encLC);
		smCommand.append(encDataTLV);
		smCommand.append(leTLV);
		smCommand.append(checksumTLV);
		smCommand.append((byte) 0x00);
		if (encLC.length() > 1) {
			// extended length is needed for lc, le needs to be extended length
			// also
			smCommand.append((byte) 0x00);
		}

		return smCommand.getBytes();
	}

	public static byte[] padding(byte[] data, int blockSize) {
		ByteBuffer paddedData = new ByteBuffer(data);
		paddedData.append((byte) 0x80);
		while (paddedData.length() % blockSize != 0) {
			paddedData.append((byte) 0x00);
		}
		return paddedData.getBytes();
	}

	public static byte[] unpadding(byte[] in) {
		System.out.println("To unpadd: " + HexString.hexifyByteArray(in));

		int i = in.length - 1;
		while (i >= 0 && in[i] == 0x00) {
			i--;
		}
		if ((in[i] & 0xFF) != 0x80) {
			// throw new
			// IllegalStateException("unpad expected constant 0x80, found 0x" +
			// Integer.toHexString((in[i] & 0x000000FF)) + "\nDEBUG: in = " +
			// Hex.bytesToHexString(in) + ", index = " + i);
			System.out.println("Error during unpadding!");
		}
		byte[] out = new byte[i];
		System.arraycopy(in, 0, out, 0, i);
		return out;
	}

	public byte[] unwrap(byte[] encryptedData) throws IOException {
		IvParameterSpec ivSpec = new IvParameterSpec(Crypto.nullIV);
		try {
			cipher.init(Cipher.DECRYPT_MODE, skenc, ivSpec);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		DataInputStream in = new DataInputStream(new ByteArrayInputStream(
				encryptedData));
		byte[] data = new byte[0];
		short sw = 0;
		boolean finished = false;
		byte[] cc = null;
		while (!finished) {
			int tag = 0;
			try {
				tag = in.readByte();
			} catch (EOFException e){
				break;
			}
			switch (tag) {
			case (byte) 0x87:
				data = readDO87(in, false);
				break;
			case (byte) 0x85:
				data = readDO87(in, true);
				break;
			case (byte) 0x99:
				sw = readDO99(in);
				break;
			case (byte) 0x8E:
				cc = readDO8E(in);
				System.out.println("CC of R-APDU: "
						+ HexString.hexifyByteArray(cc));
				finished = true;
				break;
			default:
				//TODO handle invalid tag in SM response field
			}
		}

		if (!finished) {
			System.out.println("ERROR: incorrectly structured SM response!");
			return new byte[] {};
		}
		if (!checkResponseMAC(encryptedData, cc)) {
			System.out.println("ERROR: Invalid MAC!");
		}

		//TODO handle inconsistent SW within DO99 compared to APDU SW
		if (sw==0) {
			System.out.println("WARNING: No DO99 found!");
		}

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(data, 0, data.length);
		return out.toByteArray();

		//TODO Bei Fehler ssc.decrease() durchführen!
	}

	private byte[] readDO87(DataInputStream in, boolean do85)
			throws IOException {

		int length = 0;
		int buf = in.readUnsignedByte();
		if ((buf & 0x00000080) != 0x00000080) {
			length = buf;
			if (!do85) {
				buf = in.readUnsignedByte();
				if (buf != 0x01) {
					throw new IllegalStateException(
							"DO'87 expected 0x01 marker, found "
									+ HexString.hexifyByte((byte) buf));
				}
			}
		} else {
			int lengthBytesCount = buf & 0x0000007F;
			for (int i = 0; i < lengthBytesCount; i++) {
				length = (length << 8) | in.readUnsignedByte();
			}
			if (!do85) {
				buf = in.readUnsignedByte();
				if (buf != 0x01) {
					throw new IllegalStateException(
							"DO'87 expected 0x01 marker");
				}
			}
		}
		if (!do85) {
			length--;
		}

		byte[] ciphertext = new byte[length];
		in.readFully(ciphertext);
		byte[] paddedData;
		try {
			paddedData = cipher.doFinal(ciphertext);
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		byte[] data = unpadding(paddedData);
		return data;

	}

	private short readDO99(DataInputStream in) throws IOException {
		int length = in.readUnsignedByte();
		if (length != 2) {
			throw new IllegalStateException("DO'99 wrong length");
		}
		byte sw1 = in.readByte();
		byte sw2 = in.readByte();
		return (short) (((sw1 & 0x000000FF) << 8) | (sw2 & 0x000000FF));
	}

	private byte[] readDO8E(DataInputStream in) throws IOException {
		int length = in.readUnsignedByte();
		if (length != 8) {
			throw new IllegalStateException("DO'8E wrong length");
		}
		byte[] cc1 = new byte[8];
		in.readFully(cc1);
		return cc1;
	}

	private boolean checkResponseMAC(byte[] rapdu, byte[] cc1) {

		ssc.increment();
		ByteBuffer bb = new ByteBuffer();
		bb.append(ssc.getEncoded());
		byte[] toPad = new byte[rapdu.length - 2 - 8 - 2];
		System.arraycopy(rapdu, 0, toPad, 0, rapdu.length - 2 - 8 - 2);
		byte[] paddedData = padding(toPad, 8);
		bb.append(paddedData);

		byte[] cc2 = Crypto.computeMAC(bb.getBytes(), skmac, "ISO9797Alg3Mac");
		System.out.println("CC': " + HexString.hexifyByteArray(cc2));

		return Arrays.equals(cc1, cc2);

	}

}
