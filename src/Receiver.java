import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Receiver {

	private Key pubRSA;
	private Key privRSA;
	private byte[] senderEncAES;
	private Key senderAES;
	
	public Receiver() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException{
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		pubRSA = kp.getPublic();
		privRSA = kp.getPrivate();	//generating a symmetric AES key
		
	}
	
	private void decryptSenderAES() throws Exception{
		System.out.println("Receiver: Decrypting the Sender's AES key with my RSA private key. . .");
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privRSA);
		byte[] temp = cipher.doFinal(senderEncAES);
		senderAES = new SecretKeySpec(temp, 0, temp.length, "AES");
		
	}
	
	public void decryptData()throws Exception{
		decryptSenderAES();
		System.out.println("Receiver: Decrypting the data. . .");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, senderAES);
		FileInputStream fis = new FileInputStream("src/encryptedData.dat");
		byte[] data = new byte[fis.available()];
		fis.read(data);
		fis.close();
		FileOutputStream fos = new FileOutputStream("src/decryptedData.dat");
		fos.write(cipher.doFinal(data));
		fos.close();
	}
	
	public void decryptDataWMAC()throws Exception{
		decryptSenderAES();
		System.out.println("Receiver: Decrypting the data. . .");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, senderAES);
		FileInputStream fis = new FileInputStream("src/encryptedData.dat");
		byte[] data = new byte[fis.available()];
		fis.read(data);
		fis.close();
		byte[] datSizeArr = Arrays.copyOfRange(data, 0, 4);
		ByteBuffer wrap = ByteBuffer.wrap(datSizeArr);
		int datSize = wrap.getInt();

		byte[] dat = Arrays.copyOfRange(data, 4, 4 + datSize);

		byte[] sizeMACArr = Arrays.copyOfRange(data, 4 + datSize, 4 + datSize + 4);
		wrap = ByteBuffer.wrap(sizeMACArr);
		int macSize = wrap.getInt();
		byte[] MAC = Arrays.copyOfRange(data, 4 + datSize + 4, 4 + datSize + 4 + macSize);

		byte[] decipheredDat = cipher.doFinal(dat);
		
		if(dataGood(decipheredDat, MAC)){
			System.out.println("Receiver: MAC verified, writing decrypted data to file. . . ");
			FileOutputStream fos = new FileOutputStream("src/decryptedData.dat");
			fos.write(decipheredDat);
			fos.close();
		} else {
			System.out.println("Receiver: MAC could not be verified, closing program.");
		}
		
	}
	
	public boolean dataGood(byte[] data, byte[] recMAC)throws Exception{
		Mac mac = Mac.getInstance("HmacMD5");
		mac.init(senderAES);
		byte[] digest = mac.doFinal(data);
		for(int i = 0; i < recMAC.length; i++){
			if(recMAC[i] != digest[i]){
				return false;
			}
		}
		return true;
	}
	
	public void setSenderAES()throws Exception{
		System.out.println("Receiver: Got the Sender's encrypted AES key.");
		FileInputStream fis = new FileInputStream("src/senderEncryptedAES.dat");
		byte[] k = new byte[fis.available()];
		fis.read(k);
		fis.close();
		senderEncAES = k;
	}
	
	public Key givePublic(){
		System.out.println("Receiver: Sending my RSA public key to the Sender. . .");
		return pubRSA;
	}
	
	public void releasePublic()throws Exception{
		FileOutputStream fos = new FileOutputStream("src/receiverPubRSA.dat");
		fos.write(pubRSA.getEncoded());
		fos.close();
	}
	
	
}
