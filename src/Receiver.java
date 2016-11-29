import java.security.*;

import javax.crypto.Cipher;
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
	
	public byte[] decryptData(byte[] data)throws Exception{
		decryptSenderAES();
		System.out.println("Receiver: Decrypting the data. . .");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, senderAES);
		return cipher.doFinal(data);
	}
	
	public void setSenderAES(byte[] k){
		System.out.println("Receiver: Got the Sender's encrypted AES key.");
		senderEncAES = k;
	}
	
	public Key givePublic(){
		System.out.println("Receiver: Sending my RSA public key to the Sender. . .");
		return pubRSA;
	}
	
	
}
