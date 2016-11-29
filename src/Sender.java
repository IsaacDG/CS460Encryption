import java.security.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Sender {
	
	private Key pubAES;
	private Key receiverPubRSA;
	private byte[] encryptedAESKey;
	
	public Sender() throws NoSuchAlgorithmException{
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(256);
		pubAES = kg.generateKey();
	}
	
	private void encryptAESKey() throws Exception{
		System.out.println("Sender: Encrypting my AES key with the Receiver's RSA key. . .");
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, receiverPubRSA);
		encryptedAESKey = cipher.doFinal(pubAES.getEncoded());
	}
	
	public byte[] encryptData(byte[] data) throws Exception{
		System.out.println("Sender: Encrypting the data with my AES key. . .");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, pubAES);
		System.out.println("Sender: Sending the encrypted data to the Reciever. . .");
		return cipher.doFinal(data);
	}
	
	public byte[] decryptData(byte[] data) throws Exception{
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, pubAES);
		return cipher.doFinal(data);
		
	}
	
	public byte[] getEncryptedAES()throws Exception{
		encryptAESKey();
		System.out.println("Sender: Sending my encrypted AES key to Receiver. . .");
		return encryptedAESKey;
	}
	
	public void setReceiverPubRSA(Key k){
		System.out.println("Sender: Got Receiver's public RSA key.");
		receiverPubRSA = k;
	}
	
	public Key getPub(){
		return pubAES;
	}
	
}
