import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

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
		FileOutputStream fos = new FileOutputStream("src/senderEncryptedAES.dat");
		fos.write(encryptedAESKey);
		fos.close();
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
	
	public byte[] getMAC(byte[] data)throws Exception{
		Mac mac = Mac.getInstance("HmacMD5");
		mac.init(pubAES);
		byte[] digest = mac.doFinal(data);
		return digest;
	}
	
	public void releaseEncryptedAES()throws Exception{
		encryptAESKey();
		System.out.println("Sender: Sending my encrypted AES key to Receiver. . .");
	}
	
	public void setReceiverPubRSA()throws Exception{
		FileInputStream fis = new FileInputStream("src/receiverPubRSA.dat");
		byte[] k = new byte[fis.available()];
		fis.read(k);
		fis.close();
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey pk = kf.generatePublic(new X509EncodedKeySpec(k));
		receiverPubRSA = pk;
		
	}
	
	public Key getPub(){
		return pubAES;
	}
	
}
