import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
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
		encryptedAESKey = cipher.doFinal(pubAES.getEncoded());	//encrypt the AES key using the RSA key.
		FileOutputStream fos = new FileOutputStream("src/senderEncryptedAES.dat");
		fos.write(encryptedAESKey);
		fos.close();
	}
	
	public void encryptData(byte[] data) throws Exception{
		System.out.println("Sender: Encrypting the data with my AES key. . .");
		Cipher cipher = Cipher.getInstance("AES");	//encrypt the data using our AES key
		cipher.init(Cipher.ENCRYPT_MODE, pubAES);
		System.out.println("Sender: Sending the encrypted data to the Reciever. . .");
		FileOutputStream fos = new FileOutputStream("src/encryptedData.dat");
		fos.write(cipher.doFinal(data));
		fos.close();
	}
	
	public void encryptDataAddMAC(byte[] data) throws Exception{
		System.out.println("Sender: Encrypting the data with my AES key. . .");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, pubAES);
		FileOutputStream fos = new FileOutputStream("src/encryptedData.dat");
		byte[] dataCipher = cipher.doFinal(data);
		byte[] dataMAC = getMAC(data);
		
		fos.write(ByteBuffer.allocate(4).putInt(dataCipher.length).array());	//write bytes of data size
		fos.write(dataCipher);
		fos.write(ByteBuffer.allocate(4).putInt(dataMAC.length).array());		//write bytes of MAC size
		
		System.out.println("Sender: Appending MAC to data. . .");
		fos.write(dataMAC);
		fos.close();
		System.out.println("Sender: Sending the encrypted data to the Reciever. . .");
	}
	
	public byte[] decryptData(byte[] data) throws Exception{
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, pubAES);
		return cipher.doFinal(data);
		
	}
	
	public byte[] getMAC(byte[] data)throws Exception{
		Mac mac = Mac.getInstance("HmacMD5");
		mac.init(pubAES);			//initialize HMAC using my AES key.
		byte[] digest = mac.doFinal(data);
		return digest;
	}
	
	public void releaseEncryptedAES()throws Exception{
		encryptAESKey();
		System.out.println("Sender: Sending my encrypted AES key to Receiver. . .");
	}
	
	public void setReceiverPubRSA()throws Exception{
		FileInputStream fis = new FileInputStream("src/receiverPubRSA.dat");	//get the RSA key from the file.
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
