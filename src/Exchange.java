import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Exchange {
	
public static void main(String[] args) throws Exception {
		
		Receiver r = new Receiver();
		Sender s = new Sender();
		r.releasePublic();
		s.setReceiverPubRSA();
		s.releaseEncryptedAES();
		r.setSenderAES();
		
		String filePath = "src/tosend.txt";
		File f = new File(filePath);
		byte[] plain = Files.readAllBytes(f.toPath());
		s.encryptDataAddMAC(plain);
		r.decryptDataWMAC();
		
	}

//	public static void main(String[] args) throws Exception {
//		
//		Receiver r = new Receiver();
//		Sender s = new Sender();
//		r.releasePublic();
//		s.setReceiverPubRSA();
//		s.releaseEncryptedAES();
//		r.setSenderAES();
//		
//		String filePath = "src/tosend.txt";
//		File f = new File(filePath);
//		byte[] plain = Files.readAllBytes(f.toPath());
//		s.encryptData(plain);
////		byte[] senderMAC = s.getMAC(plain);
//		r.decryptData();
////		if(r.dataGood(dataPlain, senderMAC)) System.out.println("MAC Verified By Receiver. . .");
////		fos.write(dataPlain);
////		fos.close();
//		
//	}

}
