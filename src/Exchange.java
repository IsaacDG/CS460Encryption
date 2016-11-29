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
		s.setReceiverPubRSA(r.givePublic());
		r.setSenderAES(s.getEncryptedAES());
		
		String filePath = "src/tosend.txt";
		File f = new File(filePath);
		byte[] plain = Files.readAllBytes(f.toPath());
		FileOutputStream fos = new FileOutputStream("src/test1.txt");
		fos.write(r.decryptData(s.encryptData(plain)));
		
	}

}