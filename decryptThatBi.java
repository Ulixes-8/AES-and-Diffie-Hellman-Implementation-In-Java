import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec; 
//import arrays
import java.util.Arrays;
import java.util.Scanner;


public class decryptThatBitch {

    static String serverIP = "localhost";        // server IP address (in this case, running on same machine)
    static int portNo = 11338;      

	// Values of p & g for Diffie-Hellman found using generateDHprams()
	static BigInteger g = new BigInteger("129115595377796797872260754286990587373919932143310995152019820961988539107450691898237693336192317366206087177510922095217647062219921553183876476232430921888985287191036474977937325461650715797148343570627272553218190796724095304058885497484176448065844273193302032730583977829212948191249234100369155852168");
	static BigInteger p = new BigInteger("165599299559711461271372014575825561168377583182463070194199862059444967049140626852928438236366187571526887969259319366449971919367665844413099962594758448603310339244779450534926105586093307455534702963575018551055314397497631095446414992955062052587163874172731570053362641344616087601787442281135614434639");
    static Cipher decAESsessionCipher;
	static Cipher encAESsessionCipher;
	public static void main(String[] args) {

	    try {
		String hexKey = "477dbcf529334a879beee3973931fcc1";

        //Use first 16 bytes of g^xy to make an AES key
		byte[] aesSecret = hexStringToByteArray(hexKey);
		Key aesSessionKey = new SecretKeySpec(aesSecret, "AES");
		 System.out.println("Session key: "+byteArrayToHexString(aesSessionKey.getEncoded()));
		// Set up Cipher Objects
		decAESsessionCipher = Cipher.getInstance("AES");
		decAESsessionCipher.init(Cipher.DECRYPT_MODE, aesSessionKey);
		encAESsessionCipher = Cipher.getInstance("AES");
		encAESsessionCipher.init(Cipher.ENCRYPT_MODE, aesSessionKey);
	    } catch (NoSuchAlgorithmException e ) {
		System.out.println(e);
	    } catch (InvalidKeyException e) {
		System.out.println(e);
	    } catch (NoSuchPaddingException e) {
		e.printStackTrace();
	    }


        try {

        String secretValue = "bd3b5ccbcd0c59faad48d67bb727fc3d14dd46a3124828d0130bedcf82ad041a";
        //Decrypt the secret value
        byte[] secretValueBA = hexStringToByteArray(secretValue);
        System.out.println("Lenght of secret value: "+secretValueBA.length);
        byte[] decryptedSecretValueBA = decAESsessionCipher.doFinal(secretValueBA);
        System.out.println("Decrypted secret value: "+byteArrayToHexString(decryptedSecretValueBA));
        } catch (IllegalBlockSizeException e) {
        e.printStackTrace();
        } catch (BadPaddingException e) {
        e.printStackTrace();
        }
            

}
private static String byteArrayToHexString(byte[] data) { 
    StringBuffer buf = new StringBuffer();
    for (int i = 0; i < data.length; i++) { 
    int halfbyte = (data[i] >>> 4) & 0x0F;
    int two_halfs = 0;
    do { 
        if ((0 <= halfbyte) && (halfbyte <= 9)) 
        buf.append((char) ('0' + halfbyte));
        else 
        buf.append((char) ('a' + (halfbyte - 10)));
        halfbyte = data[i] & 0x0F;
    } while(two_halfs++ < 1);
    } 
    return buf.toString();
} 

private static byte[] hexStringToByteArray(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
    data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                  + Character.digit(s.charAt(i+1), 16));
    }
    return data;
}

} 

