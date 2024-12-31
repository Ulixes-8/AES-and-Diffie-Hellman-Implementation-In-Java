import java.security.Key;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

//This Java code generates a new AES key and outputs its value in different formats. The AES (Advanced Encryption Standard) algorithm is a widely used symmetric encryption algorithm.
//
//The KeyGenerator class is used to generate a new AES key. The generateKey() method is called to generate the key, which is then stored in the Key object named "aesKey". The key's value is then extracted as an array of bytes using the getEncoded() method and stored in the "keyBytes" array.
//
//The code then outputs the key value in three different formats:
//
//    As a string representation of the byte array using the (new String(keyBytes)) method.
//
//    As a string representation of the integer values of the bytes in the array using the Arrays.toString(keyBytes) method.
//
//    As a hexadecimal string using the byteArrayToHexString() method. This method takes the byte array as input and converts each byte to its hexadecimal representation, which is then concatenated to form a string.
//
//The output of this code can be used as a secret key for AES encryption and decryption.
public class GenAESkey {
    public static void main(String[] args) {
        try {
            // Generate a new AES key
            KeyGenerator sGen = KeyGenerator.getInstance("AES");
            Key aesKey = sGen.generateKey();
            byte[] keyBytes = aesKey.getEncoded();
            System.out.println("Key as bytes: "+(new String(keyBytes)));
            System.out.println("Key as ints: "+Arrays.toString(keyBytes));

            String printableKey = byteArrayToHexString(keyBytes);
            System.out.println("Key as hex: "+printableKey);
        } catch (Exception e){
            System.out.println("doh");
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
}