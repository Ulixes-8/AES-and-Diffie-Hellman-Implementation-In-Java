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
public class Protocol2Client3 {

    // Server IP address and port number
static String serverIP = "localhost";        // server IP address (in this case, running on same machine)
    static int portNo = 11338;      


	public static void main(String[] args) {

        try {

            System.out.println("Connecting to server...");
            Socket myConnection = new Socket(serverIP, portNo);
            DataOutputStream outStream = new DataOutputStream(myConnection.getOutputStream());
            DataInputStream inStream = new DataInputStream(myConnection.getInputStream());
            System.out.println("Connected to server.");
   
            byte[] gBytes = hexStringToByteArray("dd14a10d8200fb914767670fcc0063d1");
            
		    outStream.write(gBytes);
        
        
        } catch (Exception e) {
            e.printStackTrace();
        }

    }  
    private static byte[] hexStringToByteArray(String s) {
        // Convert hex string to byte array
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

} 