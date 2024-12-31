
// This is the client-side implementation of the protocol. When run, it connects to the server at the specified host and port, and then executes the steps of the protocol:

// 1. Send the "Connect Protocol 1" message to the server.
// 2. Receive the server's nonce challenge and save it.
// 3. Generate a nonce challenge for the server and send it.
// 4. Calculate the session key and send the concatenated nonces encrypted with the session key.
// 5. Receive the concatenated nonces encrypted with the session key and verify they match.
// 6. Decrypt the message containing the secret value and print it to the console.

// The `encrypt` and `decrypt` methods are used to encrypt and decrypt messages with the given AES key. They use the PKCS#5 padding scheme and ECB mode of operation.

// Note that this implementation assumes that the server is running the code from the provided `Protocol1Server.java` file. If the server has a different implementation, the client may need to be modified accordingly.



import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class Protocol1Client {

    static String hostName = "localhost";
    static int portNo = 11337;
    static String hexKey = "5";

    public static void main(String[] args) {
        try {
            Socket socket = new Socket(hostName, portNo);
            OutputStream outStream = socket.getOutputStream();
            InputStream inStream = socket.getInputStream();

            // Protocol Step 1
            String message1 = "Connect Protocol 1";
            outStream.write(message1.getBytes());

            // Protocol Step 2
            byte[] message2 = new byte[16];
            inStream.read(message2);
            byte[] serverNonce = decrypt(message2, hexStringToByteArray(hexKey));

            // Protocol Step 3
            SecureRandom random = new SecureRandom();
            byte[] clientNonce = new byte[16];
            random.nextBytes(clientNonce);
            byte[] message3 = encrypt(clientNonce, hexStringToByteArray(hexKey));
            outStream.write(message3);

            // Calculate session key
            byte[] keyBytes = xorBytes(serverNonce, clientNonce);
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
            Cipher decAEScipherSession = Cipher.getInstance("AES");
            decAEScipherSession.init(Cipher.DECRYPT_MODE, secretKeySpec);
            Cipher encAEScipherSession = Cipher.getInstance("AES");
            encAEScipherSession.init(Cipher.ENCRYPT_MODE, secretKeySpec);

            // Protocol Step 4
            byte[] message4pt = new byte[32];
            System.arraycopy(clientNonce, 0, message4pt, 0, 16);
            System.arraycopy(serverNonce, 0, message4pt, 16, 16);
            byte[] message4 = encrypt(message4pt, keyBytes);
            outStream.write(message4);

            // Protocol Step 5
            byte[] message5pt = new byte[32];
            byte[] message5 = new byte[48];
            inStream.read(message5);
            message5pt = decrypt(message5, keyBytes);
            byte[] inNs = new byte[16];
            byte[] inNc = new byte[16];
            System.arraycopy(message5pt, 0, inNs, 0, 16);
            System.arraycopy(message5pt, 16, inNc, 0, 16);

            // Check the challenge values are correct
            if (!(Arrays.equals(inNc, clientNonce) && Arrays.equals(inNs, serverNonce))) {
                System.out.println("Nonces don't match");
                return;
            }

            // Protocol Step 6
            byte[] message6pt = decrypt(inNc, inNs);
            System.out.println(new String(message6pt));

            // Close the socket connection
            socket.close();

        } catch (Exception e) {
            System.out.println("Doh " + e);
        }
    }

    private static byte[] xorBytes(byte[] one, byte[] two) {
        if (one.length != two.length) {
            return null;
        } else {
            byte[] result = new byte[one.length];
            for (int i = 0; i < one.length; i++) {
                result[i] = (byte) (one[i] ^ two[i]);
            }
            return result;
        }
    }

    private static byte[] encrypt(byte[] message, byte[] keyBytes) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Key aesKey = new SecretKeySpec(keyBytes, "AES");
        Cipher encAEScipher = Cipher.getInstance("AES");
        encAEScipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return encAEScipher.doFinal(message);
    }
    
    private static byte[] decrypt(byte[] message, byte[] keyBytes) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Key aesKey = new SecretKeySpec(keyBytes, "AES");
        Cipher decAEScipher = Cipher.getInstance("AES");
        decAEScipher.init(Cipher.DECRYPT_MODE, aesKey);
        return decAEScipher.doFinal(message);
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