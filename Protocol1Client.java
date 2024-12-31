import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;



// This is a Java program that creates a client socket variable.
public class Protocol1Client {
            
                // Define some constants to be used in the protocol
                static String serverIP = "localhost";        // server IP address (in this case, running on same machine)
                static int portNo = 11337;                   // port number on which the server is listening
            
                public static void main(String[] args) {
                    try {
                        // Step 1: Connect to the server
                        System.out.println("Connecting to server...");
                        Socket client = new Socket(serverIP, portNo);
                        OutputStream outStream = client.getOutputStream();
                        InputStream inStream = client.getInputStream();
                        // Protocol Step 1
                        String message1 = "Connect Protocol 1";
                        outStream.write(message1.getBytes());

                        // Step 2: Receive a nonce from the server and store it
                        System.out.println("Receiving nonce from server...");
                        byte[] serverNonce = new byte[32];
        
                        inStream.read(serverNonce);
            
                        // Step 3: Return the encrypted nonce that the server sent to us
                        System.out.println("Sending nonce to server...");
                        outStream.write(serverNonce);
            		    System.out.println("Server Nonce "+byteArrayToHexString(serverNonce));

                        //Print size of serverNonce in bytes
                        System.out.println("Size of serverNonce: " + serverNonce.length);
            
                        //Introduce a delay to simulate a slow connection
                        Thread.sleep(1000); 

                        
                        byte[] message4 = new byte[48];
                        
                        inStream.read(message4);
                        System.out.println("Received message: " + byteArrayToHexString(message4));
            
                        Thread.sleep(1000); 
                        
                        outStream.write(message4);
                        System.out.println("Sending message to server...");

                        

                        //Calculate session key 
                            // Calculate session key
                        String msg = "3909cb35d6fd95cafba153825a3da2b6";
                        byte[] keyBytes = xorBytes(hexStringToByteArray(msg), hexStringToByteArray(msg));
                        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
                        Cipher decAEScipherSession = Cipher.getInstance("AES");			
                        decAEScipherSession.init(Cipher.DECRYPT_MODE, secretKeySpec);
                        Cipher encAEScipherSession = Cipher.getInstance("AES");			
                        encAEScipherSession.init(Cipher.ENCRYPT_MODE, secretKeySpec);
                        System.out.println("Session key :"+byteArrayToHexString(keyBytes));

                        Thread.sleep(1000); 

                        // Step 6: Wait for server response and decrypt it.
                        byte[] message6 = new byte[48];
                        inStream.read(message6);
                        System.out.println("Received message: " + byteArrayToHexString(message6));
                        
                        byte[] decryptedMessage6 = decAEScipherSession.doFinal(message6);
                        //Put it in plaintext
                        
                        System.out.println("Decrypted message: " + byteArrayToHexString(decryptedMessage6));
                                
                        
                        client.close();
            
                    } catch (Exception e) {
                        System.out.println("Doh " + e);
                    }
                }
                
                private static byte[] xorBytes(byte[] one, byte[] two) {
                    // Perform an XOR operation of two byte arrays
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
        