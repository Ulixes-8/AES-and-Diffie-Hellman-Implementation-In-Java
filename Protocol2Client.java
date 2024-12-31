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


public class Protocol2Client {

    static String serverIP = "localhost";        // server IP address (in this case, running on same machine)
    static int portNo = 11338;      

	// Values of p & g for Diffie-Hellman found using generateDHprams()
	static BigInteger g = new BigInteger("129115595377796797872260754286990587373919932143310995152019820961988539107450691898237693336192317366206087177510922095217647062219921553183876476232430921888985287191036474977937325461650715797148343570627272553218190796724095304058885497484176448065844273193302032730583977829212948191249234100369155852168");
	static BigInteger p = new BigInteger("165599299559711461271372014575825561168377583182463070194199862059444967049140626852928438236366187571526887969259319366449971919367665844413099962594758448603310339244779450534926105586093307455534702963575018551055314397497631095446414992955062052587163874172731570053362641344616087601787442281135614434639");
    static Cipher decAESsessionCipher;
	static Cipher encAESsessionCipher;
	public static void main(String[] args) {

        try {

            // Step 1: Connect to the server
            System.out.println("Connecting to server...");
            Socket myConnection = new Socket(serverIP, portNo);
            DataOutputStream outStream = new DataOutputStream(myConnection.getOutputStream());
            DataInputStream inStream = new DataInputStream(myConnection.getInputStream());
            System.out.println("Connected to server.");
   
            // Protocol Step 1
            // C -> S: g^x
            System.out.println("Sending g^x to server...");
            DHParameterSpec dhSpec = new DHParameterSpec(p,g);
		    KeyPairGenerator diffieHellmanGen = KeyPairGenerator.getInstance("DiffieHellman");
		    diffieHellmanGen.initialize(dhSpec);
		    KeyPair serverPair = diffieHellmanGen.generateKeyPair();
		    PrivateKey x = serverPair.getPrivate();
		    PublicKey gToTheX = serverPair.getPublic();
		     System.out.println("g^x len: "+gToTheX.getEncoded().length);
		     System.out.println("g^x cert: "+byteArrayToHexString(gToTheX.getEncoded()));
            outStream.writeInt(gToTheX.getEncoded().length);
		    outStream.write(gToTheX.getEncoded());
            System.out.println("Sent g^x to server.");
   
            //Protocol Step 2
            //S -> C: g^y
            System.out.println("Receiving g^y from server...");
            int publicKeyLen = inStream.readInt();
		    byte[] message1 = new byte[publicKeyLen];
		    inStream.read(message1);
		    KeyFactory keyfactoryDH = KeyFactory.getInstance("DH");
		    X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(message1);
		    PublicKey gToTheY = keyfactoryDH.generatePublic(x509Spec);
		     System.out.println("g^y len: "+publicKeyLen);
		     System.out.println("g^y cert: "+byteArrayToHexString(gToTheX.getEncoded()));
            System.out.println("Received g^y from server.");
		    calculateSessionKey(x, gToTheY);
            System.out.println("Calculated session key.");
  
            // Protocol Step 3
            // C -> S: {Nonce} gXY
            System.out.println("Sending nonce to server...");
		    SecureRandom gen = new SecureRandom();
		    // int clientNonce = gen.nextInt();
            // int clientNonce = 1111111111;
            int clientNonce = 1786732326;
            System.out.println("Client nonce: "+clientNonce);
		    byte[] clientNonceBytes = BigInteger.valueOf(clientNonce).toByteArray();
            byte[] encq = encAESsessionCipher.doFinal(clientNonceBytes);
            //oNLY SEND FIRST 16 BYTES
            byte[] encq16 = new byte[16];
            for(int i=0;i<16;i++){
            	encq16[i]=encq[i];
            }
            outStream.write(encq16);
        
        
            // Protocol Step 4
            //S -> C: {{clientNonce+1}Kcs, Ns} gXY
            byte[] message4ct = new byte[32];
            inStream.read(message4ct);
            byte[] message4body = decAESsessionCipher.doFinal(message4ct);
            // Extracting the encrypted client nonce from the received data
            byte[] encryptedClientNonceInc = new byte[16]; // {Ncs + 1}Kcs

            System.arraycopy(message4body,0,encryptedClientNonceInc,0,16);
            //Extracting the server nonce from the received data
            byte[] serverNonceBytes = new byte[4];
            System.arraycopy(message4body,16,serverNonceBytes,0,4);
            //Fetching the server nonce value
            int serverNonce = new BigInteger(serverNonceBytes).intValue();
            System.out.println("Received nonce from server.");
            System.out.println("server nonce: "+serverNonce); 
            System.out.println("encrypted client nonce: "+byteArrayToHexString(encryptedClientNonceInc));

            // Protocol Step 5
            // C -> S: {ServerNonce+1}Kcs
            //Import scanner
            
            

            //Take in user string input. 
            System.out.println("Enter a string to send to the server: ");
            Scanner sc = new Scanner(System.in);
            String userString = sc.nextLine();
            
            //Convert it into a byte array
            byte[] userStringBytes = hexStringToByteArray(userString);

            //Encrypt it with the session key
            byte[] userStringEnc = encAESsessionCipher.doFinal(userStringBytes);
            
            //Send it to the server
            outStream.write(userStringEnc);

            //Thread sleep
            Thread.sleep(1000);

            //Protocol Step 6
            //S -> C: {SecretValue}g^xy
            System.out.println("Receiving secret value from server...");
            byte[] message7ct = new byte[128];
            inStream.read(message7ct);
            System.out.println("Length of message7ct: "+message7ct.length);
            // byte[] message7body = decAESsessionCipher.doFinal(message7ct);
            //Convert the received data to hexString
            // String secretValue = byteArrayToHexString(message7body);
            String secretValue = byteArrayToHexString(message7ct);
            System.out.println("Received secret value from server.");        
            System.out.println(secretValue);
            myConnection.close();

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

    	// This method sets decAESsessioncipher & encAESsessioncipher 
	private static void calculateSessionKey(PrivateKey y, PublicKey gToTheX)  {
	    try {
		// Find g^xy
		KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DiffieHellman");
		serverKeyAgree.init(y);
		serverKeyAgree.doPhase(gToTheX, true);
		byte[] secretDH = serverKeyAgree.generateSecret();
		 System.out.println("g^xy: "+byteArrayToHexString(secretDH));
		//Use first 16 bytes of g^xy to make an AES key
		byte[] aesSecret = new byte[16];
		System.arraycopy(secretDH,0,aesSecret,0,16);
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
	}

    @SuppressWarnings("unused")
	public static void generateDHprams() throws NoSuchAlgorithmException, InvalidParameterSpecException {
	    AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");   
	    paramGen.init(1024);   
	    //Generate the parameters   
	    AlgorithmParameters params = paramGen.generateParameters();   
	    DHParameterSpec dhSpec = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);   
	    System.out.println("These are some good values to use for p & g with Diffie Hellman");
	    System.out.println("p: "+dhSpec.getP());
	    System.out.println("g: "+dhSpec.getG());
	    
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