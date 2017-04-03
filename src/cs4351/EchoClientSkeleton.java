package cs4351;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class EchoClientSkeleton {
    // This code includes socket code originally written 
    // by Dr. Yoonsik Cheon at least 10 years ago.
    // This version used for Computer Security, Spring 2017.    
	// Modified by Marco Lopez for Computer Security Spring 2017
    public static void main(String[] args) {

        String host = "172.19.152.11";
        BufferedReader in; // for reading strings from socket
        PrintWriter out;   // for writing strings to socket
        ObjectInputStream objectInput;   // for reading objects from socket        
        ObjectOutputStream objectOutput; // for writing objects to socket
        Cipher cipheRSA, cipherEnc;
        byte[] clientRandomBytes;
        PublicKey[] pkpair;
        Socket socket;
        // Handshake
        try {
            // socket initialization
            socket = new Socket(host, 8008);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
        } catch (IOException e) {
            System.out.println("socket initialization error");
            System.out.println(e);
            return;
        }
        // Send hello to server
        out.println("hello");
        out.flush();
        
        String serverCertificatePublicEncryptionKey = "";
        String serverCertificatePublicSignatureKey = "";
        String serverSignature = "";
        
        // Receive Server certificate
        // Will need to verify the certificate and extract the Server public keys
        try {
            String line = in.readLine();
            
            //This variable determines whether or not a public key is being read.
            boolean publicKey = false;
            //This variable determines whether or not we have read the first public key already.
            boolean readFirstKey = false;
            
            boolean readSignature = false;
            
            while (!"-----END SIGNATURE-----".equals(line)) {
            	line = in.readLine();
            	
            	if("-----BEGIN PUBLIC KEY-----".equals(line)){
            		publicKey = true;
            		continue;
            	}
                
            	else if("-----END PUBLIC KEY-----".equals(line)){
            		publicKey = false;
            		readFirstKey = true;
            		continue;
            	}
            	
            	else if("-----BEGIN SIGNATURE-----".equals(line)){
            		readSignature = true;
            		continue;
            	}
            	
            	if(publicKey){
            		//If we haven't finished reading the first key, continue adding it to the first key string
            		if(!readFirstKey) 
            			serverCertificatePublicEncryptionKey += line;
            		
            		//Otherwise add it to the second key string
            		else 
            			serverCertificatePublicSignatureKey += line;
            	}
            	
            	else if(readSignature){
            		serverSignature += line;
            	}
            }
            
            readSignature = false;
        } catch (IOException e) {
            System.out.println("problem reading the certificate from server");
            return;
        }

        String clientEncryptionPublicKey = "";

        try {   
            // read and send certificate to server
            File file = new File("MarcoLopezClientCertificate.txt");
            Scanner input = new Scanner(file);
            String line;
            
            boolean readingKey = false;
            boolean readEncryptionKey = false;
            
            while (input.hasNextLine()) {
                line = input.nextLine();
                out.println(line);
               
                if("-----BEGIN PUBLIC KEY-----".equals(line)){
                	readingKey = true;
                }
                
                else if("-----END PUBLIC KEY-----".equals(line)){
                	readingKey = false;
                	readEncryptionKey = true;
                	
                }
                
                else if(readingKey){
                	if(!readEncryptionKey)
                		clientEncryptionPublicKey += line;
                }
            }
            out.flush();
        } catch (FileNotFoundException e){
            System.out.println("certificate file not found");
            return;
        }
        
        
        try {
        	
            // initialize object streams
            objectOutput = new ObjectOutputStream(socket.getOutputStream());
            objectInput = new ObjectInputStream(socket.getInputStream());
            // receive encrypted random bytes from server
            byte[] encryptedBytes = (byte[]) objectInput.readObject();
            
            //Decrypt the random bytes
            Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            //Use the client's private encryption key to decrypt
            PrivateKey privKey = PemUtils.readPrivateKey("MarcoLopezClientEncryptPrivate.pem");
            decryptCipher.init(Cipher.DECRYPT_MODE, privKey);
            
            byte[] decryptedRandomBytes = decryptCipher.doFinal(encryptedBytes); 
            
            // receive signature of hash of random bytes from server
            byte[] signatureBytes = (byte[]) objectInput.readObject();
            
            try {
                Signature sig = Signature.getInstance("SHA1withRSA");
                PublicKey pubKey = PemUtils.readPublicKey("MarcoLopezClientSignPublic.pem");
                
                sig.initVerify(pubKey);
                sig.update(decryptedRandomBytes);
                if (sig.verify(Base64.getDecoder().decode(serverSignature))) {
                    System.out.println("Signature verification succeeded");
                } else {
                    System.out.println("Signature verification failed");
                }
            } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                System.out.println("problem verifying signature: " + e);
            }
            // will need to verify the signature and decrypt the random bytes
            
            
        } catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) { 
            System.out.println("Problem with receiving random bytes from server");
            System.err.println(ex);
            return;
        }
        // generate random bytes for shared secret
        clientRandomBytes = new byte[8];
        // the next line would initialize the byte array to random values
        // new Random().nextBytes(clientRandomBytes);
        // here we leave all bytes to zeroes.
        // The server shifts to testing mode when receiving all byte 
        // values zeroes and uses all zeroes as shared secret
        try {
            // you need to encrypt and send the the random byte array
            // here, precalculated encrypted bytes using zeroes as shared secret
            byte[] encryptedBytes = {-101, 122, -50, -56, 68, -30, -48, 115, 
                -52, 116, -40, 43, 121, 77, -44, -89, -10, -35, 38, -45, -64, 
                52, 109, 72, -107, 57, 58, -16, 56, -101, -93, 51, 106, -7, 40, 
                72, -56, 85, -82, -110, -17, -64, 70, 57, 12, 111, -62, 117, 28, 
                48, -78, -84, 80, -69, 86, -14, 120, -99, -96, -69, -13, -49, 
                -92, -19, 1, 81, -57, 29, -5, -19, 125, 7, 13, -128, 62, 7, -6, 
                66, 77, -124, 127, -95, -76, -85, -80, -13, -113, 91, 53, 59, 
                19, 86, -1, -14, 23, 2, 127, 76, -24, -117, 76, -108, 11, -78, 
                -64, -94, -51, 13, -9, -44, -96, -23, -55, 22, -79, -23, -36, 
                42, -60, -55, -2, -52, -52, 39, -94, 53, 81, 58};
            objectOutput.writeObject(encryptedBytes);
            // you need to generate a signature of the hash of the random bytes
            // here, precalculated signature using the client secret key associated with the certificate
            byte[] signatureBytes = {48, 17, -50, -3, 125, -10, -88, -6, -33, 
                10, 14, 93, 112, 14, 74, -32, -27, -56, -86, 91, -101, 87, 117, 
                109, 41, 1, 6, -4, -94, 47, 83, -46, 44, 76, 61, 83, 72, 36, 
                -127, -44, 5, -77, 121, 19, 107, 91, -123, 31, 123, -22, 114, 
                -79, 103, 39, 122, -122, 73, -99, -16, 22, 20, 37, 27, 14, 31, 
                11, 36, 12, -118, 38, 120, 47, 57, -110, -27, -14, 31, -37, 85, 
                -56, -108, 100, -71, 29, 26, 26, 8, -47, 49, -66, 88, 6, 73, 
                124, -35, 9, 16, 59, 44, -113, 62, -61, -31, 58, -116, 113, 35, 
                119, 5, -117, -91, -109, -8, 123, -40, -105, -96, -71, -50, 41, 
                78, -113, -32, -75, 36, -29, 89, -51};
            objectOutput.writeObject(signatureBytes);
        } catch (IOException e) {
            System.out.println("error computing or sending the signature for random bytes");
            return;
        }
        // initialize the shared secret with all zeroes
        // will need to generate from a combination of the server and 
        // the client random bytes generated
        byte[] sharedSecret = new byte[16];
        //System.arraycopy(serverRandomBytes, 0, sharedSecret, 0, 8);
        //System.arraycopy(clientRandomBytes, 8, sharedSecret, 8, 8);
        try {
            // we will use AES encryption, CBC chaining and PCS5 block padding
            cipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");            
            // generate an AES key derived from randomBytes array
            SecretKeySpec secretKey = new SecretKeySpec(sharedSecret, "AES");
            cipherEnc.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] iv = cipherEnc.getIV();
            objectOutput.writeObject(iv);
        } catch (IOException | NoSuchAlgorithmException 
                | NoSuchPaddingException | InvalidKeyException e) {
            System.out.println("error setting up the AES encryption");
            return;
        }
        try {
            // Encrypted communication
            System.out.println("Starting messages to the server. Type messages, type BYE to end");    
            Scanner userInput = new Scanner(System.in);
            boolean done = false;
            while (!done) {
                // Read message from the user
                String userStr = userInput.nextLine();
                // Encrypt the message
                byte[] encryptedBytes = cipherEnc.doFinal(userStr.getBytes());
                // Send encrypted message as an object to the server
                objectOutput.writeObject(encryptedBytes);
                // If user says "BYE", end session
                if (userStr.trim().equals("BYE")) {
                    System.out.println("client session ended");
                    done = true;
                } else {
                    // Wait for reply from server,
                    encryptedBytes = (byte[]) objectInput.readObject();
                    // will need to decrypt and print the reply to the screen
                    System.out.println("Encrypted echo received, but not decrypted");
                }
            }            
        } catch (IllegalBlockSizeException | BadPaddingException 
                | IOException | ClassNotFoundException e) {
            System.out.println("error in encrypted communication with server");
        }
    }
}
