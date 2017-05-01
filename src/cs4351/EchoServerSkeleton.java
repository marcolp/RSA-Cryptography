package cs4351;

import org.jetbrains.annotations.Nullable;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

public class EchoServerSkeleton {
    // This code includes socket code originally written
    // by Dr. Yoonsik Cheon at least 10 years ago.
    // This version used for Computer Security, Spring 2017.
    // Modified by Marco Lopez for Computer Security Spring 2017
    public static void main(String[] args) {

        String host = "172.19.154.68";
        BufferedReader in; // for reading strings from socket
        PrintWriter out;   // for writing strings to socket
        ObjectInputStream objectInput;   // for reading objects from socket
        ObjectOutputStream objectOutput; // for writing objects to socket
        Cipher cipheRSA, cipherEnc;
        byte[] clientRandomBytes;
        byte[] serverRandomBytes;
        PublicKey[] pkpair;
        Socket socket;
        // Handshake
        try {
            // socket initialization
            ServerSocket connections = new ServerSocket(8008);
            socket = connections.accept();
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));

            // Receive hello from client
            String firstMessage = in.readLine();
            if (!firstMessage.equals("hello")) {
                System.out.println("Wrong first message");
                return;
            }

        } catch (IOException e) {
            System.out.println("socket initialization error");
            System.out.println(e);
            return;
        }


        String serverEncryptionPublicKey = "";

        try {
            // read and send certificate to client
            File file = new File("MarcoLopezServerCertificate.txt");
            Scanner input = new Scanner(file);
            String line;

            boolean readingKey = false;
            boolean readEncryptionKey = false;

            line = input.nextLine();

            while (input.hasNextLine()) {
                out.println(line);

                if ("-----BEGIN PUBLIC KEY-----".equals(line)) {
                    readingKey = true;
                    line = input.nextLine();
                    continue;
                } else if ("-----END PUBLIC KEY-----".equals(line)) {
                    readingKey = false;
                    readEncryptionKey = true;
                    line = input.nextLine();
                    continue;
                }

                if (readingKey) {
                    if (!readEncryptionKey)
                        serverEncryptionPublicKey += line;
                }

                line = input.nextLine();
            }
            out.println(line);
            out.flush();
        } catch (FileNotFoundException e) {
            System.out.println("certificate file not found");
            return;
        }


        String clientCertificatePublicEncryptionKey = "";
        String clientCertificatePublicSignatureKey = "";
        String clientSignature = "";
        String contents = "";

        // Receive Server certificate
        // Will need to verify the certificate and extract the Server public keys
        try {
            String line = in.readLine();

            //This variable determines whether or not a public key is being read.
            boolean publicKey = false;
            //This variable determines whether or not we have read the first public key already.
            boolean readFirstKey = false;

            boolean readSignature = false;
//			contents += line+"\r\n";
            while (!"-----END SIGNATURE-----".equals(line)) {

//				contents += line+ "\r\n";
                if(!line.equals("-----END SIGNATURE-----") && !line.equals("-----BEGIN SIGNATURE-----") && !readSignature)
                    contents += line + "\r\n";

                if ("-----BEGIN PUBLIC KEY-----".equals(line)) {
                    publicKey = true;
//					contents += line + "\r\n";
//					line = in.readLine();
//					continue;
                } else if ("-----END PUBLIC KEY-----".equals(line)) {

                    publicKey = false;
                    readFirstKey = true;
//					contents += line+ "\r\n";
//					line = in.readLine();
//					continue;
                } else if ("-----BEGIN SIGNATURE-----".equals(line)) {
                    readSignature = true;
//					line = in.readLine();
//					continue;
                }

                else if (publicKey) {
                    //If we haven't finished reading the first key, continue adding it to the first key string
                    if (!readFirstKey)
                        clientCertificatePublicEncryptionKey += line;

                        //Otherwise add it to the second key string
                    else
                        clientCertificatePublicSignatureKey += line;
                }
                else if (readSignature) {
                    clientSignature += line;
                }

                line = in.readLine();

            }

            verifyCertificate(contents, clientSignature);

            readSignature = false;
        } catch (IOException e) {
            System.out.println("problem reading the certificate from server");
            return;
        }


        try {
            // initialize object streams
            objectOutput = new ObjectOutputStream(socket.getOutputStream());
            objectInput = new ObjectInputStream(socket.getInputStream());


            //==============================Create server random bytes==============================
            serverRandomBytes = new byte[8];
            new Random().nextBytes(serverRandomBytes);

            //Encrypt the random bytes
            Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            //Use the client's public encryption key to encrypt
            PublicKey clientPrivateEncryptKey = makePublicKeyFromString(clientCertificatePublicEncryptionKey);
            encryptCipher.init(Cipher.ENCRYPT_MODE, clientPrivateEncryptKey);
            byte[] serverRandomBytesEncrypted = encryptCipher.doFinal(serverRandomBytes);

            // send encrypted random bytes to client
            objectOutput.writeObject(serverRandomBytesEncrypted);

            //Hash the random bytes
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(serverRandomBytes);
            byte[] hashedBytes;
            hashedBytes = md.digest();

            //Sign the hashed bytes
            byte[] serverHashedSignedRandomBytes = signBytes(hashedBytes);

            //Send the hashed signed random bytes to the client
            objectOutput.writeObject(serverHashedSignedRandomBytes);



            //==============================Receive the client's encrypted random bytes==============================
            byte[] clientRandomEncryptedBytes = (byte[]) objectInput.readObject();

            //Decrypt the random bytes
            Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            //Use the server's private encryption key to decrypt
            PrivateKey serverPrivateEncryptKey = PemUtils.readPrivateKey("MarcoLopezServerEncryptPrivate.pem");
            decryptCipher.init(Cipher.DECRYPT_MODE, serverPrivateEncryptKey);
            clientRandomBytes = decryptCipher.doFinal(clientRandomEncryptedBytes);

            //Receive the client's hashed signed bytes
            byte[] clientHashedSignedBytes = (byte[]) objectInput.readObject();


            //Hash the random bytes
            md.update(clientRandomBytes);
            byte[] clientHashedBytes;
            clientHashedBytes = md.digest();


            PublicKey serverPublicSignKey = makePublicKeyFromString(clientCertificatePublicSignatureKey);

            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(serverPublicSignKey);                    //Public key generated from certificate
            sig.update(clientHashedBytes);                                //Message to verify signature for
            if (sig.verify(clientHashedSignedBytes)) {
                System.out.println("Client signature verification succeeded");
            } else {
                System.out.println("Client signature verification failed");
            }

        } catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | SignatureException ex) {
            System.out.println("Problem with receiving random bytes from server");
            System.err.println(ex);
            ex.printStackTrace();
            return;
        }



        // initialize the shared secret with all zeroes
        // will need to generate from a combination of the server and
        // the client random bytes generated
        byte[] sharedSecret = new byte[16];
        System.arraycopy(serverRandomBytes, 0, sharedSecret, 0, 8);
        System.arraycopy(clientRandomBytes, 0, sharedSecret, 8, 8);
        SecretKey secretKey;
        try {
            //=======================================Encrypting cipher=======================================
            // we will use AES encryption, CBC chaining and PCS5 block padding
            cipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // generate an AES key derived from randomBytes array
            secretKey = new SecretKeySpec(sharedSecret, "AES");
            cipherEnc.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] serverIV = cipherEnc.getIV();
            objectOutput.writeObject(serverIV);

        } catch (IOException | NoSuchAlgorithmException
                | NoSuchPaddingException | InvalidKeyException e) {
            System.out.println("error setting up the AES encryption");
            return;
        }
        try {
            // Encrypted communication
            System.out.println("Starting messages to the server. Type messages, type BYE to end");
            Scanner userInput = new Scanner(System.in);


            //=======================================Decrypting cipher=======================================
            // we will use AES encryption, CBC chaining and PCS5 block padding
            Cipher decryptingCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            //We should receive the client's IV
            byte[] clientIV = (byte[]) objectInput.readObject();

            // initialize with a specific vector instead of a random one
            decryptingCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(clientIV) );


            boolean done = false;
            while (!done) {
                // Read message from the client
                byte[] clientMsg = (byte[]) objectInput.readObject();
                // Decrypt the message
                String decriptedMessage = new String(decryptingCipher.doFinal(clientMsg));
                System.out.println("This is what the server decrypted: " + decriptedMessage);

                // If user says "BYE", end session
                if (decriptedMessage.trim().equals("BYE")) {
                    System.out.println("client session ended");
                    done = true;
                } else {
                    // Create echo message
                    String echoMessage = "Echo: "+decriptedMessage;

                    //Encrypt echo message
                    byte[] encryptedEcho = cipherEnc.doFinal(echoMessage.getBytes());

                    // Send the encrypted echo to the client
                    objectOutput.writeObject(encryptedEcho);
                }
            }
        } catch (IllegalBlockSizeException | BadPaddingException
                | IOException | ClassNotFoundException e) {
            System.out.println("error in encrypted communication with server");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    /**
     * @param key
     * @return
     */
    @Nullable
    private static PublicKey makePublicKeyFromString(String key) {
        byte[] byteKey = Base64.getDecoder().decode(key);
        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("RSA");
            PublicKey publicKey = kf.generatePublic(X509publicKey);
            return publicKey;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * @param key
     * @return
     */
    @Nullable
    private static PrivateKey makePrivateKeyFromString(String key) {
        byte[] byteKey = Base64.getDecoder().decode(key);
        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(X509publicKey);
            return privateKey;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Uses the client's private signature key to sign a byte message
     *
     * @param message - to be signed
     * @return - signed byte array
     */
    @Nullable
    private static byte[] signBytes(byte[] message) {
        Signature sig;
        byte[] signedMessage;
        try {
            sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(PemUtils.readPrivateKey("MarcoLopezServerSignPrivate.pem"));
            sig.update(message);
            signedMessage = sig.sign();
            return signedMessage;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static void verifyCertificate(String certificateContents, String certificateSignature) {
        PublicKey pubKey;
        Signature sig;

        // get the public key of the signer from file
        // Read public key from file
        pubKey = PemUtils.readPublicKey("CApublicKey.pem");
        if (pubKey == null)
            return;

        // verify the signature
        try {
            // print the actual string that was signed (for verification)
//			System.out.println(certificateContents);
            // verify the signature
            sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(pubKey);
            sig.update(certificateContents.getBytes());
            // output the result of the verification
            // System.out.println("Signature:"+signature);
            if (sig.verify(Base64.getDecoder().decode(certificateSignature))) {
                System.out.println("Client certificate signature verification succeeded");
            } else {
                System.out.println("Client certificate signature verification failed");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println("error occurred while trying to verify signature" + e);
        }
    }

}
