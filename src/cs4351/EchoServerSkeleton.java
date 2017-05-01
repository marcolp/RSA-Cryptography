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

        // Receive client certificate
        // Will need to verify the certificate and extract the Server public keys
        try {
            String line;

            //This variable determines whether or not a public key is being read.
            boolean publicKey = false;
            //This variable determines whether or not we have read the first public key already.
            boolean readFirstKey = false;

            boolean readSignature = false;
            line = in.readLine();

            while (!"-----END SIGNATURE-----".equals(line)) {

                if ("-----BEGIN PUBLIC KEY-----".equals(line)) {
                    publicKey = true;
                    line = in.readLine();
                    continue;
                } else if ("-----END PUBLIC KEY-----".equals(line)) {

                    publicKey = false;
                    readFirstKey = true;
                    line = in.readLine();
                    continue;
                } else if ("-----BEGIN SIGNATURE-----".equals(line)) {
                    readSignature = true;
                    line = in.readLine();
                    continue;
                }

                if (publicKey) {
                    //If we haven't finished reading the first key, continue adding it to the first key string
                    if (!readFirstKey)
                        clientCertificatePublicEncryptionKey += line;

                        //Otherwise add it to the second key string
                    else
                        clientCertificatePublicSignatureKey += line;
                } else if (readSignature) {
                    clientSignature += line;
                }
                line = in.readLine();

            }

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
            decryptCipher.init(Cipher.DECRYPT_MODE, clientPrivateEncryptKey);
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
            sig.update(hashedBytes);                                //Message to verify signature for
            if (sig.verify(clientHashedSignedBytes)) {
                System.out.println("Signature verification succeeded");
            } else {
                System.out.println("Signature verification failed");
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
            // we will use AES encryption, CBC chaining and PCS5 block padding
            cipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // generate an AES key derived from randomBytes array
            secretKey = new SecretKeySpec(sharedSecret, "AES");
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

            //We should be receiving the server's IV for its encrypting cipher
            byte[] serverIV = (byte[]) objectInput.readObject();

            // we will use AES encryption, CBC chaining and PCS5 block padding
            Cipher decryptingCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // initialize with a specific vector instead of a random one
            decryptingCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(serverIV));


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

                    String str = new String(decryptingCipher.doFinal(encryptedBytes));
                    System.out.println("This is what we decrypted: " + str);
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

}
