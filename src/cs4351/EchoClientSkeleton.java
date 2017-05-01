package cs4351;

import org.jetbrains.annotations.Nullable;

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

        String UTEPhost = "172.19.154.68";
        String localhost = "127.0.0.1";
        String myHost = "192.168.1.68";
        String caroHost = "129.108.148.86";
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
            socket = new Socket(caroHost, 8008);
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
            line = in.readLine();
            contents += line;
            while (!"-----END SIGNATURE-----".equals(line)) {

                if ("-----BEGIN PUBLIC KEY-----".equals(line)) {
                    publicKey = true;
                    line = in.readLine();
                    contents += line;
                    continue;
                } else if ("-----END PUBLIC KEY-----".equals(line)) {

                    publicKey = false;
                    readFirstKey = true;
                    line = in.readLine();
                    contents += line;
                    continue;
                } else if ("-----BEGIN SIGNATURE-----".equals(line)) {
                    readSignature = true;
                    line = in.readLine();
                    contents += line;
                    continue;
                }

                if (publicKey) {
                    //If we haven't finished reading the first key, continue adding it to the first key string
                    if (!readFirstKey)
                        serverCertificatePublicEncryptionKey += line;

                        //Otherwise add it to the second key string
                    else
                        serverCertificatePublicSignatureKey += line;
                } else if (readSignature) {
                    serverSignature += line;
                }

                line = in.readLine();
                contents += line;
            }

            verifyCertificate(contents, serverSignature);

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
                        clientEncryptionPublicKey += line;
                }

                line = input.nextLine();
            }
            out.println(line);
            out.flush();
        } catch (FileNotFoundException e) {
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
            PrivateKey clientPrivateEncryptKey = PemUtils.readPrivateKey("MarcoLopezClientEncryptPrivate.pem");
            decryptCipher.init(Cipher.DECRYPT_MODE, clientPrivateEncryptKey);
            serverRandomBytes = decryptCipher.doFinal(encryptedBytes);


            // receive signature of hash of random bytes from server
            byte[] signedBytes = (byte[]) objectInput.readObject();

            //Hash the random bytes
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(serverRandomBytes);
            byte[] hashedBytes;
            hashedBytes = md.digest();


            PublicKey serverPublicSignKey = makePublicKeyFromString(serverCertificatePublicSignatureKey);

            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(serverPublicSignKey);                    //Public key generated from certificate
            sig.update(hashedBytes);                                //Message to verify signature for
            if (sig.verify(signedBytes)) {
                System.out.println("Random Bytes signature verification succeeded");
            } else {
                System.out.println("Random Bytes signature verification failed");
            }

        } catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | SignatureException ex) {
            System.out.println("Problem with receiving random bytes from server");
            System.err.println(ex);
            ex.printStackTrace();
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


            //Create 8 random bytes to send to the server
            new Random().nextBytes(clientRandomBytes);


            //Encrypt the random bytes
            Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            //Use the server's public encryption key to encrypt
            PublicKey clientPrivateEncryptKey = makePublicKeyFromString(serverCertificatePublicEncryptionKey);
            encryptCipher.init(Cipher.ENCRYPT_MODE, clientPrivateEncryptKey);
            byte[] clientRandomBytesEncrypted = encryptCipher.doFinal(clientRandomBytes);


            // you need to encrypt and send the the random byte array
            // here, precalculated encrypted bytes using zeroes as shared secret
//            byte[] encryptedBytes = {-101, 122, -50, -56, 68, -30, -48, 115,
//                    -52, 116, -40, 43, 121, 77, -44, -89, -10, -35, 38, -45, -64,
//                    52, 109, 72, -107, 57, 58, -16, 56, -101, -93, 51, 106, -7, 40,
//                    72, -56, 85, -82, -110, -17, -64, 70, 57, 12, 111, -62, 117, 28,
//                    48, -78, -84, 80, -69, 86, -14, 120, -99, -96, -69, -13, -49,
//                    -92, -19, 1, 81, -57, 29, -5, -19, 125, 7, 13, -128, 62, 7, -6,
//                    66, 77, -124, 127, -95, -76, -85, -80, -13, -113, 91, 53, 59,
//                    19, 86, -1, -14, 23, 2, 127, 76, -24, -117, 76, -108, 11, -78,
//                    -64, -94, -51, 13, -9, -44, -96, -23, -55, 22, -79, -23, -36,
//                    42, -60, -55, -2, -52, -52, 39, -94, 53, 81, 58};

            //Send the client's encrypted random bytes
            objectOutput.writeObject(clientRandomBytesEncrypted);
            // you need to generate a signature of the hash of the random bytes
            // here, precalculated signature using the client secret key associated with the certificate

            //Hash the random bytes
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(clientRandomBytes);
            byte[] hashedClientBytes;
            hashedClientBytes = md.digest();

            //Sign the hashed random bytes
            byte[] clientSignedHashedBytes = signBytes(hashedClientBytes);

//            byte[] signatureBytes = {48, 17, -50, -3, 125, -10, -88, -6, -33,
//                    10, 14, 93, 112, 14, 74, -32, -27, -56, -86, 91, -101, 87, 117,
//                    109, 41, 1, 6, -4, -94, 47, 83, -46, 44, 76, 61, 83, 72, 36,
//                    -127, -44, 5, -77, 121, 19, 107, 91, -123, 31, 123, -22, 114,
//                    -79, 103, 39, 122, -122, 73, -99, -16, 22, 20, 37, 27, 14, 31,
//                    11, 36, 12, -118, 38, 120, 47, 57, -110, -27, -14, 31, -37, 85,
//                    -56, -108, 100, -71, 29, 26, 26, 8, -47, 49, -66, 88, 6, 73,
//                    124, -35, 9, 16, 59, 44, -113, 62, -61, -31, 58, -116, 113, 35,
//                    119, 5, -117, -91, -109, -8, 123, -40, -105, -96, -71, -50, 41,
//                    78, -113, -32, -75, 36, -29, 89, -51};
            objectOutput.writeObject(clientSignedHashedBytes);
        } catch (IOException e) {
            System.out.println("error computing or sending the signature for random bytes");
            return;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
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
                    System.out.println("This is what the client decrypted: " + str);
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
        Signature sig = null;
        byte[] signedMessage;
        try {
            sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(PemUtils.readPrivateKey("MarcoLopezClientSignPrivate.pem"));
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

    //Method modified from VerifyCert.java provided by Dr.Longpre
    public static boolean verifyCertificate(ArrayList<String> certificate) {
        System.out.println("VERIFYING Client...\n");
        int i = 0;
        PublicKey pubKey;
        String contents;
        String encryptionPK = "";
        String signaturePK = "";
        String signature;
        Signature sig;
        pubKey = PemUtils.readPublicKey("CApublicKey.pem");
        if (pubKey == null)
            return false;
        try {
            String line = certificate.get(i++);
            if (!"-----BEGIN INFORMATION-----".equals(line)) {
                System.out.println("expecting:-----BEGIN INFORMATION-----");
                System.out.println("got:" + line);
                return false;
            }
            contents = line + "\r\n";
            line = certificate.get(i++);
            while (!"-----END INFORMATION-----".equals(line)) {
                contents += line + "\r\n";
                line = certificate.get(i++);
            }
            contents += line + "\r\n";
            line = certificate.get(i++);
            while (!"-----END PUBLIC KEY-----".equals(line)) {
                contents += line + "\r\n";
                if (!"-----BEGIN PUBLIC KEY-----".equals(line)) {
                    encryptionPK += line;
                }
                line = certificate.get(i++);
            }
            contents += line + "\r\n";
            line = certificate.get(i++);
            while (!"-----END PUBLIC KEY-----".equals(line)) {
                contents += line + "\r\n";
                if (!"-----BEGIN PUBLIC KEY-----".equals(line)) {
                    signaturePK += line;
                }
                line = certificate.get(i++);
            }
            contents += line + "\r\n";
            line = certificate.get(i++);
            if (!"-----BEGIN SIGNATURE-----".equals(line)) {
                System.out.println("expecting:-----BEGIN SIGNATURE-----");
                System.out.println("got:" + line);
                return false;
            }
            signature = certificate.get(i++);
            line = certificate.get(i++);
            if (!"-----END SIGNATURE-----".equals(line)) {
                System.out.println("expecting:-----END SIGNATURE-----");
                System.out.println("got:" + line);
                return false;
            }
            return false;
        } catch (NoSuchElementException e) {
            System.out.println("Unexpectedly reached the end of file, " + e);
            return false;
        }
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
            System.out.println(certificateContents);
            // verify the signature
            sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(pubKey);
            sig.update(certificateContents.getBytes());
            // output the result of the verification
            // System.out.println("Signature:"+signature);
            if (sig.verify(Base64.getDecoder().decode(certificateSignature))) {
                System.out.println("Server certificate signature verification succeeded");
            } else {
                System.out.println("Server certificate signature verification failed");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println("error occurred while trying to verify signature" + e);
        }
    }
}
