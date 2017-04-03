package cs4351;

import java.io.*;
import java.net.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class CryptoMultiEchoServer {
    // This code originally was written from a piece of code written 
    // by Yoonsik Cheon at least 10 years ago.
    // It was rewritten several times by Luc Longpre over the years.
    // This version used for Computer Security, Spring 2017.    
    public static void main(String[] args) {

        System.out.println("CryptoMultiEchoServer started.");
        int sessionID = 0; // assign incremental session ids to each client connection

        try {
            ServerSocket s = new ServerSocket(8008);
            // The server runs until an error occurs
            // or is stopped externally
            for (;;) {
                Socket incoming = s.accept();
                // start a connection with the client
                // in a new thread and wait for another
                // connection
                new ClientHandler(incoming, ++sessionID).start();
                // start() causes the thread to begin execution
                // the JVM calls the run() method of this thread
            }
        } catch (Exception e) {
            System.out.println("Error: " + e);
        }
        System.out.println("MultiEchoServer stopped.");
    }

    private static class ClientHandler extends Thread {

        protected Socket incoming;
        protected int id;

        public ClientHandler(Socket incoming, int id) {
            this.incoming = incoming;
            this.id = id;
        }

        public void run() {
            try {
                // in and out for socket communication using strings
                BufferedReader in
                        = new BufferedReader(
                                new InputStreamReader(incoming.getInputStream()));
                PrintWriter out
                        = new PrintWriter(
                                new OutputStreamWriter(incoming.getOutputStream()));
                // send hello to client
                out.print("Hello! This is Java MultiEchoServer. ");
                out.println("Enter BYE to exit.");
                out.flush();

                // We could use Base64 encoding and communicate with strings using in and out
                // However, we show here how to send and receive serializable java objects                    
                ObjectInputStream objectInput = new ObjectInputStream(incoming.getInputStream());
                ObjectOutputStream objectOutput = new ObjectOutputStream(incoming.getOutputStream());
                
                
                // read the file of random bytes from which we can derive an AES key
                byte[] randomBytes;
                try {
                    FileInputStream fis = new FileInputStream("randomBytes");
                    randomBytes = new byte[fis.available()];
                } catch (Exception e) {
                    System.out.println("problem reading the randomBytes file");
                    return;
                }
                
                
                // get the initialization vector from the client
                // each client will have a different vector
                byte[] iv = (byte[]) objectInput.readObject();
                
                // we will use AES encryption, CBC chaining and PCS5 block padding
                Cipher decryptingCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                // generate an AES key derived from randomBytes array
                SecretKeySpec secretKey = new SecretKeySpec(randomBytes, "AES");
                // initialize with a specific vector instead of a random one
                decryptingCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

                
                Cipher encrpytingCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                encrpytingCipher.init(Cipher.ENCRYPT_MODE, secretKey);
                objectOutput.writeObject(encrpytingCipher.getIV());
                
//                SecretKeySpec encryptionKey = new SecretKeySpec(randomBytes, "AES");
//                if(encryptionKey == secretKey) System.out.println("==");
//                else if(encryptionKey.equals(secretKey)) System.out.println(".equals");
                
                // keep echoing the strings received until
                // receiving the string "BYE" which will break
                // out of the for loop and close the thread
                for (;;) {
                    // get the encrypted bytes from the client as an object
                    byte[] toDecryptBytes = (byte[]) objectInput.readObject();
                    // decrypt the bytes
                    String str = new String(decryptingCipher.doFinal(toDecryptBytes));
                    // reply to the client with an echo of the string
                    // this reply is not encrypted, you need to modify this
                    // by encrypting the reply
                    
                    
                    String echoStr = "Echo: " + str;
                    //Encrypt whatever we are going to send
                    byte[] enrtyptedBytes = encrpytingCipher.doFinal(echoStr.getBytes());
                    //Send the encrypted bytes to the client
                    objectOutput.writeObject(enrtyptedBytes);
                    
                    //NO LONGER NEEDED
//                    out.println("Echo: " + str);
//                    out.flush();
                    // print the message received from the client
                    
                    System.out.println("Received from session " + id + ": " + str);
                    if (str.trim().equals("BYE")) {
                        break;
                    }
                }
                System.out.println("Session " + id + " ended.");
                incoming.close();
            } catch (Exception e) {
                System.out.println("Error: " + e);
                e.printStackTrace();
            }
        }
    }
}
