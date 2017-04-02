package cs4351;
import java.io.*;
import java.security.*;
import java.util.*;

class VerifyCert {

    public static void main(String[] args) {
        // This program reads a certificate file named certificate.txt
        // and the certificate authority's public key file CApublicKey.pem,
        // parses the certificate for formatting,
        // and uses the public key to verify the signature.
        // The program uses PemUtils.java.
        // Written by Luc Longpre for Computer Security, Spring 2017

        File file;
        PublicKey pubKey;
        String contents;
        String signature;
        Signature sig;
        Scanner reader = new Scanner(System.in);

        // get the public key of the signer from file
        // Read public key from file
        pubKey = PemUtils.readPublicKey("CApublicKey.pem");
        if (pubKey==null)
            return;

        // get the certificate and signature
        try {
        	System.out.println("Enter the file name of the certificate to test and press enter.");
        	String fileName = reader.nextLine();
        	
            file = new File(fileName);
            Scanner input = new Scanner(file);
            String line = input.nextLine();
            if (!"-----BEGIN INFORMATION-----".equals(line)) {
                System.out.println("expecting:-----BEGIN INFORMATION-----");
                System.out.println("got:" + line);
                return;
            }
            contents = line+"\r\n";
            line = input.nextLine();
            while (!"-----END PUBLIC KEY-----".equals(line)) {
                contents += line + "\r\n";
                line = input.nextLine();
            }
            contents += line + "\r\n";
            line = input.nextLine();
            while (!"-----END PUBLIC KEY-----".equals(line)) {
                contents += line + "\r\n";
                line = input.nextLine();
            }
            contents += line + "\r\n";
            line = input.nextLine();
            if (!"-----BEGIN SIGNATURE-----".equals(line)) {
                System.out.println("expecting:-----BEGIN SIGNATURE-----");
                System.out.println("got:" + line);
                return;
            }
            signature = input.nextLine();
            line = input.nextLine();
            if (!"-----END SIGNATURE-----".equals(line)) {
                System.out.println("expecting:-----END SIGNATURE-----");
                System.out.println("got:" + line);
                return;
            }
        } catch (NoSuchElementException e) {
            System.out.println("Unexpectedly reached the end of file, "+e);
            return;
        } catch (FileNotFoundException e) {
            System.out.println("Problem reading the certificate, "+e);
            return;
        } 
        
        // verify the signature
        try {
            // print the actual string that was signed (for verification)
            System.out.println(contents);
            // verify the signature
            sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(pubKey);
            sig.update(contents.getBytes());
            // output the result of the verification
            // System.out.println("Signature:"+signature);
            if (sig.verify(Base64.getDecoder().decode(signature))) {
                System.out.println("Signature verification succeeded");
            } else {
                System.out.println("Signature verification failed");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println("error occurred while trying to verify signature"+e);
        }
    }
}
