package cs4351;
import java.io.*;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class Verify {

    public static void main(String[] args) {
        // Written by Luc Longpre for Computer Security, Spring 2017        
        File file;
        PublicKey pubKey;
        String signature;
        String messageSigned = "Marco Lopez 4/1/2017 Testing signature";
        
        System.out.println("Verifying the signature of: \""+messageSigned+"\"");

        // Read public key from file
        pubKey = PemUtils.readPublicKey("MarcoLopezClientSignPublic.pem");

        // Read signature from file
        try {
            file = new File("signature.txt");
            Scanner input = new Scanner(file);
            signature = input.nextLine();
        } catch (FileNotFoundException ex) {
            System.out.println("Could not open signature file: " + ex);
            return;
        }

        try {
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(pubKey);
            sig.update(messageSigned.getBytes());
            if (sig.verify(Base64.getDecoder().decode(signature))) {
                System.out.println("Signature verification succeeded");
            } else {
                System.out.println("Signature verification failed");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println("problem verifying signature: " + e);
        }
    }
    
    public static boolean verifySignature(String message, String filename, String signature){
    	File file;
        PublicKey pubKey;
        String messageSigned = message;
        
        System.out.println("Verifying the signature of: \""+messageSigned+"\"");

        // Read public key from file
        pubKey = PemUtils.readPublicKey(filename);

        try {
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(pubKey);
            sig.update(messageSigned.getBytes());
            if (sig.verify(Base64.getDecoder().decode(signature))) {
                System.out.println("Signature verification succeeded");
                return true;
            } else {
                System.out.println("Signature verification failed");
                return false;
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println("problem verifying signature: " + e);
        }
        
        return false;
    }
}
