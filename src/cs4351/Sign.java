package cs4351;
import java.io.*;
import java.security.*;
import java.util.Base64;

class Sign {

    public static void main(String[] args) {
        // Written by Luc Longpre for Computer Security, Spring 2017
        
        File file;
        PrivateKey privKey;
        Signature sig;
        String messageToSign = "Marco Lopez 4/1/2017 Testing signature";
        byte[] signature;
        
        System.out.println("Signing the message: \""+messageToSign+"\"");

        // Read private key from file
        privKey = PemUtils.readPrivateKey("MarcoLopezClientSignPrivate.pem");

        try {
            sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(privKey);
            sig.update(messageToSign.getBytes());
            signature = sig.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println("Error attempting to sign");
            return;
        }
        file = new File("signature.txt");
        try (PrintWriter output = new PrintWriter(file)) {
            output.print(Base64.getEncoder().encodeToString(signature));
        } catch (Exception e) {
            System.out.println("Could not create signature file");
        }
    }
}
