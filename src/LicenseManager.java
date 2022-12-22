import java.util.Base64;
import javax.crypto.Cipher;
import java.util.Base64.Decoder;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;


public class LicenseManager {
    public static PublicKey get_PublicKey(String filename) throws Exception {
        
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        X509EncodedKeySpec spec =
        new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static PrivateKey get_PrivateKey(String filename) throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        PKCS8EncodedKeySpec spec =
        new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public static String get_DecryptedString(String encryptedString) throws Exception {
        PrivateKey privateKey = get_PrivateKey("private.key");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        Decoder decoder = Base64.getDecoder();
        byte[] encryptedBytes = decoder.decode(encryptedString);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);
        return decryptedString;
    }

    public static String MD5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(input.getBytes());
            BigInteger no = new BigInteger(1, messageDigest);
            String hashtext = no.toString(16);
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    
    private static byte[] signSHA256RSA(String input) throws Exception {
        PrivateKey privateKey = get_PrivateKey("private.key"); 
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(input.getBytes("UTF-8"));
        byte[] s = privateSignature.sign();
        return s;
    }

    public static byte[] create_DigitalCertificate(String encryptedText){
        System.out.println("Server -- Server is being requested...");
        byte[] digitalCertificate = new byte[0];
        try {
            System.out.println("Server -- Incoming Encrypted Text: "+encryptedText);
            String plainText = get_DecryptedString(encryptedText);
            System.out.println("Server -- Decrypted Text: "+plainText);
            String hash = MD5(plainText);
            System.out.println("Server -- MD5 Plain License Text: "+hash);
            digitalCertificate = signSHA256RSA(hash);
            Base64.Encoder encoder = Base64.getEncoder();
            String encoded = encoder.encodeToString(digitalCertificate);
            System.out.println("Server -- Digital Signature: "+encoded);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return digitalCertificate;
    }

    public static void Connect(){
        System.out.println("LicenseManager service started..." );
    }
}
