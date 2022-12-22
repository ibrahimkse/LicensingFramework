import java.util.Base64;
import java.util.Base64.Encoder;
import javax.crypto.Cipher;
import java.io.BufferedReader;
import java.io.File;  // Import the File class
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;


public class Client {


    public static String get_MAC(){
        String macAddress = "";
        try {
            InetAddress localHost = InetAddress.getLocalHost();
            NetworkInterface ni = NetworkInterface.getByInetAddress(localHost);
            byte[] hardwareAddress = ni.getHardwareAddress();
            String[] hexadecimal = new String[hardwareAddress.length];
            for (int i = 0; i < hardwareAddress.length; i++) {
                hexadecimal[i] = String.format("%02X", hardwareAddress[i]);
            }
            macAddress = String.join(":", hexadecimal);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return macAddress;
    }

    public static String get_SerialNumber(){
        String serialNumber = "";
        try {
            for (FileStore store: FileSystems.getDefault().getFileStores()) {
                serialNumber = store.getAttribute("volume:vsn").toString();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return serialNumber;
    }

    public static String get_MotherBoardSerialNumber(){
        String command = "wmic baseboard get serialnumber";
        String serialNumber = "";
        try {
            Process SerialNumberProcess = Runtime.getRuntime().exec(command);
            InputStreamReader ISR = new InputStreamReader(SerialNumberProcess.getInputStream());
            BufferedReader br = new BufferedReader(ISR);
            br.readLine();
            br.readLine();
            serialNumber = br.readLine().trim();
            SerialNumberProcess.waitFor();
            br.close();

        } catch (Exception e) {
            e.printStackTrace();
        }

        return serialNumber;
    }

    public static String get_Plain(){
        String username = "sulo";
        String serialID = "1234-5678-9012";
        String mac = get_MAC();
        String serial = get_SerialNumber();
        String mString = get_MotherBoardSerialNumber();
        String plainString = username +"$" + serialID +"$" + mac +"$" + serial + "$" +mString;


        System.out.println("My MAC: " + mac);
        System.out.println("My Disk ID: " + serial);
        System.out.println("My Motherboard ID: " + mString);
        return plainString;
    }

    public static PublicKey get_PublicKey(String filename) throws Exception {
        
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static String get_EncryptedString(String plainString) throws Exception {
        String encryptedString = "";
        try {
            PublicKey publicKey = get_PublicKey("public.key");
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(plainString.getBytes(StandardCharsets.UTF_8));
            Encoder encoder = Base64.getEncoder();
            encryptedString = encoder.encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("Client -- Encrypted License Text: "+encryptedString);
        return encryptedString;
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

    public static boolean VerifySignature(byte[] signature,String hash){
        boolean bool = false;
        try {
            PublicKey publicKey = get_PublicKey("public.key");
            Signature sign = Signature.getInstance("SHA256withRSA");
            byte[] hashBytes = hash.getBytes(StandardCharsets.UTF_8);
            sign.initVerify(publicKey);
            sign.update(hashBytes);
            bool = sign.verify(signature);
        } catch (Exception e) {
        }
        return  bool;
    }

    public static boolean LicenseExists(){
        try {
            File myObj = new File("license.txt");
            if (myObj.exists()) {
                return true;
            } 
        } catch (Exception e) {
            e.printStackTrace();
        } 
        System.out.println("Client -- License file is not found.");
        return false;
    }

    public static boolean LicenseCorrupted(String plainString,String hash){
        try {
            Path path = Paths.get("license.txt");
            byte[] data = Files.readAllBytes(path);

            return !VerifySignature(data,hash);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public static void GenerateNewLicenseFile(String plainString,String hash){
        String encryptedString = "";
        try {
            encryptedString = get_EncryptedString(plainString);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("Client -- MD5 License Text: "+hash);
        byte[] digitalCertificate =  LicenseManager.create_DigitalCertificate(encryptedString);
        if(VerifySignature(digitalCertificate,hash)){
            // create file and write digital certificate
            try {
                File myObj = new File("license.txt");
                if(myObj.exists()){
                    myObj.delete();
                }else{
                    System.out.println("Client -- License is not found.");
                }
                
                if (myObj.createNewFile()) {
                    try (FileOutputStream outputStream = new FileOutputStream(myObj)) {
                        outputStream.write(digitalCertificate);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            } 
        }else{
            System.out.println("License Not Verified");
        }  
        System.out.println("Client -- Succeed. The license file content is secured and signed by the server.");
    }

    public static void main(String[] args) {
        System.out.println("Client started...");
        String plainString = get_Plain();
        String hash = MD5(plainString);
        LicenseManager.Connect();

        if(LicenseExists()){
            System.out.println("Client -- Raw License Text: "+plainString);
            
            if(LicenseCorrupted(plainString,hash)){
                System.out.println("Client -- The license file has been broken!!");
                GenerateNewLicenseFile(plainString,hash);
            }
            else{
                System.out.println("Client -- MD5 License Text: "+hash);
                System.out.println("Client -- Succeed. The license is correct.");
            }
        }
        else{
            System.out.println("Client -- Raw License Text: "+plainString);
            GenerateNewLicenseFile(plainString,hash);
        } 
    }
}