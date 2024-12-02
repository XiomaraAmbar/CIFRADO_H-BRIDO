// Importa las clases necesarias para la encriptación RSA y AES
import javax.crypto.Cipher; // Clase que permite realizar operaciones de encriptación y desencriptación
import javax.crypto.SecretKey; // Clase para representar claves secretas utilizadas en criptografía simétrica
import javax.crypto.spec.SecretKeySpec; // Clase para especificar una clave secreta para el algoritmo AES
import java.security.PrivateKey; // Clase para representar claves privadas en criptografía asimétrica
import java.security.PublicKey; // Clase para representar claves públicas en criptografía asimétrica
import java.util.Base64; // Clase para codificar y decodificar datos en Base64

// Clase que implementa la encriptación y desencriptación de claves AES utilizando RSA
public class RSAEncryption {

    // Método para encriptar una clave AES utilizando una clave pública RSA
    public static String encryptAESKey(SecretKey aesKey, PublicKey publicKey) throws Exception {
        
        // Crea una instancia del cifrador RSA
        Cipher cipher = Cipher.getInstance("RSA");
        
        // Inicializa el cifrador en modo de encriptación utilizando la clave pública
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        
        // Realiza la encriptación de la clave AES
        byte[] encryptedKey = cipher.doFinal(aesKey.getEncoded());
        
        // Codifica la clave encriptada a formato Base64 para su transmisión segura como texto
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    // Método para desencriptar una clave AES utilizando una clave privada RSA
    public static SecretKey decryptAESKey(String encryptedKey, PrivateKey privateKey) throws Exception {
        
        // Crea una instancia del cifrador RSA
        Cipher cipher = Cipher.getInstance("RSA");
        
        // Inicializa el cifrador en modo de desencriptación utilizando la clave privada
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        
        // Decodifica el texto en Base64 a su representación en bytes
        byte[] decodedKey = Base64.getDecoder().decode(encryptedKey);
        
        // Realiza la desencriptación de la clave AES
        byte[] decryptedKey = cipher.doFinal(decodedKey);
        
        // Crea una nueva clave secreta a partir de la clave desencriptada
        return new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
    }
}
