// Importa las clases necesarias para manejar claves secretas y realizar el hash
import javax.crypto.SecretKey; // Clase para representar claves secretas utilizadas en criptografía simétrica
import javax.crypto.spec.SecretKeySpec; // Clase que permite especificar una clave secreta para el algoritmo AES
import java.security.MessageDigest; // Clase para calcular el hash utilizando algoritmos como SHA-256

// Clase que implementa la derivación de claves a partir de una clave maestra
public class KeyDerivation {
    
    // Método que deriva una clave a partir de una clave maestra utilizando SHA-256
    public static SecretKey deriveKey(byte[] masterKey, String purpose, int length) throws Exception {
        
        // Crea una instancia de MessageDigest utilizando el algoritmo SHA-256
        // SHA-256 es un algoritmo de hash que genera una cadena de 256 bits (32 bytes)
        MessageDigest sha = MessageDigest.getInstance("SHA-256");

        // Convierte el propósito (String) a un arreglo de bytes
        // El propósito es un parámetro que se utilizará junto con la clave maestra
        // para generar una clave derivada única para un propósito específico
        byte[] purposeBytes = purpose.getBytes();

        // Actualiza el objeto MessageDigest con los bytes de la clave maestra
        // Esta operación incluye la clave maestra en el cálculo del hash
        sha.update(masterKey);

        // Actualiza el objeto MessageDigest con los bytes del propósito
        // El propósito ayuda a personalizar la clave derivada para un uso específico
        sha.update(purposeBytes);

        // Calcula el hash final (digest) combinando la clave maestra y el propósito
        // El resultado es un arreglo de bytes que representa el hash derivado
        byte[] derivedKey = sha.digest();

        // Crea una nueva clave secreta (SecretKeySpec) a partir del hash derivado
        // El primer parámetro es el arreglo de bytes que contiene el hash calculado
        // El segundo parámetro (0) indica que comenzamos desde el primer byte del arreglo
        // El tercer parámetro (length / 8) establece la longitud de la clave derivada en bytes
        // El cuarto parámetro especifica el algoritmo que se utilizará, en este caso "AES"
        return new SecretKeySpec(derivedKey, 0, length / 8, "AES");
    }
}
