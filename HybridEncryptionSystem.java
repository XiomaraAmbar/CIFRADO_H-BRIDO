// `SecretKey` es la interfaz que representa una clave secreta utilizada en criptografía simétrica.
// `KeyGenerator` es la clase que se utiliza para generar claves secretas para algoritmos de cifrado como AES o DES.
import javax.crypto.SecretKey; // Interfaz para claves secretas.
import javax.crypto.KeyGenerator; // Clase para generar claves secretas.


public class HybridEncryptionSystem {
    public static void main(String[] args) throws Exception {
        
        // Generar una clave maestra utilizando el algoritmo AES
        // Esta clave se usará como base para derivar claves específicas para otros algoritmos.
        byte[] masterKey = KeyGenerator.getInstance("AES").generateKey().getEncoded();

        // Derivar una clave AES de 256 bits para el modo AES-GCM
        // Este es un algoritmo de cifrado simétrico que se utiliza para cifrar grandes cantidades de datos.
        SecretKey aesKey = KeyDerivation.deriveKey(masterKey, "AES-GCM", 256);

        // Derivar una clave ChaCha20 de 256 bits usando la clave maestra
        // ChaCha20 es un algoritmo de flujo adecuado para cifrar mensajes pequeños de manera eficiente.
        SecretKey chachaKey = KeyDerivation.deriveKey(masterKey, "ChaCha20", 256);

        // Cifrado y descifrado de un mensaje pequeño con ChaCha20
        // Se usa ChaCha20 porque es más eficiente para datos pequeños y permite un cifrado rápido.
        String smallMessage = "Hola, mensaje de prueba!"; // Mensaje de prueba
        String encryptedMessage = Chacha20Encryption.encrypt(smallMessage, chachaKey); // Cifrado del mensaje
        String decryptedMessage = Chacha20Encryption.decrypt(encryptedMessage, chachaKey); // Descifrado del mensaje

        // Mostrar el mensaje original, el mensaje cifrado y el mensaje descifrado
        System.out.println("Mensaje original: " + smallMessage);
        System.out.println("Mensaje cifrado: " + encryptedMessage);
        System.out.println("Mensaje descifrado: " + decryptedMessage);

        // Cifrado y descifrado de un documento grande con AES-GCM
        // AES-GCM es utilizado para datos más grandes debido a su seguridad y eficiencia.
        String largeData = "Este es un documento largo..."; // Datos grandes de prueba
        String encryptedLargeData = AESEncryptionGCM.encrypt(largeData, aesKey); // Cifrado del documento grande
        String decryptedLargeData = AESEncryptionGCM.decrypt(encryptedLargeData, aesKey); // Descifrado del documento

        // Mostrar el contenido original, el cifrado y el descifrado del documento grande
        System.out.println("Original documento grande: " + largeData);
        System.out.println("Documento grande cifrado: " + encryptedLargeData);
        System.out.println("Documento grande descifrado: " + decryptedLargeData);
    }
}
