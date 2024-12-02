import javax.crypto.Cipher; // Importa la clase Cipher para realizar las operaciones de cifrado y descifrado.
import javax.crypto.SecretKey; // Importa SecretKey para manejar claves secretas de cifrado.
import javax.crypto.spec.ChaCha20ParameterSpec; // Importa ChaCha20ParameterSpec para los parámetros del algoritmo ChaCha20.
import java.security.SecureRandom; // Importa SecureRandom para generar números aleatorios seguros (en este caso, el nonce).
import java.util.Base64; // Importa Base64 para codificar y decodificar los datos en formato Base64.

public class Chacha20Encryption {
    // Longitud del nonce (número aleatorio único usado una sola vez) en bytes (12 bytes en este caso)
    private static final int NONCE_LENGTH = 12;

    // Método para cifrar datos utilizando el algoritmo ChaCha20
    public static String encrypt(String data, SecretKey key) throws Exception {
        // Crear un nonce aleatorio de 12 bytes (para garantizar que cada operación de cifrado sea única)
        byte[] nonce = new byte[NONCE_LENGTH];
        new SecureRandom().nextBytes(nonce); // Llenar el nonce con bytes aleatorios.

        // Crear un objeto Cipher para utilizar el algoritmo ChaCha20
        Cipher cipher = Cipher.getInstance("ChaCha20");
        // Inicializar el Cipher en modo de cifrado con la clave secreta y el nonce
        cipher.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));

        // Cifrar los datos (convertidos a bytes) utilizando el cipher
        byte[] encryptedData = cipher.doFinal(data.getBytes());

        // Crear un nuevo arreglo de bytes para almacenar tanto el nonce como los datos cifrados
        byte[] nonceAndData = new byte[nonce.length + encryptedData.length];

        // Copiar el nonce y los datos cifrados al nuevo arreglo
        System.arraycopy(nonce, 0, nonceAndData, 0, nonce.length);
        System.arraycopy(encryptedData, 0, nonceAndData, nonce.length, encryptedData.length);

        // Codificar los datos (nonce + datos cifrados) en Base64 y devolver como cadena
        return Base64.getEncoder().encodeToString(nonceAndData);
    }

    // Método para descifrar los datos cifrados en Base64 utilizando el algoritmo ChaCha20
    public static String decrypt(String encryptedData, SecretKey key) throws Exception {
        // Decodificar los datos cifrados (nonce + datos) desde Base64
        byte[] nonceAndData = Base64.getDecoder().decode(encryptedData);

        // Extraer el nonce (primeros 12 bytes) y los datos cifrados (resto del arreglo)
        byte[] nonce = new byte[NONCE_LENGTH];
        byte[] data = new byte[nonceAndData.length - NONCE_LENGTH];
        System.arraycopy(nonceAndData, 0, nonce, 0, nonce.length); // Copiar el nonce
        System.arraycopy(nonceAndData, nonce.length, data, 0, data.length); // Copiar los datos cifrados

        // Crear un objeto Cipher para utilizar el algoritmo ChaCha20
        Cipher cipher = Cipher.getInstance("ChaCha20");
        // Inicializar el Cipher en modo de descifrado con la clave secreta y el nonce
        cipher.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));

        // Descifrar los datos cifrados
        byte[] decryptedData = cipher.doFinal(data);

        // Convertir los datos descifrados a una cadena y devolverla
        return new String(decryptedData);
    }
}
