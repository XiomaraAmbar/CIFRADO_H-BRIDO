import javax.crypto.Cipher; // Importa la clase Cipher para realizar cifrado y descifrado.
import javax.crypto.KeyGenerator; // Importa KeyGenerator para generar claves secretas.
import javax.crypto.SecretKey; // Importa SecretKey para manejar claves secretas de cifrado.
import javax.crypto.spec.GCMParameterSpec; // Importa GCMParameterSpec para parámetros de GCM (modo de operación).
import java.io.File; // Importa la clase File para manejar archivos.
import java.io.FileInputStream; // Importa FileInputStream para leer datos desde archivos.
import java.io.FileOutputStream; // Importa FileOutputStream para escribir datos en archivos.
import java.security.SecureRandom; // Importa SecureRandom para generar valores aleatorios seguros.
import java.util.Base64; // Importa Base64 para codificar y decodificar datos en formato Base64.

public class AESEncryptionGCM {
    // Definir constantes para la longitud del IV (vector de inicialización) y el TAG (etiqueta de autenticación) de GCM
    private static final int GCM_IV_LENGTH = 12; // Longitud del IV en GCM (12 bytes).
    private static final int GCM_TAG_LENGTH = 128; // Longitud del TAG en GCM (128 bits).

    // Método para cifrar una cadena de texto utilizando AES en modo GCM
    public static String encrypt(String data, SecretKey key) throws Exception {
        // Generar un IV (vector de inicialización) aleatorio
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv); // Llenar el IV con valores aleatorios.

        // Obtener un objeto Cipher para usar el algoritmo AES en modo GCM sin relleno
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // Inicializar el Cipher en modo cifrado con la clave secreta y los parámetros GCM (etiqueta y IV)
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

        // Cifrar los datos (convertidos a bytes) con el cipher
        byte[] encryptedData = cipher.doFinal(data.getBytes());

        // Crear un nuevo arreglo de bytes para almacenar tanto el IV como los datos cifrados
        byte[] ivAndData = new byte[iv.length + encryptedData.length];

        // Copiar el IV y los datos cifrados al nuevo arreglo
        System.arraycopy(iv, 0, ivAndData, 0, iv.length);
        System.arraycopy(encryptedData, 0, ivAndData, iv.length, encryptedData.length);

        // Codificar los datos (IV + datos cifrados) en Base64 y devolver como cadena
        return Base64.getEncoder().encodeToString(ivAndData);
    }

    // Método para descifrar los datos cifrados en Base64 utilizando AES en modo GCM
    public static String decrypt(String encryptedData, SecretKey key) throws Exception {
        // Decodificar los datos cifrados (IV + datos) desde Base64
        byte[] ivAndData = Base64.getDecoder().decode(encryptedData);

        // Extraer el IV (primeros 12 bytes) y los datos cifrados (resto del arreglo)
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] data = new byte[ivAndData.length - GCM_IV_LENGTH];
        System.arraycopy(ivAndData, 0, iv, 0, iv.length); // Copiar el IV
        System.arraycopy(ivAndData, iv.length, data, 0, data.length); // Copiar los datos cifrados

        // Obtener un objeto Cipher para usar el algoritmo AES en modo GCM sin relleno
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // Inicializar el Cipher en modo descifrado con la clave secreta y los parámetros GCM (etiqueta y IV)
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

        // Descifrar los datos cifrados
        byte[] decryptedData = cipher.doFinal(data);

        // Convertir los datos descifrados a una cadena y devolverla
        return new String(decryptedData);
    }
}
