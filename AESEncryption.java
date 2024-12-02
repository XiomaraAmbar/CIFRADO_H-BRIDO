import javax.crypto.Cipher; // Importa la clase Cipher para realizar cifrado y descifrado.
import javax.crypto.KeyGenerator; // Importa KeyGenerator para generar claves secretas.
import javax.crypto.SecretKey; // Importa SecretKey para manejar claves secretas de cifrado.
import java.io.File; // Importa la clase File para manejar archivos.
import java.io.FileInputStream; // Importa FileInputStream para leer datos desde archivos.
import java.io.FileOutputStream; // Importa FileOutputStream para escribir datos en archivos.
import java.util.Base64; // Importa Base64 para codificar y decodificar datos en formato Base64.

public class AESEncryption {

    // Método para generar una clave secreta AES de 256 bits.
    public static SecretKey generateAESKey() throws Exception {
        // Se crea un generador de claves para el algoritmo AES.
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        // Se establece el tamaño de la clave en 256 bits.
        keyGen.init(256);
        // Se genera y retorna la clave secreta AES.
        return keyGen.generateKey();
    }

    // Método para cifrar una cadena de texto utilizando la clave AES.
    public static String encrypt(String data, SecretKey key) throws Exception {
        // Se obtiene el objeto Cipher para usar el algoritmo AES.
        Cipher cipher = Cipher.getInstance("AES");
        // Se inicializa el Cipher en modo de cifrado con la clave proporcionada.
        cipher.init(Cipher.ENCRYPT_MODE, key);
        // Se convierte la cadena de datos en bytes y se cifra.
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        // Se codifican los datos cifrados en Base64 y se retorna la cadena resultante.
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    // Método para descifrar datos cifrados en Base64 usando la clave AES.
    public static String decrypt(String encryptedData, SecretKey key) throws Exception {
        // Se obtiene el objeto Cipher para usar el algoritmo AES.
        Cipher cipher = Cipher.getInstance("AES");
        // Se inicializa el Cipher en modo de descifrado con la clave proporcionada.
        cipher.init(Cipher.DECRYPT_MODE, key);
        // Se decodifican los datos cifrados en Base64 a bytes.
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
        // Se descifra la información decodificada.
        byte[] decryptedData = cipher.doFinal(decodedData);
        // Se convierte los datos descifrados a una cadena y se retorna.
        return new String(decryptedData);
    }

    // Método para cifrar un archivo y escribir el resultado en un archivo de salida.
    public static void encryptFile(File inputFile, File outputFile, SecretKey key) throws Exception {
        // Se obtiene el objeto Cipher para usar el algoritmo AES.
        Cipher cipher = Cipher.getInstance("AES");
        // Se inicializa el Cipher en modo de cifrado con la clave proporcionada.
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // Se usan flujos de entrada y salida de archivos para leer y escribir datos.
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            // Se usa un búfer para leer bloques de datos del archivo de entrada.
            byte[] buffer = new byte[4096];
            int bytesRead;
            // Mientras haya datos para leer, se cifran y se escriben en el archivo de salida.
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    fos.write(output);
                }
            }
            // Se escribe cualquier dato restante del cifrado final.
            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                fos.write(outputBytes);
            }
        }
    }

    // Método para descifrar un archivo y escribir el resultado en un archivo de salida.
    public static void decryptFile(File inputFile, File outputFile, SecretKey key) throws Exception {
        // Se obtiene el objeto Cipher para usar el algoritmo AES.
        Cipher cipher = Cipher.getInstance("AES");
        // Se inicializa el Cipher en modo de descifrado con la clave proporcionada.
        cipher.init(Cipher.DECRYPT_MODE, key);

        // Se usan flujos de entrada y salida de archivos para leer y escribir datos.
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            // Se usa un búfer para leer bloques de datos del archivo de entrada.
            byte[] buffer = new byte[4096];
            int bytesRead;
            // Mientras haya datos para leer, se descifran y se escriben en el archivo de salida.
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    fos.write(output);
                }
            }
            // Se escribe cualquier dato restante del descifrado final.
            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                fos.write(outputBytes);
            }
        }
    }
}
