import java.io.File; // Importa la clase File para trabajar con archivos.
import java.security.PrivateKey; // Importa la clase PrivateKey para trabajar con claves privadas en criptografía asimétrica.
import java.security.PublicKey; // Importa la clase PublicKey para trabajar con claves públicas en criptografía asimétrica.
import javax.crypto.SecretKey; // Importa la clase SecretKey para trabajar con claves secretas en criptografía simétrica.

public class HybridEncryption {
    public static void main(String[] args) throws Exception {
        // Generar claves RSA
        GenerateKeys rsaKeys = new GenerateKeys(2048); // Crear un objeto GenerateKeys con longitud de clave RSA de 2048 bits.
        rsaKeys.createKeys(); // Generar el par de claves RSA.
        PublicKey publicKey = rsaKeys.getPublicKey(); // Obtener la clave pública generada.
        PrivateKey privateKey = rsaKeys.getPrivateKey(); // Obtener la clave privada generada.

        // Generar una clave AES
        SecretKey aesKey = AESEncryption.generateAESKey(); // Generar una clave secreta AES.

        // Cifrar un mensaje
        String message = "Este es un mensaje secreto."; // Mensaje que se desea cifrar.
        String encryptedMessage = AESEncryption.encrypt(message, aesKey); // Cifrar el mensaje usando la clave AES.
        String encryptedAESKey = RSAEncryption.encryptAESKey(aesKey, publicKey); // Cifrar la clave AES usando la clave pública RSA.

        // Descifrar el mensaje
        SecretKey decryptedAESKey = RSAEncryption.decryptAESKey(encryptedAESKey, privateKey); // Descifrar la clave AES usando la clave privada RSA.
        String decryptedMessage = AESEncryption.decrypt(encryptedMessage, decryptedAESKey); // Descifrar el mensaje usando la clave AES descifrada.

        // Mostrar los resultados
        System.out.println("Mensaje original: " + message); // Mostrar el mensaje original.
        System.out.println("Mensaje cifrado: " + encryptedMessage); // Mostrar el mensaje cifrado.
        System.out.println("Mensaje descifrado: " + decryptedMessage); // Mostrar el mensaje descifrado.

        // Cifrar y descifrar un archivo
        File inputFile = new File("input.txt"); // Especificar el archivo de entrada a cifrar.
        File encryptedFile = new File("encrypted.dat"); // Especificar el archivo donde se almacenará el archivo cifrado.
        File decryptedFile = new File("decrypted.txt"); // Especificar el archivo donde se almacenará el archivo descifrado.

        AESEncryption.encryptFile(inputFile, encryptedFile, aesKey); // Cifrar el archivo usando la clave AES.
        AESEncryption.decryptFile(encryptedFile, decryptedFile, decryptedAESKey); // Descifrar el archivo usando la clave AES descifrada.

        // Mostrar mensaje de finalización de la operación de cifrado y descifrado de archivos.
        System.out.println("Archivo cifrado y descifrado de manera exitosa.");
    }
}


