import javax.swing.*;
import java.io.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

public class HybridEncryptionGUI {

    public static void main(String[] args) throws Exception {
        // Generar claves RSA
        GenerateKeys rsaKeys = new GenerateKeys(2048); // Crear un objeto GenerateKeys con longitud de clave RSA de 2048 bits.
        rsaKeys.createKeys(); // Generar el par de claves RSA.
        PublicKey publicKey = rsaKeys.getPublicKey(); // Obtener la clave pública generada.
        PrivateKey privateKey = rsaKeys.getPrivateKey(); // Obtener la clave privada generada.

        // Generar una clave AES
        SecretKey aesKey = AESEncryption.generateAESKey(); // Generar una clave secreta AES.

        // Crear la interfaz gráfica para ingresar el mensaje
        String message = JOptionPane.showInputDialog("Ingrese el mensaje a cifrar:");
        if (message == null || message.isEmpty()) {
            System.out.println("No se ha ingresado un mensaje. Saliendo...");
            return;
        }

        // Cifrar el mensaje
        String encryptedMessage = AESEncryption.encrypt(message, aesKey); // Cifrar el mensaje usando la clave AES.
        String encryptedAESKey = RSAEncryption.encryptAESKey(aesKey, publicKey); // Cifrar la clave AES usando la clave pública RSA.

        // Descifrar el mensaje
        SecretKey decryptedAESKey = RSAEncryption.decryptAESKey(encryptedAESKey, privateKey); // Descifrar la clave AES usando la clave privada RSA.
        String decryptedMessage = AESEncryption.decrypt(encryptedMessage, decryptedAESKey); // Descifrar el mensaje usando la clave AES descifrada.

        // Mostrar los resultados
        System.out.println("Mensaje original: " + message); // Mostrar el mensaje original.
        System.out.println("Mensaje cifrado: " + encryptedMessage); // Mostrar el mensaje cifrado.
        System.out.println("Mensaje descifrado: " + decryptedMessage); // Mostrar el mensaje descifrado.

        // Crear una ventana para seleccionar el archivo a cifrar
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Seleccionar archivo a cifrar");
        int userSelection = fileChooser.showOpenDialog(null);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File inputFile = fileChooser.getSelectedFile(); // Obtener el archivo seleccionado por el usuario.
            File encryptedFile = new File("encrypted.dat"); // Especificar el archivo donde se almacenará el archivo cifrado.
            File decryptedFile = new File("decrypted.txt"); // Especificar el archivo donde se almacenará el archivo descifrado.

            // Cifrar el archivo usando la clave AES
            AESEncryption.encryptFile(inputFile, encryptedFile, aesKey);
            
            // Verificar si el archivo cifrado ha sido creado y si el tamaño del archivo ha cambiado
            if (encryptedFile.exists() && encryptedFile.length() > 0) {
                System.out.println("Archivo cifrado correctamente: " + encryptedFile.getAbsolutePath());
            } else {
                System.out.println("Error al cifrar el archivo.");
                return; // Terminar el proceso si el archivo no se ha cifrado correctamente.
            }

            // Descifrar el archivo usando la clave AES descifrada
            AESEncryption.decryptFile(encryptedFile, decryptedFile, decryptedAESKey);

            // Verificar si el archivo descifrado ha sido creado y su tamaño
            if (decryptedFile.exists() && decryptedFile.length() > 0) {
                System.out.println("Archivo descifrado correctamente: " + decryptedFile.getAbsolutePath());
            } else {
                System.out.println("Error al descifrar el archivo.");
                return; // Terminar el proceso si el archivo no se ha descifrado correctamente.
            }

            // Mostrar mensaje de finalización de la operación de cifrado y descifrado de archivos
            JOptionPane.showMessageDialog(null, "Archivo cifrado y descifrado de manera exitosa.");
        } else {
            JOptionPane.showMessageDialog(null, "No se seleccionó ningún archivo.");
        }
    }
}
