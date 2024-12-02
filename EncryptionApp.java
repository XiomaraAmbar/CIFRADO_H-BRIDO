import javax.swing.*;
import java.io.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

public class EncryptionApp {

    public static void main(String[] args) throws Exception {
        // Generación de claves RSA de 2048 bits
        GenerateKeys rsaKeys = new GenerateKeys(2048); // Se crea un objeto para generar las claves RSA de 2048 bits
        rsaKeys.createKeys(); // Llama al método para generar el par de claves RSA (pública y privada)
        PublicKey publicKey = rsaKeys.getPublicKey(); // Se obtiene la clave pública generada
        PrivateKey privateKey = rsaKeys.getPrivateKey(); // Se obtiene la clave privada generada

        // Generación de una clave secreta AES
        SecretKey aesKey = AESEncryption.generateAESKey(); // Se genera una clave AES que se utilizará para el cifrado

        // Crear una interfaz gráfica para seleccionar el tipo de cifrado
        String[] options = {"Cifrado AES simple", "Cifrado híbrido RSA + AES", "Cifrado con AES-GCM y ChaCha20"};
        // Se muestra un cuadro de diálogo con tres opciones de cifrado
        int choice = JOptionPane.showOptionDialog(null, 
                "Seleccione el tipo de cifrado:", 
                "Opciones de cifrado", 
                JOptionPane.DEFAULT_OPTION, 
                JOptionPane.INFORMATION_MESSAGE, 
                null, 
                options, 
                options[0]);

        // Dependiendo de la opción seleccionada, se ejecuta el cifrado correspondiente
        switch (choice) {
            case 0:
                aesSimpleEncryption(aesKey); // Llama a la función para cifrar con AES
                break;
            case 1:
                hybridEncryption(rsaKeys, publicKey, privateKey, aesKey); // Llama a la función para cifrar con RSA y AES
                break;
            case 2:
                aesGcmChaCha20Encryption(aesKey); // Llama a la función para cifrar con AES-GCM y ChaCha20
                break;
            default:
                System.out.println("No se ha seleccionado ninguna opción."); // En caso de que no se seleccione ninguna opción válida
        }
    }

    // Método para cifrar con AES de manera simple
    private static void aesSimpleEncryption(SecretKey aesKey) throws Exception {
        // Solicitar al usuario el mensaje a cifrar
        String message = JOptionPane.showInputDialog("Ingrese el mensaje a cifrar:");
        if (message == null || message.isEmpty()) {
            System.out.println("No se ha ingresado un mensaje. Saliendo..."); // Si no se ingresa mensaje, termina el proceso
            return;
        }

        // Cifrar el mensaje usando AES
        String encryptedMessage = AESEncryption.encrypt(message, aesKey);
        // Descifrar el mensaje para mostrarlo
        String decryptedMessage = AESEncryption.decrypt(encryptedMessage, aesKey);

        // Mostrar el mensaje original, cifrado y descifrado al usuario
        JOptionPane.showMessageDialog(null, 
            "Mensaje original: " + message + "\n" + 
            "Mensaje cifrado: " + encryptedMessage + "\n" + 
            "Mensaje descifrado: " + decryptedMessage,
            "Resultados de Cifrado",
            JOptionPane.INFORMATION_MESSAGE);

        // Preguntar al usuario si desea guardar el mensaje cifrado en un archivo
        int saveOption = JOptionPane.showConfirmDialog(null, 
            "¿Desea guardar el mensaje cifrado en un archivo?", 
            "Guardar mensaje cifrado", 
            JOptionPane.YES_NO_OPTION);

        // Si elige sí, se guarda el mensaje cifrado en un archivo
        if (saveOption == JOptionPane.YES_OPTION) {
            saveEncryptedMessageToFile(encryptedMessage);
        }
    }

    // Método para guardar el mensaje cifrado en un archivo
    private static void saveEncryptedMessageToFile(String encryptedMessage) {
        // Mostrar un selector de archivos para elegir dónde guardar el mensaje cifrado
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Guardar mensaje cifrado");
        int userSelection = fileChooser.showSaveDialog(null);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(fileToSave))) {
                writer.write(encryptedMessage); // Escribir el mensaje cifrado en el archivo
                JOptionPane.showMessageDialog(null, "Mensaje cifrado guardado con éxito.");
            } catch (IOException e) {
                JOptionPane.showMessageDialog(null, "Error al guardar el mensaje cifrado.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    // Método para cifrado híbrido (RSA + AES)
    private static void hybridEncryption(GenerateKeys rsaKeys, PublicKey publicKey, PrivateKey privateKey, SecretKey aesKey) throws Exception {
        // Solicitar al usuario el mensaje a cifrar
        String message = JOptionPane.showInputDialog("Ingrese el mensaje a cifrar:");
        if (message == null || message.isEmpty()) {
            System.out.println("No se ha ingresado un mensaje. Saliendo...");
            return;
        }

        // Cifrar el mensaje con AES
        String encryptedMessage = AESEncryption.encrypt(message, aesKey);

        // Cifrar la clave AES con la clave pública RSA
        String encryptedAESKey = RSAEncryption.encryptAESKey(aesKey, publicKey);

        // Descifrar la clave AES con la clave privada RSA
        SecretKey decryptedAESKey = RSAEncryption.decryptAESKey(encryptedAESKey, privateKey);

        // Descifrar el mensaje con la clave AES restaurada
        String decryptedMessage = AESEncryption.decrypt(encryptedMessage, decryptedAESKey);

        // Mostrar los resultados al usuario
        JOptionPane.showMessageDialog(null, 
            "Mensaje original: " + message + "\n" + 
            "Mensaje cifrado: " + encryptedMessage + "\n" + 
            "Mensaje descifrado: " + decryptedMessage,
            "Resultados de Cifrado Híbrido",
            JOptionPane.INFORMATION_MESSAGE);
    }

    // Método para cifrado con AES-GCM y ChaCha20
    private static void aesGcmChaCha20Encryption(SecretKey aesKey) throws Exception {
        // Solicitar al usuario el mensaje a cifrar
        String message = JOptionPane.showInputDialog("Ingrese el mensaje a cifrar:");
        if (message == null || message.isEmpty()) {
            System.out.println("No se ha ingresado un mensaje. Saliendo...");
            return;
        }

        // Cifrado usando AES-GCM
        String encryptedMessageAESGCM = AESEncryptionGCM.encrypt(message, aesKey);
        String decryptedMessageAESGCM = AESEncryptionGCM.decrypt(encryptedMessageAESGCM, aesKey);
        System.out.println("Cifrado AES-GCM: " + encryptedMessageAESGCM);
        System.out.println("Descifrado AES-GCM: " + decryptedMessageAESGCM);

        // Cifrado usando ChaCha20
        String encryptedMessageChaCha20 = Chacha20Encryption.encrypt(message, aesKey);
        String decryptedMessageChaCha20 = Chacha20Encryption.decrypt(encryptedMessageChaCha20, aesKey);
        System.out.println("Cifrado ChaCha20: " + encryptedMessageChaCha20);
        System.out.println("Descifrado ChaCha20: " + decryptedMessageChaCha20);
    }
}
