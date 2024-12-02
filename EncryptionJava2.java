import javax.swing.*; // Importa la librería para interfaces gráficas (JOptionPane, JFileChooser)
import java.io.*; // Importa clases para manejar archivos (File, FileWriter)
import java.security.PrivateKey; // Importa la clase para manejar claves privadas
import java.security.PublicKey; // Importa la clase para manejar claves públicas
import javax.crypto.SecretKey; // Importa la clase para manejar claves secretas (AES)

public class EncryptionJava2 {

    public static void main(String[] args) throws Exception {
        // Generar claves RSA
        GenerateKeys rsaKeys = new GenerateKeys(2048); // Crear un objeto para generar claves RSA de 2048 bits.
        rsaKeys.createKeys(); // Generar el par de claves RSA (pública y privada).
        PublicKey publicKey = rsaKeys.getPublicKey(); // Obtener la clave pública.
        PrivateKey privateKey = rsaKeys.getPrivateKey(); // Obtener la clave privada.

        // Generar una clave AES
        SecretKey aesKey = AESEncryption.generateAESKey(); // Crear una clave AES secreta para el cifrado de mensajes.

        // Menú de opciones para cifrar o descifrar
        String[] options = {"Cifrar Mensaje", "Descifrar Mensaje"}; // Opciones del menú de cifrado/descifrado.
        int choice = JOptionPane.showOptionDialog(null, "Seleccione una opción", "Opciones de Cifrado/Descifrado",
                JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, options, options[0]);

        // Dependiendo de la elección, se procede a cifrar o descifrar el mensaje
        if (choice == 0) {
            // Cifrado de mensaje
            encryptMessage(aesKey, publicKey); // Llamar a la función para cifrar el mensaje.
        } else if (choice == 1) {
            // Descifrado de mensaje
            decryptMessage(aesKey, privateKey); // Llamar a la función para descifrar el mensaje.
        } else {
            System.out.println("No se ha seleccionado ninguna opción."); // Mensaje si no se elige ninguna opción.
        }
    }

    // Método para cifrar un mensaje
    private static void encryptMessage(SecretKey aesKey, PublicKey publicKey) throws Exception {
        // Solicitar al usuario el mensaje a cifrar
        String message = JOptionPane.showInputDialog("Ingrese el mensaje a cifrar:");
        if (message == null || message.isEmpty()) { // Validar si se ingresó un mensaje
            System.out.println("No se ha ingresado un mensaje. Saliendo..."); // Mensaje de error si no hay mensaje.
            return;
        }

        // Cifrado usando AES-GCM (cifrado de flujo autenticado)
        String encryptedMessageAESGCM = AESEncryptionGCM.encrypt(message, aesKey); // Cifrar el mensaje con AES-GCM.
        // Cifrar la clave AES con RSA
        String encryptedAESKey = RSAEncryption.encryptAESKey(aesKey, publicKey); // Cifrar la clave AES con la clave pública RSA.

        // Combinar el mensaje cifrado y la clave AES cifrada en un solo String
        String combinedEncryptedData = encryptedMessageAESGCM + "\n" + encryptedAESKey;

        // Mostrar el mensaje cifrado y la clave AES cifrada
        JOptionPane.showMessageDialog(null, "Mensaje y clave cifrada:\n" + combinedEncryptedData);

        // Abrir un cuadro de diálogo para guardar el archivo cifrado
        JFileChooser fileChooser = new JFileChooser(); // Crear un cuadro de diálogo para seleccionar archivo.
        fileChooser.setDialogTitle("Guardar archivo cifrado"); // Título del cuadro de diálogo.
        int userSelection = fileChooser.showSaveDialog(null); // Mostrar cuadro de diálogo para guardar archivo.
        if (userSelection == JFileChooser.APPROVE_OPTION) { // Si el usuario aprueba la selección
            File encryptedFile = fileChooser.getSelectedFile(); // Obtener el archivo seleccionado.
            FileWriter writer = new FileWriter(encryptedFile); // Crear un escritor de archivo.
            writer.write(combinedEncryptedData); // Escribir los datos cifrados en el archivo.
            writer.close(); // Cerrar el escritor.
            JOptionPane.showMessageDialog(null, "Archivo cifrado guardado en: " + encryptedFile.getAbsolutePath()); // Confirmar guardado.
        }
    }

    // Método para descifrar un mensaje
    private static void decryptMessage(SecretKey aesKey, PrivateKey privateKey) throws Exception {
        // Solicitar al usuario el mensaje cifrado y la clave AES cifrada
        String encryptedMessage = JOptionPane.showInputDialog("Ingrese el mensaje cifrado:");
        String encryptedAESKey = JOptionPane.showInputDialog("Ingrese la clave AES cifrada:");

        // Validar que se haya ingresado el mensaje cifrado
        if (encryptedMessage == null || encryptedMessage.isEmpty()) {
            System.out.println("No se ha ingresado un mensaje cifrado."); // Mensaje de error si no se ingresó el mensaje.
            return;
        }
        // Validar que se haya ingresado la clave AES cifrada
        if (encryptedAESKey == null || encryptedAESKey.isEmpty()) {
            System.out.println("No se ha ingresado la clave AES cifrada."); // Mensaje de error si no se ingresó la clave.
            return;
        }

        // Descifrar la clave AES usando RSA
        SecretKey decryptedAESKey = RSAEncryption.decryptAESKey(encryptedAESKey, privateKey); // Usar la clave privada para descifrar la clave AES.
        
        // Descifrar el mensaje usando la clave AES descifrada
        String decryptedMessage = AESEncryptionGCM.decrypt(encryptedMessage, decryptedAESKey); // Descifrar el mensaje.

        // Mostrar el mensaje descifrado al usuario
        JOptionPane.showMessageDialog(null, "Mensaje Descifrado: " + decryptedMessage);
    }
}
