import java.security.KeyPair; // Importa la clase KeyPair para almacenar un par de claves (privada y pública).
import java.security.KeyPairGenerator; // Importa la clase KeyPairGenerator para generar un par de claves.
import java.security.PrivateKey; // Importa la clase PrivateKey para manejar claves privadas.
import java.security.PublicKey; // Importa la clase PublicKey para manejar claves públicas.

public class GenerateKeys {
    private KeyPairGenerator keyGen; // Objeto para generar el par de claves.
    private KeyPair pair; // Almacena el par de claves generado.
    private PrivateKey privateKey; // Almacena la clave privada.
    private PublicKey publicKey; // Almacena la clave pública.

    // Constructor que inicializa el generador de claves con un tamaño de clave especificado.
    // Recibe el tamaño de la clave (en bits) como parámetro.
    public GenerateKeys(int keylength) throws Exception {
        // Inicializa KeyPairGenerator para el algoritmo RSA.
        this.keyGen = KeyPairGenerator.getInstance("RSA");
        // Inicializa el generador con la longitud de clave proporcionada.
        this.keyGen.initialize(keylength);
    }

    // Método para generar el par de claves (pública y privada).
    public void createKeys() {
        // Genera el par de claves (pública y privada).
        this.pair = this.keyGen.generateKeyPair();
        // Asigna la clave privada al objeto privado.
        this.privateKey = pair.getPrivate();
        // Asigna la clave pública al objeto público.
        this.publicKey = pair.getPublic();
    }

    // Método para obtener la clave privada.
    public PrivateKey getPrivateKey() {
        return this.privateKey; // Devuelve la clave privada generada.
    }

    // Método para obtener la clave pública.
    public PublicKey getPublicKey() {
        return this.publicKey; // Devuelve la clave pública generada.
    }
}
