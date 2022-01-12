//package cs306lab3;

import java.security.Key; 
import java.security.SecureRandom; 

import javax.crypto.Cipher; 
import javax.crypto.KeyGenerator; 
import java.lang.Math;

//
// encrypt and decrypt using the DES private key algorithm

public class SymmetricSkeleton {

    /* See https://en.wikipedia.org/wiki/Data_Encryption_Standard */
    public static final int DES_KEY_SIZE = 56; 
    public static final int DES_BLOCK_SIZE = 64; 

    /**
     * Helper function; XOR two arrays of bytes. 
     * Stores the result in the first array.
     *  
     */
    public static void mapXOR (byte[] a, byte[] b) {
        int length = Math.min(a.length, b.length); 
        for (int i = 0; i < length; i++ ) {
            a[i] = (byte) ( a[i] ^ b[i] ); 
        }
    }
    
    /**
     * Helper function; determines the number of blocks needed
     * to represent byte array a. If a contains a number of
     * bytes that is not a multiple of the block size, 1 extra
     * block is added for padding.
     * 
     */
    public static int numBlocks(byte[] a){
        return (a.length % DES_BLOCK_SIZE == 0)? a.length / DES_BLOCK_SIZE : a.length / DES_BLOCK_SIZE +1;
    }

    /**
     * Run DES in ECB mode to simulate
     * encrypting/decrypting one block at a time.
     * 
     */
    public static byte[] customDES(boolean useDecryptMode, byte[] plainText, Key key) throws Exception {

        if (plainText.length != DES_BLOCK_SIZE) throw new Exception("Blocks must all be the same length"); 

        /* construct a cipher object using blockwise DES */
        Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding"); 

        /* If called in decrypt mode, set cipher to decrypt mode, otherwise use encrypt mode */
        if(useDecryptMode) cipher.init(Cipher.DECRYPT_MODE, key);
        else cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(plainText); 
    }

    /**
     * Implement DES encryption with CBC mode of operation. 
     */
    public static byte[] customDESCBCEncrypt(byte[] plainText, byte[] iv, Key key) throws Exception {

    	/**

        For the lab: implement this function. Use 
        
            https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29

        as a reference. Inside the function, you should have at least one call of the form

            bytes[] output = customDES(false, ..., key);

        Another helpful function might be System.arraycopy().
        
         */

        if (plainText.length != DES_BLOCK_SIZE) throw new Exception("Blocks must all be the same length");

        mapXOR(plainText, iv);

        byte[] copy = System.arraycopy(plainText);

        bytes[] output = customDES(false, copy, key);
        return output;
    }

    /**
     * Implement DES decryption with CBC mode of operation.
     */
    public static byte[] customDESCBCDecrypt(byte[] cipherText, byte[] iv, Key key) throws Exception {
        
    	/**

        For the lab: implement this function. Use 
        
            https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29

        as a reference. Inside the function, you should have at least one call of the form

            bytes[] output = customDES(false, ..., key);

        Another helpful function might be System.arraycopy().
        
         */

        if (plainText.length != DES_BLOCK_SIZE) throw new Exception("Blocks must all be the same length");

        mapXOR(plainText, iv);

        byte[] copy = System.arraycopy(plainText);

        bytes[] output = customDES(false, copy, key);
        return output;
    }

    /**
     * Main method. Initializes the IV and key, and provides a default message to test with.
     * 
     */
    public static void main (String[] args) throws Exception {

        /* Generate IV */
        SecureRandom rand = new SecureRandom(); 
        byte[] iv = new byte[DES_BLOCK_SIZE]; 
        rand.nextBytes(iv);

        /* Generate a key */
        KeyGenerator keyGen = KeyGenerator.getInstance("DES"); 
        keyGen.init(DES_KEY_SIZE);
        Key key = keyGen.generateKey(); 

        /* You can either supply your own string as an argument or use this default string */
        String message ="";
        if(args.length<1){
        	message = "Ave Maria! Jungfrau mild, Erhoere einer Jungfrau Flehen, Aus diesem Felsen starr und wild Soll mein Gebet zu dir hin wehen. "
                    + " Wir schlafen sicher bis zum Morgen, Ob Menschen noch so grausam sind. O Jungfrau, sieh der Jungfrau Sorgen, O Mutter, hoer "
                    + "ein bittend Kind! Ave Maria!";
        }else message = args[0];
        
        /* Print output */
        System.out.println("-- Encrypting the following message: --");
        System.out.println(message);
        byte[] encrypted = customDESCBCEncrypt(message.getBytes(), iv, key);
        System.out.println("\n-- Ciphertext (shouldn't be readable): --");
        System.out.println(new String(encrypted));
        byte[] decrypted = customDESCBCDecrypt(encrypted, iv, key);
        System.out.println("\n-- Result: --");
        System.out.println(new String(decrypted));
    }
}
