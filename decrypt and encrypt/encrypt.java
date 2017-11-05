import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;

public class encrypt {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java encrypt <padded plaintext>");
            return;
        }
        File file = new File(args[0]);
        byte[] plaintext = new byte[(int) file.length()];
        if (plaintext.length < 16 || plaintext.length % 16 != 0) {
            System.out.println("Plaintext length must be a positive multiple of 16 bytes");
            System.out.println("Instead, got " + plaintext.length);
            return;
        }
        try (FileInputStream fileInputStream = new FileInputStream(file);) {

            fileInputStream.read(plaintext);
            ArrayList<byte[]> encryptedMsg = CryptoOperation.encrypt(plaintext);

            for (byte[] arr : encryptedMsg) {
                System.out.write(arr);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

