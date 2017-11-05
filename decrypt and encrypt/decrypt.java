import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

public class decrypt {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java decrypt <ciphertext>");
            return;
        }
        File file = new File(args[0]);
        byte[] ciphertext = new byte[(int) file.length()];
        if (ciphertext.length < 32 || ciphertext.length % 16 != 0) {
            System.out.println("Ciphertext length must be at least 32 bytes, and multiples of 16");
            System.out.println("Instead, got " + ciphertext.length);
            return;
        }
        try (FileInputStream fileInputStream = new FileInputStream(file);) {

            fileInputStream.read(ciphertext);
            ArrayList<byte[]> decryptedMsgs = CryptoOperation.decrypt(ciphertext);
            for (byte[] arr : decryptedMsgs) {
                System.out.print(new String(arr, "UTF-8"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}


class CryptoOperation {

    public static final int BLOCK_SIZE = 16;
    static Oracle oracle = new Oracle();

    private static byte decryptLastByte(byte[] yn) throws IOException {
        assert (yn.length == BLOCK_SIZE);

        //first, generate random block with 15 random blocks
        byte[] r = new byte[BLOCK_SIZE];
        new Random().nextBytes(r);

        //set final byte i = 0
        r[15] = 0;

        //ask oracle if (r|yN) is valid. if not, i++, and ask until oracle says yes
        while (!oracle.isValid(Util.concat(r, yn))) {
            r[15]++;
            //System.out.println(r[15]);
            assert (r[15] != 0);
        }

        //replace r1 with any byte, and repeat above. then repeat for r2...r15
        for (int rk = 0; rk < 15; rk++) {
            r[rk] = (byte) new Random().nextInt();
            if (!oracle.isValid(Util.concat(r, yn))) {
                //if no, when we replaced rk, set D(y_N)_16=i\oplus (17-k)
                //return D(y_N)_16 \oplus y_{N-1, 16}
                return (byte) (r[15] ^ (17 - (rk + 1)));
            }
        }
        //the final byte of x_N is x_{N, 16}=D(y_N)_16\oplus y_{N-1, 16}
        return (byte) (r[15] ^ 1);
    }

    private static byte[] decryptBlock(byte[] yn) throws IOException {
        assert (yn.length == BLOCK_SIZE);

        byte[] r = new byte[BLOCK_SIZE];
        new Random().nextBytes(r);

        byte[] d = new byte[BLOCK_SIZE];
        d[15] = decryptLastByte(yn);

        for (int k = 14; k >= 0; k--) {
            for (int j = 15; j > k; j--) {
                //XOR (17-k) from the 'D' entries
                r[j] = (byte) (d[j] ^ (17 - (k + 1)));
            }

            r[k] = 0; //init i to 0

            while (!oracle.isValid(Util.concat(r, yn))) {
                r[k]++;
                //System.out.println(r[k]);
                assert (r[k] != 0);
            }
            d[k] = (byte) (r[k] ^ (17 - (k + 1)));
            //NB: the ACTUAL decrypted value is d[k] XOR'd with y_(n-1, 16)
        }
        assert (d.length == BLOCK_SIZE);
        return d;
    }

    public static ArrayList<byte[]> decrypt(byte[] iv, byte[] file) throws IOException {
        ArrayList<byte[]> msg = new ArrayList<byte[]>();

        byte[] d_yn, y_prev;
        y_prev = iv;

        while (file.length > 0) {
            d_yn = decryptBlock(Util.sub(file, 0, BLOCK_SIZE));
            msg.add(Util.xor(d_yn, y_prev));

            y_prev = Util.sub(file, 0, BLOCK_SIZE);
            file = Util.sub(file, BLOCK_SIZE, file.length);
        }

        return msg;
    }

    public static ArrayList<byte[]> decrypt(byte[] file) throws IOException {
        return decrypt(
                Util.sub(file, 0, BLOCK_SIZE),
                Util.sub(file, BLOCK_SIZE, file.length));
    }

    public static ArrayList<byte[]> encrypt(byte[] plaintext) throws IOException {
        //https://crypto.stackexchange.com/questions/40312/padding-oracle-attack-encrypting-your-own-message/
        ArrayList<byte[]> ans = new ArrayList<byte[]>();
        ArrayList<byte[]> pt = Util.parseByteArrayIntoBlocks(plaintext);

        //first generate a random block
        byte[] rand = new byte[BLOCK_SIZE];
        new Random().nextBytes(rand);
        ans.add(rand);

        byte[] c_i = rand; //ciphertext block i
        byte[] decryptedBlock;

        for (int i = plaintext.length / BLOCK_SIZE - 1; i >= 0; i--) {
            decryptedBlock = CryptoOperation.decryptBlock(c_i);
            c_i = Util.xor(decryptedBlock, pt.get(i));
            ans.add(0, c_i);
        }

        return ans;
    }
}

class Oracle {
    private static String ORACLE_TEMP_INPUT = "oracle_temp_input";
    static File temp = new File(ORACLE_TEMP_INPUT);

    static {
        temp.deleteOnExit();
    }

    public boolean isValid(byte[] arr) throws IOException {
        assert (arr.length >= 32 && arr.length % 16 == 0);

        try (OutputStream fos = new FileOutputStream(temp)) {
            fos.write(arr);
        }

        Process p = new ProcessBuilder("./oracle", ORACLE_TEMP_INPUT).start();

        BufferedReader br = new BufferedReader(new InputStreamReader(
                p.getInputStream()));
        String result = br.readLine();

        return result.equals("1");
    }
}

class Util {
    public static byte[] concat(byte[] a, byte[] b) {
        int length = a.length + b.length;
        byte[] result = new byte[length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    public static byte[] sub(byte[] a, int start, int end) {
        return Arrays.copyOfRange(a, start, end);
    }

    public static byte[] xor(byte[] a, byte[] b) {
        assert (a.length == b.length);
        byte[] ans = new byte[a.length];

        for (int k = 0; k < a.length; k++) {
            ans[k] = (byte) (a[k] ^ b[k]);
        }
        return ans;
    }

    public static ArrayList<byte[]> parseByteArrayIntoBlocks(byte[] arr) {
        assert (arr.length % CryptoOperation.BLOCK_SIZE == 0);
        ArrayList<byte[]> ans = new ArrayList<byte[]>();
        for (int k = 0; k < arr.length / CryptoOperation.BLOCK_SIZE; k++) {
            ans.add(Util.sub(arr, k * CryptoOperation.BLOCK_SIZE,
                    (k + 1) * CryptoOperation.BLOCK_SIZE));
        }
        return ans;
    }
}
