import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Scanner;

public class Runner {
	public static final String CIPHER_A = "resources/citext0";
	public static final String CIPHER_B = "resources/citext1";
	public static final int LENGTH = 400;

	public static final String[] BANNED_ITEMS = { "`", "|", "}", "{", "<", ">",
			"~", "]", "=", "+", "/", "\\", ";", "#", ":", "^", "'" };

	public static void main(String[] args) {

		try (FileInputStream cipherAInput = new FileInputStream(new File(
				CIPHER_A));
				FileInputStream cipherBInput = new FileInputStream(new File(
						CIPHER_B));

				Scanner input = new Scanner(System.in);) {
			byte cipherA[] = new byte[LENGTH];
			byte cipherB[] = new byte[LENGTH];

			cipherAInput.read(cipherA);
			cipherBInput.read(cipherB);

			// for (byte b : cipherA){
			// System.out.print(Utils.byteToChar(b));
			// }
			// String s = new String(fileContent);
			// System.out.println("File content: " + s);
			byte[] caXORcb = Utils.xor(cipherA, cipherB);

			while (true) {
				System.out.print("Enter a crib: ");
				String crib = input.nextLine();

				/********************* Show the entire crib drag result ******************/
				System.out.println("[" + crib + "]");
				ArrayList<byte[]> cribs = Utils.getCribDraggingTemplates(
						LENGTH, crib);

				for (int k = 0; k < cribs.size(); k++) {
					System.out.printf("%3d) ", k + 1);
					System.out.println(Utils.prettyXOR(cribs.get(k), caXORcb));
				}

				System.out.println();

				/************* only show the substring that was crib dragged ***************/
				ArrayList<byte[]> substringOfcaXORcb = Utils.getCroppedcaXORcb(
						crib.length(), caXORcb);
				for (int k = 0; k < substringOfcaXORcb.size(); k++) {
					String candidate = Utils.prettyXOR(
							Utils.stringToByteArray(crib),
							substringOfcaXORcb.get(k));
					if (!Utils.stringContainsItemFromList(candidate,
							BANNED_ITEMS)) {
						System.out.printf("%3d) ", k + 1);
						System.out.println(candidate);
					}
				}

			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
