import java.util.ArrayList;
import java.util.Arrays;

public class Utils {
	static byte[] stringToByteArray(String s) {
		byte[] ans = new byte[s.length()];
		for (int k = 0; k < s.length(); k++) {
			ans[k] = (byte) s.charAt(k);
		}
		return ans;
	}
	 static boolean stringContainsItemFromList(String inputStr, String[] items) {
	    return Arrays.stream(items).parallel().anyMatch(inputStr::contains);
	}

	static ArrayList<byte[]> getCribDraggingTemplates(int length, String crib) {
		ArrayList<byte[]> ans = new ArrayList<byte[]>();

		for (int k = 0; k < length - crib.length() + 1; k++) {
			byte[] temp = new byte[length];
			int pos = 0;
			for (int left = 0; left < k; left++) {
				temp[pos++] = 0;
			}
			for (int c = 0; c < crib.length(); c++) {
				temp[pos++] = (byte) crib.charAt(c);
			}
			for (int right = length - crib.length() - k; right > 0; right--) {
				temp[pos++] = 0;
			}
			ans.add(temp);
		}
		return ans;
	}

	public static ArrayList<byte[]> getCroppedcaXORcb(
			int length, byte[] caXORcb) {
		ArrayList<byte[]> ans = new ArrayList<byte[]>();

		for (int k = 0; k < caXORcb.length + 1 - length; k++) {
			byte[] temp = new byte[length];
			for (int c = 0; c < length; c++) {
				temp[c] = (byte) caXORcb[k+c];
			}
			ans.add(temp);
		}
		return ans;
	}

	static String prettyXOR(byte[] a, byte[] b) throws Exception {

		return prettyPrint(xor(a, b));
	}

	static byte[] xor(byte[] a, byte[] b) throws Exception {
		if (a.length != b.length) {
			throw new Exception("mismatched length");
		}
		byte[] ans = new byte[a.length];
		for (int k = 0; k < a.length; k++) {
			ans[k] = (byte) (a[k] ^ b[k]);
		}
		return ans;
	}

	static String prettyPrint(byte[] arr) {
		String ans = "";
		for (int k = 0; k < arr.length; k++) {
			if (arr[k] < 32 || arr[k] > 126) {
				ans += "*";
			} else {
				ans += (char) arr[k];
			}
		}
		return ans;
	}

}
