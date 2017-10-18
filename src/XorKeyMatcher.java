
public class XorKeyMatcher {
	
	byte[] keyFragment;
	byte[] cryptogram;

	public XorKeyMatcher(byte[] keyFragment, byte[] cryptogram) {
		this.keyFragment = keyFragment;
		this.cryptogram = cryptogram;
	}
	
	// TODO
	public void decrypt() {
		for (int i = 0; i < cryptogram.length - keyFragment.length + 1; i++) {
			System.out.print(i + " ");
			for (int j = 0; j < keyFragment.length; j++) {
				System.out.print((char) (cryptogram[i+j] ^ keyFragment[j]));
			}
			System.out.println();
		}
	}

}
