import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Takes multiple stream cipher encrypted messages that use the same key and
 * tries to guess the key end decode the original messages.
 * 
 * @author Kacper
 *
 */
public class ManyTimePadDecryptor {

	// Character types
	private final static String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
	private final static String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	private final static String DIGITS = "0123456789";
	private final static String TYPOGRAPHIC_SPECIAL = "!\"',.:?-$%()";
	private final static String OTHER_SPECIAL = "#&*+;<=>@[\\]^_{|}~`";
	
	// Character weights
	private final static double WEIGHT_LETTER = 1.0;
	private final static double WEIGHT_DIGIT = 0.75;
	private final static double WEIGHT_SPACE = 1.2;
	private final static double WEIGHT_TYPOGRAPHIC = 0.8;
	private final static double WEIGHT_OTHER = 0.4;
	private final static double WEIGHT_INVALID = -1.0;
	
	private final static double[] LETTER_FREQUENCIES = {
			//abcdefghijklm
			9.90, 1.47, 4.36, 3.35, 8.77, 0.30, 1.42, 1.08, 8.21, 2.28, 3.51, 3.92, 2.80,
			//nopqrstuvwxyz
			5.72, 8.60, 3.13, 0.14, 4.69, 4.98, 3.98, 2.50, 0.04, 4.65, 0.02, 3.76, 6.53
	};
	
	private final static double FREQUENCY_WEIGHT_FACTOR = 0.01;
	private final static String PUNCTUATION = ".,!";
	
	private final static double[][] BIGRAM_FREQUENCIES = {
			{ 0.00, 0.12, 1.09, 0.57, 0.00, 0.03, 0.15, 0.02, 0.03, 0.42, 0.71, 0.59, 0.49, 1.10, 0.01, 0.14, 0.00,
					0.59, 0.57, 0.46, 0.15, 0.00, 0.64, 0.00, 0.00, 0.48 },
			{ 0.20, 0.00, 0.01, 0.00, 0.17, 0.00, 0.00, 0.01, 0.27, 0.01, 0.01, 0.08, 0.00, 0.04, 0.21, 0.00, 0.00,
					0.16, 0.02, 0.00, 0.07, 0.00, 0.00, 0.00, 0.45, 0.00 },
			{ 0.21, 0.00, 0.00, 0.00, 0.31, 0.00, 0.00, 1.24, 0.91, 0.25, 0.06, 0.00, 0.00, 0.03, 0.24, 0.00, 0.00,
					0.00, 0.00, 0.03, 0.04, 0.00, 0.00, 0.00, 0.25, 1.46 },
			{ 0.41, 0.02, 0.04, 0.02, 0.24, 0.00, 0.00, 0.00, 0.06, 0.01, 0.06, 0.13, 0.04, 0.31, 0.70, 0.04, 0.00,
					0.17, 0.04, 0.01, 0.15, 0.00, 0.06, 0.00, 0.27, 0.84 },
			{ 0.04, 0.16, 0.67, 0.62, 0.01, 0.02, 0.69, 0.00, 0.02, 0.71, 0.41, 0.37, 0.66, 0.75, 0.04, 0.15, 0.00,
					0.58, 0.73, 0.26, 0.03, 0.00, 0.18, 0.00, 0.00, 0.42 },
			{ 0.06, 0.00, 0.00, 0.00, 0.04, 0.00, 0.00, 0.00, 0.09, 0.00, 0.00, 0.01, 0.00, 0.00, 0.06, 0.00, 0.00,
					0.03, 0.00, 0.00, 0.02, 0.00, 0.00, 0.00, 0.00, 0.00 },
			{ 0.20, 0.00, 0.00, 0.09, 0.06, 0.00, 0.00, 0.00, 0.14, 0.00, 0.00, 0.07, 0.01, 0.05, 0.76, 0.00, 0.00,
					0.13, 0.00, 0.00, 0.05, 0.00, 0.01, 0.00, 0.00, 0.01 },
			{ 0.12, 0.00, 0.05, 0.01, 0.05, 0.00, 0.00, 0.00, 0.05, 0.00, 0.00, 0.00, 0.01, 0.03, 0.15, 0.00, 0.00,
					0.05, 0.00, 0.01, 0.03, 0.00, 0.04, 0.00, 0.02, 0.00 },
			{ 1.23, 0.02, 0.59, 0.11, 4.22, 0.01, 0.04, 0.00, 0.07, 0.04, 0.14, 0.18, 0.20, 0.38, 0.23, 0.02, 0.00,
					0.03, 0.33, 0.11, 0.11, 0.01, 0.19, 0.00, 0.00, 0.17 },
			{ 0.80, 0.01, 0.02, 0.02, 0.91, 0.00, 0.00, 0.00, 0.14, 0.00, 0.01, 0.01, 0.04, 0.07, 0.05, 0.01, 0.00,
					0.02, 0.11, 0.00, 0.09, 0.00, 0.02, 0.00, 0.00, 0.00 },
			{ 0.60, 0.01, 0.05, 0.00, 0.04, 0.00, 0.00, 0.00, 0.73, 0.00, 0.01, 0.04, 0.00, 0.03, 0.86, 0.00, 0.00,
					0.20, 0.13, 0.37, 0.24, 0.00, 0.04, 0.00, 0.00, 0.03 },
			{ 0.34, 0.04, 0.02, 0.01, 0.59, 0.00, 0.00, 0.00, 0.64, 0.00, 0.17, 0.02, 0.01, 0.25, 0.17, 0.00, 0.00,
					0.00, 0.04, 0.02, 0.17, 0.00, 0.02, 0.00, 0.00, 0.00 },
			{ 0.38, 0.02, 0.01, 0.00, 0.16, 0.00, 0.00, 0.00, 0.75, 0.00, 0.01, 0.00, 0.01, 0.12, 0.51, 0.04, 0.00,
					0.01, 0.02, 0.01, 0.23, 0.00, 0.00, 0.00, 0.23, 0.01 },
			{ 1.55, 0.00, 0.14, 0.06, 0.72, 0.01, 0.04, 0.00, 2.67, 0.00, 0.12, 0.00, 0.00, 0.13, 0.60, 0.01, 0.00,
					0.00, 0.16, 0.18, 0.05, 0.00, 0.01, 0.00, 0.61, 0.01 },
			{ 0.01, 0.49, 0.34, 0.78, 0.01, 0.04, 0.24, 0.01, 0.04, 0.21, 0.24, 0.35, 0.29, 0.68, 0.01, 0.22, 0.00,
					0.85, 1.00, 0.29, 0.01, 0.00, 1.50, 0.00, 0.00, 0.54 },
			{ 0.26, 0.00, 0.02, 0.00, 0.16, 0.00, 0.00, 0.00, 0.30, 0.00, 0.01, 0.05, 0.00, 0.04, 1.29, 0.00, 0.00,
					1.17, 0.03, 0.02, 0.11, 0.00, 0.00, 0.00, 0.04, 0.00 },
			{ 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00,
					0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00 },
			{ 1.11, 0.01, 0.10, 0.10, 0.45, 0.00, 0.04, 0.00, 0.09, 0.00, 0.03, 0.01, 0.06, 0.06, 1.01, 0.03, 0.00,
					0.01, 0.14, 0.11, 0.21, 0.00, 0.09, 0.00, 0.33, 1.30 },
			{ 0.27, 0.00, 0.61, 0.00, 0.11, 0.01, 0.00, 0.00, 0.82, 0.02, 0.38, 0.12, 0.09, 0.17, 0.25, 0.28, 0.00,
					0.04, 0.02, 1.43, 0.10, 0.00, 0.20, 0.00, 0.13, 0.89 },
			{ 0.96, 0.00, 0.01, 0.00, 0.76, 0.00, 0.00, 0.01, 0.04, 0.00, 0.15, 0.01, 0.01, 0.14, 0.96, 0.01, 0.00,
					0.40, 0.01, 0.01, 0.29, 0.00, 0.27, 0.00, 0.60, 0.01 },
			{ 0.03, 0.10, 0.20, 0.17, 0.01, 0.01, 0.07, 0.00, 0.01, 0.16, 0.14, 0.06, 0.14, 0.13, 0.00, 0.08, 0.00,
					0.15, 0.24, 0.22, 0.00, 0.00, 0.05, 0.00, 0.00, 0.18 },
			{ 0.00, 0.00, 0.00, 0.00, 0.01, 0.00, 0.00, 0.00, 0.01, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00,
					0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00 },
			{ 1.01, 0.00, 0.09, 0.05, 0.34, 0.00, 0.00, 0.00, 1.19, 0.00, 0.02, 0.01, 0.00, 0.25, 0.56, 0.03, 0.00,
					0.07, 0.30, 0.03, 0.02, 0.00, 0.01, 0.00, 0.64, 0.07 },
			{ 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.01, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00,
					0.00, 0.00, 0.00, 0.00, 0.01, 0.00, 0.00, 0.00, 0.00 },
			{ 0.00, 0.06, 0.80, 0.08, 0.00, 0.01, 0.04, 0.00, 0.00, 0.10, 0.16, 0.14, 0.51, 0.22, 0.01, 0.09, 0.00,
					0.04, 0.41, 0.20, 0.00, 0.00, 0.26, 0.00, 0.00, 0.11 },
			{ 1.26, 0.06, 0.17, 0.12, 1.86, 0.00, 0.06, 0.00, 0.62, 0.04, 0.12, 0.06, 0.12, 0.64, 0.31, 0.05, 0.00,
					0.06, 0.05, 0.06, 0.18, 0.00, 0.17, 0.00, 1.31, 0.00 }, };
	
	private final static double FREQUENCY_BIGRAM_WEIGHT_FACTOR = 0.12;
	
	private List<byte[]> cryptograms;
	private String[] decryptedMessages;
	private byte[] key;

	public ManyTimePadDecryptor() {
		cryptograms = new ArrayList<>();
	}
	
	public void add(byte[] cryptogram) {
		cryptograms.add(cryptogram);
		key = null;
		decryptedMessages = null;
	}
	
	public void clear() {
		cryptograms.clear();
		key = null;
		decryptedMessages = null;
		cryptograms.clear();
	}
	
	public void addAll(Collection<? extends byte[]> c) {
		key = null;
		decryptedMessages = null;
		cryptograms.addAll(c);
	}

	private int maxLength() {
		int maxLen = 0;
		for (byte[] cryptogram : cryptograms) {
			maxLen = Integer.max(maxLen, cryptogram.length);
		}
		return maxLen;
	}
	
	public void decrypt() {
		if (cryptograms.size() == 0) return;
		
		int maxLen = maxLength();
		key = new byte[maxLen];
		
		// iterate up until the end of the longest cryptogram
		for (int i = 0; i < maxLen; i++){
			double[] fitness = new double[256];
			// iterate over all possible key byte values
			for (int j = 0; j < 256; j++){
				byte k = (byte)j;
				char[] decoded = new char[cryptograms.size()];
				for (int p = 0; p < cryptograms.size(); p++){
					if (cryptograms.get(p).length <= i){
						continue;
					}
					
					decoded[p] = (char) (cryptograms.get(p)[i] ^ k);
					char c = decoded[p];
					
					// calculate fitness
					if (c == ' ') fitness[j] += WEIGHT_SPACE;
					else if (LOWERCASE.indexOf(c) != -1){
						fitness[j] += WEIGHT_LETTER + FREQUENCY_WEIGHT_FACTOR * LETTER_FREQUENCIES[c - 'a'];
						if (i > 0){
							// check for bigrams
							if ((LOWERCASE + UPPERCASE).indexOf((char) (cryptograms.get(p)[i-1] ^ key[i-1])) != -1){
								char previous = Character.toLowerCase((char) (cryptograms.get(p)[i-1] ^ key[i-1]));
								fitness[j] += FREQUENCY_BIGRAM_WEIGHT_FACTOR * BIGRAM_FREQUENCIES[previous - 'a'][c - 'a'];
							}
						}
					}
					else if (UPPERCASE.indexOf(c) != -1){
						fitness[j] += WEIGHT_LETTER + FREQUENCY_WEIGHT_FACTOR * LETTER_FREQUENCIES[c - 'A'];
						if (i == 0){
							// first letter
							fitness[j] += 0.05;
						} else {
							if (LOWERCASE.indexOf((char) (cryptograms.get(p)[i-1] ^ key[i-1])) != -1){
								// uppercase after lowercase
								fitness[j] -= 0.15;
							} else if (i > 1 && 
									(char) (cryptograms.get(p)[i-1] ^ key[i-1]) == ' ' && 
									PUNCTUATION.indexOf((char) (cryptograms.get(p)[i-2] ^ key[i-2])) != -1) {
								// first letter after the end of a sentence
								fitness[j] += 0.05;
							}
						}
					}
					else if (DIGITS.indexOf(c) != -1) fitness[j] += WEIGHT_DIGIT;
					else if (TYPOGRAPHIC_SPECIAL.indexOf(c) != -1) {
						fitness[j] += WEIGHT_TYPOGRAPHIC;
						if (PUNCTUATION.indexOf(c) != -1){
							if (i > 0 && (char)(cryptograms.get(p)[i-1] ^ key[i-1]) == ' '){
								// space before punctuation mark
								fitness[j] -= 0.1;
							} else if (i == cryptograms.get(p).length-1){
								// last symbol
								fitness[j] += 0.15;
							}
						}
					}
					else if (OTHER_SPECIAL.indexOf(c) != -1) fitness[j] += WEIGHT_OTHER;
					else fitness[j] += WEIGHT_INVALID;
				}
			}
			// pick byte value with best fitness
			int bestfit = -1;
			double bestfitness = Double.NEGATIVE_INFINITY;
			for (int j = 0; j < 256; j++) {
				if (fitness[j] > bestfitness){
					bestfit = j;
					bestfitness = fitness[j];
				}
			}
			
			key[i] = (byte)bestfit;
		}

		// decrypt messages
		decryptedMessages = new String[cryptograms.size()];
		for (int i = 0; i < cryptograms.size(); i++) {
			StringBuilder message = new StringBuilder();
			for (int j = 0; j < cryptograms.get(i).length; j++){
				message.append((char) (cryptograms.get(i)[j] ^ key[j]));
			}
			decryptedMessages[i] = message.toString();
		}
	}

	public String[] getDecryptedMessages() {
		return decryptedMessages;
	}

	public byte[] getKey() {
		return key;
	}

}
