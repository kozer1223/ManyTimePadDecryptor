import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.Locale;

public class BigramCounter {
	
	private final static String CONVERT_FROM = "abcdefghijklmnopqrstuvwxyz¹æêñóœ¿Ÿ";
	private final static String CONVERT_TO = "abcdefghijklmnopqrstuvwxyzacenoszz";
	
	private final static int LETTERS = 26;

	/*
	 * Simple script for calculating bigram frequency of an input text file
	 */
	public static void main(String[] args) {
		String filename = "input.txt";
		boolean prettyOutput = false;
		
		long[][] occurences = new long[LETTERS][LETTERS];
		double[][] frequencies = new double[LETTERS][LETTERS];
		long bigrams = 0;
		
		File file = new File(filename);
		try {
			InputStream is = new FileInputStream(file);
			InputStreamReader in = new InputStreamReader(is, Charset.forName("UTF-8"));
			
			int c;
			char prev = ' ';
			while ((c = in.read()) != -1) {
				char ch = (char)c;
				if (CONVERT_FROM.indexOf(Character.toLowerCase(ch)) == -1){
					ch = ' ';
				} else {
					ch = CONVERT_TO.charAt(CONVERT_FROM.indexOf(Character.toLowerCase(ch)));
				}
				if (prev != ' ' && ch != ' '){
					bigrams++;
					occurences[prev-'a'][ch-'a']++;
				}
				prev = ch;
			}
			
			for (int i = 0; i < LETTERS; i++){
				for (int j = 0; j < LETTERS; j++){
					frequencies[i][j] = 100.0 * (double)occurences[i][j] / (double)bigrams;
				}
			}
			
			System.out.println(bigrams);
			
			if (prettyOutput) {
				//table style
				System.out.print("\t");
				for (char i = 'a'; i <= 'z'; i++){
					System.out.print(i + "\t");
				}
				System.out.println();
				
				DecimalFormat df = new DecimalFormat("#.00", DecimalFormatSymbols.getInstance(Locale.ENGLISH)); 
				
				for (int i = 0; i < LETTERS; i++) {
					System.out.print((char)('a'+i) + "\t");
					for (int j = 0; j < LETTERS; j++){
						System.out.print(df.format(frequencies[i][j]) + "\t");
					}
					System.out.println();
				}
			} else {
				//java 2d array style
				DecimalFormat df = new DecimalFormat("#.00", DecimalFormatSymbols.getInstance(Locale.ENGLISH)); 
				
				for (int i = 0; i < LETTERS; i++) {
					System.out.print("{");
					for (int j = 0; j < LETTERS; j++){
						System.out.print(df.format(frequencies[i][j]) + ((j == LETTERS - 1) ? "" : ", "));
					}
					System.out.println("},");
				}
			}
			
			in.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		
	}

}
