using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            Console.WriteLine("[+] The Cipher Text is: " + cipherText);
            
            string plainText = "";


            // [1] Create 5X5 table that contains the key and the remaining alphabet letter.
            char[,] table = Create_5x5_Table(key);
            // printing the table in the consol screen...
            PrintTable(table);

            // [2] Splitting the given cipher text into pairs of letters.
            List<string> splittedText = SplitText2s(cipherText);

            // printing the cipher text after splitting into pairs...
            PrintSplittedText(splittedText);

            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            Console.WriteLine("[+] The Plain Text is: " + plainText);

            string cipherText = "";
            // [1] Create 5X5 table that contains the key and the remaining alphabet letter.
            char[,] table = Create_5x5_Table(key);
            // printing the table in the consol screen...
            PrintTable(table);

            // [2] Splitting the given plain text into pairs of letters.
            List<string> splittedText = SplitText2s(plainText);

            // printing the plain text after splitting into pairs...
            PrintSplittedText(splittedText);

            // [3] Start encryption by:
            // [3.1] Taking each two letters and identifying their positions in the table
            foreach (var pair in splittedText)
            {
                Tuple<int, int> positionOfFirstLetterInTabl = GetLetterPosition(table, pair[0]);
                int i1 = positionOfFirstLetterInTabl.Item1;
                int j1 = positionOfFirstLetterInTabl.Item2;

                Tuple<int, int> positionOfSecondLetterInTabl = GetLetterPosition(table, pair[1]);
                int i2 = positionOfSecondLetterInTabl.Item1;
                int j2 = positionOfSecondLetterInTabl.Item2;

                // If the two letters are in the same row
                if (i1 == i2)
                {
                    int i = i1; // To indicate the same row without confusion.

                    string cipheredPair = "";

                    // Take the next right element in the row
                    if (j1 + 1 > 4) // Check if this is the last item in the row
                    {
                        cipheredPair += table[i, 0];
                    }
                    else // Take the next right element in the row
                    {
                        cipheredPair += table[i, j1 + 1];
                    }

                    if (j2 + 1 > 4) // Check if this is the last item in the row
                    {
                        cipheredPair += table[i, 0];
                    }
                    else // Take the next right element in the row
                    {
                        cipheredPair += table[i, j2 + 1];
                    }

                    // appending this ciphered pair to the main cipher text
                    cipherText += cipheredPair;

                }
                // If the two letters are in the same column
                else if (j1 == j2)
                {
                    int j = j1; // To indicate the same column without confusion.

                    string cipheredPair = "";

                    // Take the next element below in the column
                    if (i1 + 1 > 4) // Check if this is the last item in the column
                    {
                        // take the first element in the column
                        cipheredPair += table[0, j];
                    }
                    else // Take the next element below in the column
                    {
                        cipheredPair += table[i1 + 1, j];
                    }

                    if (i2 + 1 > 4) // Check if this is the last item in the column
                    {
                        // take the first element in the column
                        cipheredPair += table[0, j];
                    }
                    else // Take the next element below in the column
                    {
                        cipheredPair += table[i2 + 1, j];
                    }

                    // appending this ciphered pair to the main cipher text
                    cipherText += cipheredPair;
                }
                // If the two letters are not in the same row or the same column
                else
                {
                    string cipheredPair = "";
                    cipheredPair += table[i1, j2];
                    cipheredPair += table[i2, j1];

                    cipherText += cipheredPair;
                }
            }

            Console.WriteLine("[+] The Ciphered P: " + cipherText);
            Console.WriteLine("[+] The Cipher Text is: " + cipherText);

            return cipherText;
        }

        public char[,] Create_5x5_Table(string key)
        {
            // Converting the Key to Upper case letters.
            key = key.ToUpper();

            // Checking if the key contains the letter 'J' and replace it with 'I'
            if (key.Contains('J'))
            {
                key = key.Replace('J', 'I');
            }

            // [1] Initialize the 5X5 table.
            char[,] table = new char[5, 5];

            // [2.1] Getting the uniqe letters that exist in the key
            List<char> uniquKeyLetters = GetUniqueKeyLetters(key);
            // [2.2] Getting the letters that aren't exist in the key
            List<char> nonKeyLetters = GetNonKeyLetters(key);


            // [3] Distribute the key in its first indexes,
            // and the remained empty indexes will be filled with the alphabet that aren't in the key. 

            int currentkeyIndex = 0; // To track the current index of the key when inserting in the table.
            int currentNonkeyIndex = 0; // To track the current index of the remaining alphabet letters when inserting in the table.


            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    // Check if the key is tatally distributed on the tabel.
                    if (currentkeyIndex >= uniquKeyLetters.Count())
                    {
                        // Start distributing the remained alphabet letters                         
                        table[i, j] = nonKeyLetters[currentNonkeyIndex];
                        currentNonkeyIndex++; // Move to the next character in the remained alphabet letters.

                    }
                    else
                    {
                        // Start distributing the unique key letters.
                        table[i, j] = uniquKeyLetters[currentkeyIndex];
                        currentkeyIndex++; // Move to the next character in the key

                    }
                }
            }

            return table;
        }

        public List<char> GetNonKeyLetters(string key)
        {
            List<char> nonKeyLetters = new List<char>();
            char alphabet = 'A'; // Start with 'A'

            key = key.ToUpper(); // Convert the key to uppercase

            for (int i = 0; i < 26; i++)
            {
                char alphaLetter = (char)(alphabet + i);
                if (!key.Contains(alphaLetter))
                {
                    nonKeyLetters.Add(alphaLetter);
                }
            }
            // Removing the letter 'J'
            nonKeyLetters.Remove('J');

            return nonKeyLetters;
        }

        public List<char> GetUniqueKeyLetters(string key)
        {
            List<char> uniquKeyLetters = new List<char>();
            key = key.ToUpper(); // Convert the key to uppercase

            for (int i = 0; i < key.Length; i++)
            {
                if (!(uniquKeyLetters.Contains(key[i])))
                {
                    uniquKeyLetters.Add(key[i]);
                }
            }
            return uniquKeyLetters;
        }

        public void PrintTable(char[,] table)
        {
            Console.WriteLine("[+] Key Table:\n");
            // Access and print elements of the table
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    Console.Write(table[i, j] + " ");
                }
                Console.WriteLine();
            }

        }

        public void PrintSplittedText(List<string> splittedText)
        {
            Console.Write("[+] The Plain Text After Splitting: ");
            foreach (var pair in splittedText)
            {
                Console.Write(pair + " ");
            }
            Console.WriteLine();
        }

        public List<string> SplitText2s(string text)
        {
            text = text.ToUpper();

            List<string> twoCharsList = new List<string>();
            for (int i = 0; i < text.Length; i += 2)
            {
                string twoChars; // The two letter to be added each time.

                if (!(i + 1 >= text.Length)) // Check if this is not the last letter
                {
                    if (text[i] == text[i + 1]) // Check the doubl letters case
                    {
                        if (!(i + 2 >= text.Length)) // Check if this is not the letter before the last letter. 
                        {
                            // Add 'X' to the first instance,
                            // and the next two letters will be the same letter and the letter after it by 2 indexes,
                            // as we are sure that it is a double instance
                            twoChars = text[i].ToString() + "X";
                            twoCharsList.Add(twoChars);

                            twoChars = text[i].ToString() + text[i + 2].ToString();
                            twoCharsList.Add(twoChars);
                            i++; // increament i by one to avoid taking the already taken letter again in this case
                        }
                        else // If these are the last two letters, add 'X' to each instance of them.
                        {
                            twoChars = text[i].ToString() + "X";
                            twoCharsList.Add(twoChars);

                            twoChars = text[i + 1].ToString() + "X";
                            twoCharsList.Add(twoChars);
                        }
                    }
                    else
                    {
                        twoChars = text[i].ToString() + text[i + 1].ToString();
                        twoCharsList.Add(twoChars);
                    }
                }
                else // If there is only one character left, append 'X' to it.
                {
                    twoChars = text[i].ToString() + "X";
                    twoCharsList.Add(twoChars);
                }
            }
            return twoCharsList;
        }

        public Tuple<int, int> GetLetterPosition(char[,] table, char letter)
        {
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (table[i, j] == letter)
                    {
                        return Tuple.Create(i, j); // returning a tuple of the (i,j) position for the letter in the table 
                    }
                }
            }

            return null; // Character not found
        }

    }



    /*
    Key = helloworld

    j:   0   1   2   3   4
    i                    
    0    H	 E	 L	 O	 W          (0, 3) --> (0, 0)
    1    R	 D	 A	 B	 C          (1, 0) --> (1, 3)
    2    F	 G	 I	 K	 M
    3    N	 P	 Q	 S	 T          (3, 3) --> (3, 4)
    4    U	 V	 X	 Y	 Z          (3, 4) --> (3, 0)

    STOORYYBOX
    ST OX OR YX YB OX
    TN LY HB ZY OK LY


     */

}