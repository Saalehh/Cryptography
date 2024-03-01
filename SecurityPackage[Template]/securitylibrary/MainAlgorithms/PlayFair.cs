using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            // Converting the Key and given text to Upper case letters.
            key = key.ToUpper();
            cipherText = cipherText.ToUpper();

            Console.WriteLine("[+] The Cipher Text is: " + cipherText);
            Console.WriteLine("[+] The Key Text is: " + key);

            string plainText = "";


            // [1] Create 5X5 table that contains the key and the remaining alphabet letter.
            char[,] table = Create_5x5_Table(cipherText, key);
            // printing the table in the consol screen...
            PrintTable(table);

            // [2] Splitting the given cipher text into pairs of letters.
            List<string> splittedText = SplitText2s(cipherText);

            // printing the cipher text after splitting into pairs...
            PrintSplittedText(splittedText);

            // [3] Start decryption by:
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

                    string decreptedPair = "";

                    // Take the next left element in the row
                    if (j1 - 1 < 0) // Check if this is the first item in the row
                    {
                        decreptedPair += table[i, 4];
                    }
                    else // Take the next left element in the row
                    {
                        decreptedPair += table[i, j1 - 1];
                    }

                    if (j2 - 1 < 0) // Check if this is the first item in the row
                    {
                        decreptedPair += table[i, 4];
                    }
                    else // Take the next left element in the row
                    {
                        decreptedPair += table[i, j2 - 1];
                    }

                    plainText = CheckOriginalXCase(plainText, decreptedPair);
                    // appending this ciphered pair to the main cipher text
                    plainText += decreptedPair;

                }
                // If the two letters are in the same column
                else if (j1 == j2)
                {
                    int j = j1; // To indicate the same column without confusion.

                    string decreptedPair = "";

                    // Take the next element above in the column
                    if (i1 - 1 < 0) // Check if this is the first item in the column
                    {
                        // take the last element in the column
                        decreptedPair += table[4, j];
                    }
                    else // Take the next element above in the column
                    {
                        decreptedPair += table[i1 - 1, j];
                    }

                    if (i2 - 1 < 0) // Check if this is the first item in the column
                    {
                        // take the last element in the column
                        decreptedPair += table[4, j];
                    }
                    else // Take the next element above in the column
                    {
                        decreptedPair += table[i2 - 1, j];
                    }

                    plainText = CheckOriginalXCase(plainText, decreptedPair);
                    // appending this ciphered pair to the main cipher text
                    plainText += decreptedPair;
                }
                // If the two letters are not in the same row or the same column
                else
                {
                    string decreptedPair = "";
                    decreptedPair += table[i1, j2];
                    decreptedPair += table[i2, j1];

                    plainText = CheckOriginalXCase(plainText, decreptedPair);
                    plainText += decreptedPair;
                }
            }

            // if the last letter of the plain text is 'X' we will assume that this 'X' is 
            // resultet from adding it to complete the pair of letters in the encryption phase.
            if (plainText.EndsWith("X"))
            {
                plainText = plainText.Remove(plainText.Length - 1);
            }
            Console.WriteLine("[+] The Decrepted Cipher is: " + plainText + "\n\n");

            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            // Converting the Key and given text to Upper case letters.
            key = key.ToUpper();
            plainText = plainText.ToUpper();

            Console.WriteLine("[+] The Plain Text is: " + plainText);
            Console.WriteLine("[+] The Key Text is: " + key);

            string cipherText = "";

            // [1] Create 5X5 table that contains the key and the remaining alphabet letter.
            char[,] table = Create_5x5_Table(plainText, key);
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

            Console.WriteLine("[+] The Cipher Text is: " + cipherText + "\n\n");

            return cipherText;
        }

        private string Handle_i_j_Case(string text, string key)
        {
            // handling the case of 'I' , 'J', as we should consider that if the key contains 'I' or 'J',
            // it should contain the one which is in the given input.
            // if the text to be encrypted/decrepted contains 'J', deal with 'J' in the key table
            // and if it contains 'I' instead, we should deal with 'I' in the key table
            // and all this is because the table is 5X5 and the alphabet letters are 26,
            // so we deal with 'I' or 'J', but NOT BOTH in the same key table.
            if (text.Contains('I') && key.Contains('J'))
            {
                key = key.Replace('J', 'I');
            }
            else if (text.Contains('J') && key.Contains('I'))
            {
                key = key.Replace('I', 'J');
            }
            return key;
        }

        private char[,] Create_5x5_Table(string text, string key)
        {
            // [1] Initialize the 5X5 table.
            char[,] table = new char[5, 5];

            // [2.1] Getting the uniqe letters that exist in the key
            List<char> uniquKeyLetters = GetUniqueKeyLetters(text, key);
            // [2.2] Getting the letters that aren't exist in the key
            List<char> nonKeyLetters = GetNonKeyLetters(text, key);


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

        private List<char> GetNonKeyLetters(string text, string key)
        {
            List<char> nonKeyLetters = new List<char>();
            char alphabet = 'A'; // Start with 'A'

            for (int i = 0; i < 26; i++)
            {
                char alphaLetter = (char)(alphabet + i);
                if (!key.Contains(alphaLetter))
                {
                    nonKeyLetters.Add(alphaLetter);
                }
            }

            // Handling the 'I' AND 'J' cases in the remaining alphabet letters to be distributed
            key = Handle_i_j_Case(text, key);

            if (key.Contains('I'))
            {
                // this means that the text might contains 'I' or maybe not,
                // but we are sure that the text does not conatin 'J',
                // as we handled it in the function above.
                nonKeyLetters.Remove('J');
            }
            else if (key.Contains('J'))
            {
                // this means that the text might contains 'J' or maybe not,
                // but we are sure that the text does not conatin 'I',
                // as we handled it in the function above.
                nonKeyLetters.Remove('I');
            }
            else
            {
                // if the key does not contain 'I' or 'J',
                // so we will deal with 'I' by default in the key table and remove 'J'.
                nonKeyLetters.Remove('J');
            }

            return nonKeyLetters;
        }

        private List<char> GetUniqueKeyLetters(string text, string key)
        {
            key = Handle_i_j_Case(text, key);

            List<char> uniquKeyLetters = new List<char>();

            for (int i = 0; i < key.Length; i++)
            {
                if (!(uniquKeyLetters.Contains(key[i])))
                {
                    uniquKeyLetters.Add(key[i]);
                }
            }
            return uniquKeyLetters;
        }

        private void PrintTable(char[,] table)
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

        private void PrintSplittedText(List<string> splittedText)
        {
            Console.Write("[+] The Text After Splitting: ");
            foreach (var pair in splittedText)
            {
                Console.Write(pair + " ");
            }
            Console.WriteLine();
        }

        private List<string> SplitText2s(string text)
        {

            List<string> twoCharsList = new List<string>();
            for (int i = 0; i < text.Length; i += 2)
            {
                string twoChars; // The two letter to be added each time.

                if (i + 1 < text.Length) // Check if this is not the last letter
                {
                    if (text[i] == text[i + 1]) // Check the doubl letters case
                    {
                        if (i + 2 < text.Length) // Check if this is not the letter before the last letter. 
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

        private Tuple<int, int> GetLetterPosition(char[,] table, char letter)
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

        private string CheckOriginalXCase(string text, string pair)
        {
            if (text.Length > 1)
            {
                if ((text[text.Length - 2] == pair[0]) && (text[text.Length - 1] == 'X'))
                {
                    text = text.Remove(text.Length - 1);
                }
            }
            
            return text;
        }

    }



    /* [DEMO]

        Key : helloworld

        Key Table:

        j:   0   1   2   3   4             (Encryption)
        i                            [OR] not same row or column
        0    H	 E	 L	 O	 W        O   (0, 3) --> (0, 0)  H
        1    R	 D	 A	 B	 C        R   (1, 0) --> (1, 3)  B
        2    F	 G	 I	 K	 M       [ST]    same row
        3    N	 P	 Q	 S	 T        S   (3, 3) --> (3, 4)  T
        4    U	 V	 X	 Y	 Z        T   (3, 4) --> (3, 0)  N
                                     [YB]    same column
                                      Y   (0, 2) --> (, 2)   O                                                       
                                      B   (3, 2) --> (, 2)   K                                                      

        Word :          STOORYYBOX
        Splitted :      ST OX OR YX YB OX
        Encryption :    TN LY HB ZY OK LY

    */

}