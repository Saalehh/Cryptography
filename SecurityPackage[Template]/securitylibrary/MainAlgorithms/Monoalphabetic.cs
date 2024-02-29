using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            /// key[ALPHA_INDEX[plainText[i]]] = cipherText[i]
            var remainingAlpha = new SortedSet<char>() { 'a', 'b', 'c', 'd', 'e',
            'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
            't', 'u', 'v', 'w', 'x', 'y', 'z'};

            var ALPHA_INDEX = new Dictionary<char, int>() { { 'a', 0 }, { 'b', 1 }, { 'c', 2 },
            { 'd', 3 }, { 'e', 4 }, { 'f', 5 }, { 'g', 6 }, { 'h', 7 }, { 'i', 8 }, { 'j', 9 },
            { 'k', 10 }, { 'l', 11 }, { 'm', 12 }, { 'n', 13 }, { 'o', 14 }, { 'p', 15 }, { 'q', 16 },
            { 'r', 17 }, { 's', 18 }, { 't', 19 }, { 'u', 20 },{ 'v', 21 }, { 'w', 22 }, { 'x', 23 },
            { 'y', 24 }, { 'z', 25 }};

            // Initialize the key with 26 characters of None values
            StringBuilder keyGen = new StringBuilder("__________________________");
            
            // Fill the key with the inversed equation of Encryption
            for (int i = 0; i < plainText.Length; i++)
            {
                keyGen[ALPHA_INDEX[plainText[i]]] = (char)(cipherText[i] + 32); // ToLower
                remainingAlpha.Remove((char)(cipherText[i] + 32));
            }

            // Fill the rest with remainingAlpha
            for (int i = 0; i < keyGen.Length; i++)
            {
                if (keyGen[i] == '_')
                {
                    // In case of first letter in key is None
                    if (i == 0)
                    {
                        keyGen[i] = remainingAlpha.First();
                        remainingAlpha.Remove(keyGen[i]);
                    }
                    else
                    {
                        bool found = false;
                        foreach (char c in remainingAlpha)
                        {
                            // Get the next letter that comes after keyGen[i - 1] in Alphabet
                            if (c > keyGen[i - 1])
                            {
                                keyGen[i] = c;
                                remainingAlpha.Remove(c);
                                found = true;
                                break;
                            }
                        }
                        // In case you found Nothing get the first remaining character
                        if (!found)
                        {
                            keyGen[i] = remainingAlpha.First();
                            remainingAlpha.Remove(keyGen[i]);
                        }
                    }
                }
            }

            return keyGen.ToString();
        }

        public string Decrypt(string cipherText, string key)
        {
            /// plainText[i] = INDEX_ALPHA[key.IndexOf(cipherText[i])]
            var INDEX_ALPHA = new Dictionary<int, char>() { { 0, 'a' }, { 1 , 'b' }, { 2 , 'c' },
            { 3 , 'd' }, { 4 , 'e' }, { 5 , 'f' }, { 6 , 'g' }, { 7 , 'h' }, { 8 , 'i' }, { 9 , 'j' },
            { 10 , 'k' }, { 11 , 'l' }, { 12 , 'm' }, { 13 , 'n' }, { 14 , 'o' }, { 15 , 'p' }, { 16 , 'q' },
            { 17 , 'r' }, { 18 , 's' }, { 19 , 't' }, { 20 , 'u' },{ 21 , 'v' }, { 22 , 'w' }, { 23 , 'x' },
            { 24 , 'y' }, { 25 , 'z' }};

            StringBuilder plainText = new StringBuilder();
            foreach (char letter in cipherText.ToLower())   // Assert all Lowercase
            {
                /*int alphaIndex = key.IndexOf(letter);
                decryptedText.Append((char)(alphaIndex + 97));*/
                plainText.Append(INDEX_ALPHA[key.IndexOf(letter)]);
            }
            return plainText.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            /// cipherText[i] = key[ALPHA_INDEX[plainText[i]]]
            var ALPHA_INDEX = new Dictionary<char, int>() { { 'a', 0 }, { 'b', 1 }, { 'c', 2 },
            { 'd', 3 }, { 'e', 4 }, { 'f', 5 }, { 'g', 6 }, { 'h', 7 }, { 'i', 8 }, { 'j', 9 },
            { 'k', 10 }, { 'l', 11 }, { 'm', 12 }, { 'n', 13 }, { 'o', 14 }, { 'p', 15 }, { 'q', 16 },
            { 'r', 17 }, { 's', 18 }, { 't', 19 }, { 'u', 20 },{ 'v', 21 }, { 'w', 22 }, { 'x', 23 },
            { 'y', 24 }, { 'z', 25 }};

            StringBuilder cipherText = new StringBuilder();
            foreach (char letter in plainText.ToLower())    // Assert all Lowercase
            {
                /*int asciiLetter = (int) letter;
                int alphaIndex = asciiLetter - 97;  // Index in Alphabet
                encryptedText.Append(key[alphaIndex]);*/
                cipherText.Append(key[ALPHA_INDEX[letter]]);
            }
            return cipherText.ToString().ToUpper();
        }







        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	=
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        /// 

        public string AnalyseUsingCharFrequency(string cipher)
        {
            var sortedAlpha = new SortedDictionary<int, char>() { { 0, 'e' }, { 1 , 't' }, { 2 , 'a' },
            { 3, 'o' }, { 4, 'i' },{ 5, 'n' }, { 6, 's' }, { 7, 'r' }, { 8, 'h' }, { 9, 'l' }, { 10, 'd' }, { 11, 'c' },
            { 12, 'u' }, { 13, 'm' }, { 14, 'f' }, { 15, 'p' }, { 16, 'g' }, { 17, 'w' }, { 18, 'y' }, { 19, 'b' }, { 20, 'v' },
            { 21, 'k' }, { 22, 'x' }, { 23, 'j' }, { 24, 'q' }, { 25, 'z' }};

            StringBuilder plainText = new StringBuilder();
            var letterFreq = new SortedDictionary<char, int>();

            // Calculate the frequency of each letter in cipherText
            foreach (char letter in cipher.ToLower())
            {
                if (letterFreq.ContainsKey(letter))
                    letterFreq[letter]++;
                else
                    letterFreq.Add(letter, 1);
            }

            // Sort the cipherText letters according to their frequency
            StringBuilder cipherTextSorted = new StringBuilder();
            foreach (KeyValuePair<char, int> entry in letterFreq)
            {
                char letter = entry.Key;
                cipherTextSorted.Append(letter);
            }

            // Apply BubbleSort to sort the cipherText letters
            for (int i = 0; i < cipherTextSorted.Length; i++)
            {
                for (int j = i + 1; j < cipherTextSorted.Length; j++)
                {
                    if (letterFreq[cipherTextSorted[i]] < letterFreq[cipherTextSorted[j]])
                    {
                        char temp = cipherTextSorted[i];
                        cipherTextSorted[i] = cipherTextSorted[j];
                        cipherTextSorted[j] = temp;
                    }
                }
            }

            // Map the sorted letters with the sorted frequency chart (descendingly)
            var mapping = new SortedDictionary<char, char>();
            for (int i = 0; i < cipherTextSorted.Length; i++)
            {
                mapping.Add(cipherTextSorted[i], sortedAlpha[i]);
            }
            foreach (char letter in cipher.ToLower())
            {
                if (mapping.ContainsKey(letter))
                    plainText.Append(mapping[letter]);
            }

            return plainText.ToString();
        }
    }
}