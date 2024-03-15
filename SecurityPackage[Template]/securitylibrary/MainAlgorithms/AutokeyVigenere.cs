using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {

            var cipherTextLength = cipherText.Length;

            //  Building the matrix
            char[,] matrix = new char[26, 26];
            for (int row = 0; row < 26; row++)
            {
                char letter = (char)('A' + row);
                for (int col = 0; col < 26; col++)
                {
                    matrix[row, col] = letter;
                    letter++;
                    if (letter > 'Z')
                    {
                        letter = 'A';
                    }
                }
            }

            //  Getting the LongKey
            string repeatedKey = "";
            for (int i = 0; i < cipherTextLength; i++)
            {
                for (int row = 0; row < 26; row++)
                {
                    if (matrix[row, (plainText[i] - 'a')] == cipherText[i])
                    {
                        repeatedKey += (char)('a' + row);
                        break;
                    }
                }
            }

            //  Getting the real key
            string Key = "";

            for (int i = 0 ;i< cipherTextLength; i++)
            {
                if (repeatedKey[i] == plainText[0])
                {
                    if (cipherText == Encrypt(plainText, Key))
                    {
                        return Key;
                    }
                    else
                    {
                        Key += repeatedKey[i];
                    }
                }
                else
                {
                    Key += repeatedKey[i];
                }
            }
            //Console.WriteLine(plainText);
            //Console.WriteLine(Key);

            return Key;
        }

        public string Decrypt(string cipherText, string key)
        {
            var cipherTextLength = cipherText.Length;
            
            //  Bulding the matrix
            char[,] matrix = new char[26, 26];
            for (int row = 0; row < 26; row++)
            {
                char letter = (char)('A' + row);
                for (int col = 0; col < 26; col++)
                {
                    matrix[row, col] = letter;
                    letter++;
                    if (letter > 'Z')
                    {
                        letter = 'A';
                    }
                }
            }

            //  Getting the plainText
            var plainText = "";
            for (int i = 0; i < cipherTextLength; i++)
            {
                for (int row = 0; row < 26; row++)
                {
                    if (matrix[row, (key[i] - 'a')] == cipherText[i])
                    {
                        plainText += (char)('a' + row);
                        if (key.Length < cipherText.Length)
                        {
                            key += plainText[plainText.Length - 1];
                        }
                        break;
                    }
                }
            }

            return plainText;

        }

        public string Encrypt(string plainText, string key)
        {

            var diffrienceLength = plainText.Length - key.Length;
            string newKey = "";

            
            newKey += key + plainText.Substring(0, diffrienceLength);
            //Console.WriteLine(newKey);
            //  Bulding the matrix
            char[,] matrix = new char[26, 26];
            for (int row = 0; row < 26; row++)
            {
                char letter = (char)('A' + row);
                for (int col = 0; col < 26; col++)
                {
                    matrix[row, col] = letter;
                    letter++;
                    if (letter > 'Z')
                    {
                        letter = 'A';
                    }
                }
            }

            //  Getting the cipherText
            var cipherText = "";
            for (int i = 0; i < newKey.Length; i++)
            {
                cipherText += matrix[plainText[i] - 'a', newKey[i] - 'a'];
            }

            return cipherText;


        }
    }
}
