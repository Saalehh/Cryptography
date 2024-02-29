using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {

        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            StringBuilder cipherText = new StringBuilder();
            foreach (char letter in plainText)
            {
                int asciiLetter = (int)letter;
                if (asciiLetter <= 122 && asciiLetter >= 97)    // lowercase
                {
                    cipherText.Append((char)((asciiLetter + key - 97) % 26 + 97));
                }
                else if (asciiLetter <= 90 && asciiLetter >= 65)    // uppercase
                {
                    cipherText.Append((char)((asciiLetter + key - 65) % 26 + 65));
                }
                else
                {
                    cipherText.Append(letter);
                }
            }
            return cipherText.ToString().ToUpper();
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            StringBuilder plainText = new StringBuilder();
            foreach (char letter in cipherText)
            {
                int asciiLetter = (int)letter;
                if (asciiLetter <= 90 && asciiLetter >= 65)
                {
                    if (asciiLetter - key - 65 < 0)     // letter index < 0 after subtracting key
                        plainText.Append((char)(26 + (asciiLetter - key - 65) + 65));
                    else
                        plainText.Append((char)((asciiLetter - key - 65) % 26 + 65));
                }
                else
                {
                    plainText.Append(letter);
                }
            }
            return plainText.ToString().ToLower();
        }

        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            for (int keyGen = 0; keyGen < 26; keyGen++)
            {
                if (cipherText == Encrypt(plainText, keyGen))
                    return keyGen;
            }
            return 0;
        }
    }
}