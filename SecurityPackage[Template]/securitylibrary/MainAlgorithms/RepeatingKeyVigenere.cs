namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
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
            for (int i = 0; i < repeatedKey.Length; i++)
            {
                if (repeatedKey.Substring(i, Key.Length) == Key && Key != "")
                    break;
                Key += repeatedKey[i];
            }

            return Key;
        }

        public string Decrypt(string cipherText, string key)
        {
            var cipherTextLength = cipherText.Length;
            var keyLength = key.Length;
            string newKey = "";

            //  Generating the new key by repeating itself
            int repeatedWord = cipherTextLength / keyLength;
            while (repeatedWord > 0)
            {
                newKey += key;
                repeatedWord--;
            }
            newKey += key.Substring(0, cipherTextLength % keyLength);

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
                    if (matrix[row, (newKey[i] - 'a')] == cipherText[i])
                    {
                        plainText += (char)('a' + row);
                        break;
                    }
                }
            }

            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            var painTextLength = plainText.Length;
            var keyLength = key.Length;
            string newKey = "";

            //  Generating the new key by repeating itself
            int repeatedWord = painTextLength / keyLength;
            while (repeatedWord > 0)
            {
                newKey += key;
                repeatedWord--;
            }
            newKey += key.Substring(0, painTextLength % keyLength);

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

