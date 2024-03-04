using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int suitableKey = 2; // Initialize the best key with a default value
            int minKey = 2; // Minimum key value to start with
            int maxKey = cipherText.Length / 2; // Maximum key value (half the length of the ciphertext)

            // Iterate through possible key values
            for (int key = minKey; key <= maxKey; key++)
            {
                // Encrypt the plaintext using the current key
                string EncryptedText = Encrypt(plainText, key);

                // Check if the decrypted text matches the provided plaintext
                if (EncryptedText.Equals(cipherText))
                {
                    // If a match is found, set the best key and break out of the loop
                    suitableKey = key;
                    break;
                }
            }

            // Return the best key found during analysis
            return suitableKey;
        }
        public string Decrypt(string cipherText, int key)
        {
            // Display the cipher text and key
            Console.Write("Cipher Text: ");
            Console.WriteLine(cipherText);
            Console.Write("Key: ");
            Console.WriteLine(key);
            // Convert the cipher text to lowercase for consistency
            cipherText = cipherText.ToLower();

            // Initialize a StringBuilder to store the plain text
            var plainText = new StringBuilder("");

            // Calculate the length of each part of the cipher text when dividing it into segments based on the key
            int P_T_Length = CalculateP_T_Length(cipherText, key);

            // Create a 2D array to represent the cipher text table using the specified method (col-wise in this case)
            char[,] ciptherTextTable = Create2DArray(cipherText, P_T_Length, key, "col-wise");

            // Print the 2D array representing the cipher text table for visualization
            Print2DArray(ciptherTextTable, key, P_T_Length);

            // Copy the characters from the cipher text table into the plain text StringBuilder, column by column
            plainText = CopyCharactersTable(ciptherTextTable, key, P_T_Length, "col-wise");

            // Display the plain text
            Console.Write("Plain Text: ");
            Console.WriteLine(plainText.ToString());
            // Convert the StringBuilder containing the plain text to a string and return it
            return plainText.ToString();

        }
        public string Encrypt(string plainText, int key)
        {
            // Display the plain text and key
            Console.Write("Plain Text: ");
            Console.WriteLine(plainText);
            Console.Write("Key: ");
            Console.WriteLine(key);
            // Convert the plaintext to uppercase for consistency
            plainText = plainText.ToUpper();

            // Initialize a StringBuilder to store the ciphertext
            var cipherText = new StringBuilder("");

            // Calculate the length of each part of the plaintext when dividing it into segments based on the key
            int P_T_Length = CalculateP_T_Length(plainText, key);

            // Create a 2D array to represent the plaintext table using the specified method (row-wise in this case)
            char[,] plainTextTable = Create2DArray(plainText, P_T_Length, key, "row-wise");

            // Print the 2D array representing the plaintext table for visualization
            Print2DArray(plainTextTable, key, P_T_Length);

            // Copy the characters row by row from the plaintext table into the ciphertext StringBuilder
            cipherText = CopyCharactersTable(plainTextTable, key, P_T_Length, "row-wise");


            // Display the cipher text
            Console.Write("Cipher Text: ");
            Console.WriteLine(cipherText.ToString());
            // Convert the StringBuilder containing the ciphertext to a string and return it
            return cipherText.ToString();

        }
        private int CalculateP_T_Length(String Text, int key)
        {
            // Calculate the length of each part of the plaintext when dividing it into segments based on the key
            int segmentLength = Text.Length / key;

            // If the division has a remainder, indicating that the length of each segment is not evenly divisible by the key
            if (Text.Length % key != 0)
            {
                // Increment the segment length by 1 to accommodate the remaining characters
                segmentLength++;
            }

            // Return the calculated segment length
            return segmentLength;
        }
        private char[,] Create2DArray(string Text, int nColumns, int depth, string method)
        {

            char[,] arr = new char[depth, nColumns]; // Create a 2D character array to hold the encrypted or decrypted text

            if (method == "row-wise") // If the encryption or decryption method is row-wise
            {
                int textPointer = 0; // Initialize a pointer to keep track of the current character position in the text
                for (int col = 0; col < nColumns; col++) // Iterate through each column of the array
                {
                    for (int row = 0; row < depth; row++) // Iterate through each row of the array
                    {
                        if (textPointer < Text.Length) // If there are characters left in the text
                        {
                            arr[row, col] = Text[textPointer]; // Assign the character from the text to the current position in the array
                            textPointer++; // Move to the next character in the text
                        }
                        else
                        {
                            arr[row, col] = ' '; // If the text ends before filling the entire array, pad the remaining cells with spaces
                        }
                    }
                }
            }
            else if (method == "col-wise") // If the encryption or decryption method is column-wise
            {
                int textPointer = 0; // Initialize a pointer to keep track of the current character position in the text
                for (int i = 0; i < depth; i++) // Iterate through each row of the array
                {
                    for (int j = 0; j < nColumns; j++) // Iterate through each column of the array
                    {
                        if (textPointer < Text.Length) // If there are characters left in the text
                        {
                            arr[i, j] = Text[textPointer]; // Assign the character from the text to the current position in the array
                            textPointer++; // Move to the next character in the text
                        }
                        else
                        {
                            arr[i, j] = ' '; // If the text ends before filling the entire array, pad the remaining cells with spaces
                        }
                    }
                }
            }

            return arr; // Return the filled 2D array

        }
        private void Print2DArray(char[,] arr, int depth, int nColumns)
        {
            // Output the resulting 2D array to the console
            Console.WriteLine("Resulting 2D array:");

            // Iterate through each row of the array
            for (int row = 0; row < depth; row++)
            {
                // Iterate through each column of the array
                for (int col = 0; col < nColumns; col++)
                {
                    // Output the character at the current position followed by a space
                    Console.Write(arr[row, col] + " ");
                }
                // Move to the next line after printing each row
                Console.WriteLine();
            }
        }
        private StringBuilder CopyCharactersTable(char[,] arr, int depth, int nColumns, string method)
        {
            // Check the method for copying characters
            if (method == "row-wise")
            {
                // Initialize a StringBuilder to store the cipher text
                var cipherText = new StringBuilder("");

                // Iterate through each row of the array
                for (int row = 0; row < depth; row++)
                {
                    // Iterate through each column of the array
                    for (int col = 0; col < nColumns; col++)
                    {
                        // If the character at the current position is not a space, append it to the cipherText StringBuilder
                        if (arr[row, col] != ' ')
                            cipherText.Append(arr[row, col]);
                    }
                }

                // Return the cipher text as a StringBuilder
                return cipherText;
            }
            else if(method == "col-wise")
            {
                // Initialize a StringBuilder to store the plain text
                var plainText = new StringBuilder("");

                // Iterate through each column of the array
                for (int col = 0; col < nColumns; col++)
                {
                    // Iterate through each row of the array
                    for (int row = 0; row < depth; row++)
                    {
                        // If the character at the current position is not a space, append it to the plainText StringBuilder
                        if (arr[row, col] != ' ')
                            plainText.Append(arr[row, col]);
                    }
                }

                // Return the plain text as a StringBuilder
                return plainText;
            }
            return new StringBuilder();

        }
    }
}
