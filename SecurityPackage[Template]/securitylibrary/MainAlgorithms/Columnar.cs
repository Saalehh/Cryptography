using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {

        /*
         * Encryption
         * 
         * Key = 1 3 4 2 5
         *  
         *  [+] Write                        [+] Read
         *  Row-Wise                         Col-Wise
         *  
         *  C O M P U                        C P O M U
         *  T E R S C           ->           T S E R C
         *  I E N C E                        I C E N E
         *  
         *  0 1 2 3 4 5 6 7 8 9 1 1 1 1 1    0 5 1 3 
         *                      0 1 2 3 4        0
         *  C o m p u t e r S c i e n c e -> C T I P S C O E E M R N U C E
         *  
         *  nColumns = key.Count()
         *  depth = Ceil(plainText.Length/rowSize)
         *  [+] Matrix: depth x nColumns
         */

        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            
            int nColumns = CalculateColumnsNumber(plainText, cipherText);
            int depth = plainText.Length / nColumns;

            char[,] plainTextTable = Create2DArray(plainText, nColumns, depth, "row-wise");
            char[,] cipherTextTable = Create2DArray(cipherText, nColumns, depth, "col-wise");

            var keyGen = new List<int>();
            for(int i = 1; i <= nColumns; i++)
                keyGen.Add(i);

            for (int i = 0; i < 1; i++)
            {
                for (int j = 0; j < nColumns; j++)
                {
                    // Search the row
                    for (int k = 0; k < nColumns; k++)
                    {
                        bool found = false;
                        if (plainTextTable[i, j] == cipherTextTable[i, k])
                        {
                            // Check the Column
                            bool areEqual = true;
                            for (int l = 0; l < depth; l++)
                            {
                                if (plainTextTable[l, j] != cipherTextTable[l, k])
                                {
                                    areEqual = false;
                                    break;
                                }
                            }
                            if (areEqual)
                            {
                                keyGen[j] = k + 1;
                                found = true;
                            }
                        }
                        if (found)
                            break;
                    }
                }
            }

            return keyGen;
        }

        private int CalculateColumnsNumber(string plainText, string cipherText)
        {
            // Dictionary for number of letter occurrence in cipherText
            Dictionary<char, int> occurrence = new Dictionary<char, int>();
            // Initialization
            foreach (char letter in plainText)
            {
                if (!occurrence.ContainsKey(letter))
                    occurrence.Add(letter, 1);
            }

            int mostFreqColNum = 0;
            // Dictionary for calculating the mostFreqColNum
            var freq = new Dictionary<int, int>();
            // Initialization
            freq[mostFreqColNum] = 0;

            for (int i = 1; i < cipherText.Length; i++)
            {
                int indexBefore = plainText.IndexOf(cipherText[i - 1]);
                for (int j = 0; j < occurrence[cipherText[i - 1]] - 1; j++)
                {
                    int temp = plainText.IndexOf(cipherText[i - 1], indexBefore + 1);
                    indexBefore = (temp != -1) ? temp : indexBefore;
                }

                occurrence[cipherText[i]]++;
                int indexPresent = plainText.IndexOf(cipherText[i]);
                for (int j = 0; j < occurrence[cipherText[i]] - 1; j++)
                {
                    int temp = plainText.IndexOf(cipherText[i], indexPresent + 1);
                    indexPresent = (temp != -1) ? temp : indexPresent;
                }

                // Calculate the distance between both indices
                int distance = (indexPresent > indexBefore) ?
                    indexPresent - indexBefore : indexBefore - indexPresent;

                // Increase the frequency of this distance
                if (!freq.ContainsKey(distance))
                {
                    freq.Add(distance, 0);
                }
                freq[distance]++;

                // mostFreqColNum = Max between this distance and mostFreqColNum
                mostFreqColNum = (freq[distance] > freq[mostFreqColNum]) ?
                    distance : mostFreqColNum;
            }

            return mostFreqColNum;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            // Calculate the table size
            int nColumns = key.Count();
            int depth = cipherText.Length / nColumns;

            // Reorder cipherText using key
            var cipherTextReordered = new StringBuilder(cipherText);            
            for (int i = 0, k = 0; i < cipherTextReordered.Length && k < key.Count(); i += depth, k++)
            {
                for (int j = 0; j < depth; j++) {
                    cipherTextReordered[i+j] = cipherText[(key[k] - 1) * depth + j];
                }                
            }

            // Create the algorithm table Column-Wise with the reordered cipherText
            char[,] plainTextTable = Create2DArray(cipherTextReordered.ToString(), nColumns, depth, "col-wise");

            // Create the plainText by reading the table Row-Wise
            var plainText = new StringBuilder();
            for (int i = 0; i < depth; i++)
            {
                for (int j = 0; j < nColumns; j++)
                {
                    plainText.Append(plainTextTable[i, j]);
                }
            }

            return plainText.ToString().ToLower();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            // Assert all UpperCase
            plainText = plainText.ToUpper();

            // Calculate the table size
            int nColumns = key.Count();
            int depth = plainText.Length / nColumns;
            
            // In case of empty table cells -> Pad the plainText with 'X's
            if (plainText.Length % nColumns != 0)
            {
                depth++;
                plainText = PadX(plainText, (nColumns * depth) - plainText.Length);
            }

            // Create the algorithm table
            char[,] plainTextTable = Create2DArray(plainText, nColumns, depth, "row-wise");

            // Make cipherText the same size as plainText (after padding if it happened)
            var cipherText = new StringBuilder(plainText);

            // Create the cipherText by putting each column in its correct place
            for (int i = 0; i < nColumns; i++)
            {
                for (int j = 0; j < depth; j++)
                {
                    cipherText[(key[i] - 1) * depth + j] = plainTextTable[j, i];
                }
            }

            return cipherText.ToString();
        }

        private string PadX(string plainText, int count)
        {
            for (int i = 0; i < count; i++)
            {
                plainText += 'X';
            }
            return plainText;
        }

        private char[,] Create2DArray(string Text, int nColumns, int depth, string method)
        {
            char[,] arr = new char[depth, nColumns];
            if (method == "row-wise") {
                int textPointer = 0;
                for (int i = 0; i < depth; i++)
                {
                    for (int j = 0; j < nColumns; j++)
                    {
                        arr[i, j] = Text[textPointer];
                        textPointer++;
                    }
                }
            }
            else if (method == "col-wise")
            {
                int textPointer = 0;
                for (int i = 0; i < nColumns; i++)
                {
                    for (int j = 0; j < depth; j++)
                    {
                        arr[j, i] = Text[textPointer];
                        textPointer++;
                    }
                }
            }
            return arr;
        }

    }
}
