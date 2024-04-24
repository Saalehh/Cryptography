using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        static readonly int[] initialPermutationTable = new int[]
              {
            57, 49, 41, 33, 25, 17, 9,  1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7,
            56, 48, 40, 32, 24, 16, 8,  0,
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6
              };
        static readonly int[] permutedChoice1Table = new int[]
        {
            56, 48, 40, 32, 24, 16,  8,
             0, 57, 49, 41, 33, 25, 17,
             9,  1, 58, 50, 42, 34, 26,
            18, 10,  2, 59, 51, 43, 35,

            62, 54, 46, 38, 30, 22, 14,
             6, 61, 53, 45, 37, 29, 21,
            13,  5, 60, 52, 44, 36, 28,
            20, 12,  4, 27, 19, 11,  3
        };
        static readonly int[] permutedChoice2Table = new int[]
        {
            13, 16, 10, 23,  0, 4,
            2 , 27, 14,  5, 20, 9,
            22, 18, 11,  3, 25, 7,
            15,  6, 26, 19, 12, 1,
            40, 51, 30, 36, 46, 54,
            29, 39, 50, 44, 32, 47,
            43, 48, 38, 55, 33, 52,
            45, 41, 49, 35, 28, 31
        };
        static readonly int[] expansionTable = new int[]
        {
            31,  0,  1,  2,  3,  4,
            3,   4,  5,  6,  7,  8,
            7,   8,  9, 10, 11, 12,
            11, 12, 13, 14, 15, 16,
            15, 16, 17, 18, 19, 20,
            19, 20, 21, 22, 23, 24,
            23, 24, 25, 26, 27, 28,
            27, 28, 29, 30, 31,  0
        };
        static readonly int[,] sBox1 = new int[,]
         {
            {14,  4, 13, 1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9, 0, 7},
            {0,  15,  7, 4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5, 3, 8},
            {4,   1, 14, 8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10, 5, 0},
            {15, 12,  8, 2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0, 6, 13}
         };
        static readonly int[,] sBox2 = new int[,]
        {
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
            {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
            {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
            {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
        };
        static readonly int[,] sBox3 = new int[,]
        {
            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
            {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
            {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
            {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
        };
        static readonly int[,] sBox4 = new int[,]
        {
            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
            {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
            {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
            {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
        };
        static readonly int[,] sBox5 = new int[,]
        {
            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
            {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
            {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
            {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
        };
        static readonly int[,] sBox6 = new int[,]
        {
            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
            {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
            {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
            {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
        };
        static readonly int[,] sBox7 = new int[,]
        {
            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
            {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
            {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
            {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
        };
        static readonly int[,] sBox8 = new int[,]
        {
            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
            {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
            {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
            {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
        };
        static readonly int[] permutationBox = new int[]
        {
            15, 6, 19, 20,
            28, 11, 27, 16,
            0, 14, 22, 25,
            4, 17, 30, 9,
            1, 7, 23, 13,
            31, 26, 2, 8,
            18, 12, 29, 5,
            21, 10, 3, 24
        };
        static readonly int[] finalPermutationTable = new int[]
        {
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25,
            32, 0, 40, 8, 48, 16, 56, 24
        };


        public override string Encrypt(string plainText, string key)
        {
            /// <summary>
            /// Encrypts the given plaintext using the DES algorithm with the provided key.
            /// </summary>
            /// <param name="plainText">The plaintext to be encrypted.</param>
            /// <param name="key">The key used for encryption.</param>
            /// <returns>The ciphertext obtained after encryption.</returns>
            
            // [0] Convert To binary
            string binaryPlain = ConvertHexToBinary(plainText);
            string binaryKey = ConvertHexToBinary(key);

            // [1] Initial Permutaiton 
            string permuted = InitialPermutaiton(binaryPlain);

            // [2] Prepare the 16 roundKeys
            List<string> roundKeys = GenerateRoundKeys(binaryKey);

            // [3] Apply the 16 rounds with the 16 keys
            // This is the input for each round, at the first round, the PC-1 is the input, then the output of a round is the input for the next one.
            string roundInput = permuted;
            string roundOutput = "";
            foreach (var roundKey in roundKeys)
            {
                roundOutput = Round(roundInput, roundKey);
                roundInput = roundOutput;
            }
            // Catching the output after the 16 rounds.
            string outputOf16Rounds = roundOutput;

            //[4] Swap the two 32-bit blocks of the output
            string L_output = outputOf16Rounds.Substring(0, 32);
            string R_output = outputOf16Rounds.Substring(32);

            StringBuilder swapped = new StringBuilder();
            swapped.Append(R_output);
            swapped.Append(L_output);

            // [5] Apply the final permutation
            string cipheredBlock = FinalPermutation(swapped.ToString());

            return "0x" + ConvertBinaryToHex(cipheredBlock);
        }
        public override string Decrypt(string cipherText, string key)
        {
            /// <summary>
            /// Decrypts the given ciphertext using the DES algorithm with the provided key.
            /// </summary>
            /// <param name="cipherText">The ciphertext to be decrypted.</param>
            /// <param name="key">The key used for decryption.</param>
            /// <returns>The plaintext obtained after decryption.</returns>

            // [0] Convert To binary
            string binaryCipher = ConvertHexToBinary(cipherText);
            string binaryKey = ConvertHexToBinary(key);

            // [1] Initial Permutaiton 
            string permuted = InitialPermutaiton(binaryCipher);

            // [2] Prepare the 16 roundKeys
            List<string> roundKeys = GenerateRoundKeys(binaryKey);

            // [3] Apply the 16 rounds with the 16 keys [BUT] in the INVERSE order ! 
            // This is the input for each round, at the first round, the PC-1 is the input, then the output of a round is the input for the next one.
            string roundInput = permuted;
            string roundOutput = "";
            for (int i = 15; i >= 0; i--)
            {
                roundOutput = Round(roundInput, roundKeys[i]);
                // Setting the input for the next round, which is the previous round output.
                roundInput = roundOutput;
            }
            // Catching the output after the 16 rounds.
            string outputOf16Rounds = roundOutput;

            //[4] Swap the two 32-bit blocks of the output
            string L_output = outputOf16Rounds.Substring(0, 32);
            string R_output = outputOf16Rounds.Substring(32);

            StringBuilder swapped = new StringBuilder();
            swapped.Append(R_output);
            swapped.Append(L_output);

            // [5] Apply the final permutation
            string cipheredBlock = FinalPermutation(swapped.ToString());

            return "0x" + ConvertBinaryToHex(cipheredBlock);
        }
        
        #region Helper Functions
        static string ConvertHexToBinary(string hex)
        {
            /// <summary>
            /// Converts a hexadecimal string to a binary string.
            /// </summary>
            /// <param name="hex">The hexadecimal string to be converted.</param>
            /// <returns>The binary representation of the hexadecimal string.</returns>

            // Remove the '0x' prefix if present
            hex = hex.Substring(2);

            StringBuilder binaryString = new StringBuilder();

            foreach (char d in hex)
            {
                // Map each digit to its binary representation
                string binary = Convert.ToString(Convert.ToInt32(d.ToString(), 16), 2);

                // Ensure that each digit is represented in 4-bits
                binary = binary.PadLeft(4, '0');
                binaryString.Append(binary);
            }

            // Ensure that the returned binary string is divisible by 64
            if ((binaryString.Length % 64) != 0)
            {
                int zerosToBePadded = 64 - (binaryString.Length % 64);
                for (int i = 0; i < zerosToBePadded; i++)
                {
                    binaryString.Append('0');
                }
            }

            return binaryString.ToString();
        }
        static string ConvertBinaryToHex(string binary)
        {
            /// <summary>
            /// Converts a binary string to a hexadecimal string.
            /// </summary>
            /// <param name="binary">The binary string to be converted.</param>
            /// <returns>The hexadecimal representation of the binary string.</returns>

            StringBuilder hexString = new StringBuilder();

            // Map each 4-bit chunk to its hex representation
            for (int i = 0; i < binary.Length; i += 4)
            {
                string hexDigit = Convert.ToInt32(binary.Substring(i, 4), 2).ToString("X");
                hexString.Append(hexDigit);
            }

            return hexString.ToString();
        }
        static string XOR(string binary1, string binary2)
        {
            /// <summary>
            /// Performs a bitwise XOR operation between two binary strings.
            /// </summary>
            /// <param name="binary1">The first binary string.</param>
            /// <param name="binary2">The second binary string.</param>
            /// <returns>The result of the bitwise XOR operation.</returns>

            StringBuilder XORresult = new StringBuilder();
            for (int i = 0; i < binary1.Length; i++)
            {
                char bit1 = binary1[i];
                char bit2 = binary2[i];
                XORresult.Append(bit1 == bit2 ? '0' : '1');
            }

            return XORresult.ToString();
        }
        static string InitialPermutaiton(string plain64Bit)
        {
            /// <summary>
            /// The first step applied to the plainText while encryption, Performs the initial permutation step on the given block.
            /// </summary>
            /// <param name="plain64Bit">The 64-bit block of data to be permuted.</param>
            /// <returns>The 64-bit block after the initial permutation.</returns>
            StringBuilder permuted = new StringBuilder();
            for (int i = 0; i < 64; i++)
            {
                permuted.Append(plain64Bit[initialPermutationTable[i]]);
            }
            return permuted.ToString();
        }           
        static string PermutedChoice1(string key64Bit)
        {
            /// <summary>
            /// Performs the Permuted Choice 1 (PC-1) step on the given 64-bit key.
            /// </summary>
            /// <param name="key64Bit">The 64-bit key to be permuted.</param>
            /// <returns>The 56-bit key after the PC-1 step.</returns>
            StringBuilder permutedChoice1 = new StringBuilder();
            for (int i = 0; i < 56; i++)
            {
                permutedChoice1.Append(key64Bit[permutedChoice1Table[i]]);
            }
            return permutedChoice1.ToString();
        }
        static string LeftCircularShift(string key28Bit, int roundNum)
        {
            /// <summary>
            /// Performs the left circular shift (LS) on a 28-bit key segment based on the round number.
            /// </summary>
            /// <param name="key28Bit">The 28-bit key segment to be shifted.</param>
            /// <param name="roundNum">The round number for which the shift is being performed.</param>
            /// <returns>The 28-bit key segment after the left circular shift.</returns>
            string shifted;

            int[] roundsToShiftOnePos = { 1, 2, 9, 16 };
            if (Array.IndexOf(roundsToShiftOnePos, roundNum) != -1)
            {

                // Perform the left circular shift with one position
                shifted = key28Bit.Substring(1) + key28Bit.Substring(0, 1);

            }
            else
            {
                // Perform the left circular shift with two positions
                shifted = key28Bit.Substring(2) + key28Bit.Substring(0, 2);

            }
            return shifted.ToString();
        }
        static string PermutedChoice2(string key56Bit)
        {
            /// <summary>
            /// Performs the Permuted Choice 2 (PC-2) step on the given 56-bit key.
            /// </summary>
            /// <param name="key56Bit">The 56-bit key to be permuted.</param>
            /// <returns>The 48-bit round key after the Permuted Choice 2 step.</returns>
            StringBuilder roundKey = new StringBuilder();
            for (int i = 0; i < 48; i++)
            {
                roundKey.Append(key56Bit[permutedChoice2Table[i]]);
            }
            return roundKey.ToString();
        }
        static List<string> GenerateRoundKeys(string key64Bit)
        {
            /// <summary>
            /// Generates a list of round keys for use in the Data Encryption Standard (DES) algorithm based on the given 64-bit key.
            /// </summary>
            /// <param name="key64Bit">The 64-bit key from which the round keys are generated.</param>
            /// <returns>A list containing the generated round keys.</returns>

            // [1] Permuted Choice 1 (PC-1)
            string permuted = PermutedChoice1(key64Bit);

            // [2] Split the permuted key into C & D parts 28-bit each
            string C = permuted.Substring(0, 28);
            string D = permuted.Substring(28);

            // [3] Create a list to store all the generated roundkeys
            List<string> roundKeys = new List<string>();
            string roundKey;

            // [4] Apply the left circular shift and  PC-2 on each 28-bit key segement pair, for all the rounds
            for (int i = 1; i <= 16; i++)
            {
                // Left Circular Shift
                string C_shifted = LeftCircularShift(C, i);
                string D_shifted = LeftCircularShift(D, i);

                // Concat the C_shifted and D_shifted 
                StringBuilder shifted = new StringBuilder();
                shifted.Append(C_shifted);
                shifted.Append(D_shifted);

                // Apply the PC-2 to get the permuted and selected 48-bit key
                roundKey = PermutedChoice2(shifted.ToString());
                roundKeys.Add(roundKey);

                // Updating the C and D for generating the next round key
                C = C_shifted; D = D_shifted;
            }

            return roundKeys;
        }
        static string Round(string block64Bit, string roundKey)
        {
            /// <summary>
            /// Performs a single round on the given 64-bit plaintext using the provided round key.
            /// </summary>
            /// <param name="block64Bit">The 64-bit plaintext to be processed in the round.</param>
            /// <param name="roundKey">The 48-bit round key to be used in the round.</param>
            /// <returns>The 64-bit ciphertext after the round.</returns>

            StringBuilder output = new StringBuilder();

            // [1] Split the input to Left & Right parts, 32-bit each
            string L = block64Bit.Substring(0, 32);
            string R = block64Bit.Substring(32);

            // [2] Apply the funciton with the right side and the rondKey
            string functionResult = Function(R, roundKey);

            // [3] XoR the result with the left side and ensure that the result is 32-bit
            string newR = XOR(L, functionResult).PadLeft(32, '0');

            output.Append(R);
            output.Append(newR);

            return output.ToString();
        }
        static string Function(string right32Bit, string roundKey)
        {
            /// <summary>
            /// Applies the core function of a single round on the given 32-bit right side using the provided 48-bit round key.
            /// </summary>
            /// <param name="right32Bit">The 32-bit right side to be processed by the function.</param>
            /// <param name="roundKey">The 48-bit round key to be used in the function.</param>
            /// <returns>The result of applying the function, typically a 32-bit output.</returns>

            string result;
            // [1] Expansion of 32-bit right side to be 48-bit
            string expandedR = Expand(right32Bit);

            // [2] XoR the 48-bit roundKey with the expanded right side and ensure that the output is 48-bit
            string XoRResult = XOR(expandedR, roundKey).PadLeft(48, '0');

            // [3] S-boxes
            StringBuilder sBoxResult = new StringBuilder();
            for (int i = 0; i < XoRResult.Length; i += 6)
            {
                sBoxResult.Append(SBox(XoRResult.Substring(i, 6), (i / 6) + 1));
            }

            // [4] Permutation
            result = FunctionPermutation(sBoxResult.ToString());

            return result;
        }
        static string Expand(string input32Bit)
        {
            /// <summary>
            /// Expands a 32-bit input to a 48-bit output using the expansion table specified by the Data Encryption Standard (DES) algorithm.
            /// </summary>
            /// <param name="input32Bit">The 32-bit input to be expanded.</param>
            /// <returns>The expanded 48-bit output.</returns>

            StringBuilder result48Bit = new StringBuilder();
            for (int i = 0; i < 48; i++)
            {
                result48Bit.Append(input32Bit[expansionTable[i]]);
            }
            return result48Bit.ToString();
        }
        static string SBox(string input6Bit, int sboxNumber)
        {
            /// <summary>
            /// Performs substitution using the specified S-box based on the given 6-bit input and S-box number.
            /// </summary>
            /// <param name="input6Bit">The 6-bit input for substitution.</param>
            /// <param name="sboxNumber">The number of the S-box to be used (1 to 8).</param>
            /// <returns>The 4-bit output after substitution.</returns>

            string result4Bit = "";
            // [1] get the row number
            StringBuilder row = new StringBuilder();
            row.Append(input6Bit[0]);
            row.Append(input6Bit[input6Bit.Length - 1]);
            int rowNum = Convert.ToInt32(row.ToString(), 2);

            // [2] get the cloumn number
            string col = col = input6Bit.Substring(1, 4);

            int colNum = Convert.ToInt32(col, 2);

            // [3] index in the suitable s-box
            if (sboxNumber == 1)
            {
                result4Bit = Convert.ToString(sBox1[rowNum, colNum], 2).PadLeft(4, '0');
            }
            else if (sboxNumber == 2)
            {
                result4Bit = Convert.ToString(sBox2[rowNum, colNum], 2).PadLeft(4, '0');
            }
            else if (sboxNumber == 3)
            {
                result4Bit = Convert.ToString(sBox3[rowNum, colNum], 2).PadLeft(4, '0');
            }
            else if (sboxNumber == 4)
            {
                result4Bit = Convert.ToString(sBox4[rowNum, colNum], 2).PadLeft(4, '0');
            }
            else if (sboxNumber == 5)
            {
                result4Bit = Convert.ToString(sBox5[rowNum, colNum], 2).PadLeft(4, '0');
            }
            else if (sboxNumber == 6)
            {
                result4Bit = Convert.ToString(sBox6[rowNum, colNum], 2).PadLeft(4, '0');
            }
            else if (sboxNumber == 7)
            {
                result4Bit = Convert.ToString(sBox7[rowNum, colNum], 2).PadLeft(4, '0');
            }
            else if (sboxNumber == 8)
            {
                result4Bit = Convert.ToString(sBox8[rowNum, colNum], 2).PadLeft(4, '0');
            }

            return result4Bit;

        }
        static string FunctionPermutation(string input)
        {
            /// <summary>
            /// Permutes the 32-bit output comming form the s-box.
            /// </summary>
            /// <param name="input">The 32-bit input to be permuted.</param>
            /// <returns>The permuted output.</returns>

            StringBuilder permuted = new StringBuilder();
            for (int i = 0; i < 32; i++)
            {
                permuted.Append(input[permutationBox[i]]);
            }
            return permuted.ToString();
        }
        static string FinalPermutation(string input)
        {
            /// <summary>
            /// Performs the final permutation on the input according to the Data Encryption Standard (DES) algorithm.
            /// </summary>
            /// <param name="input">The input string to be permuted.</param>
            /// <returns>The result of the final permutation.</returns>

            StringBuilder permuted = new StringBuilder();
            for (int i = 0; i < 64; i++)
            {
                permuted.Append(input[finalPermutationTable[i]]);
            }
            return permuted.ToString();
        }
        #endregion
    }
}
