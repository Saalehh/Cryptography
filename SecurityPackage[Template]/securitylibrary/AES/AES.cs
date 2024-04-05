using System;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        private readonly byte[] sBox = new byte[]
        {
                0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
                0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
                0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
                0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
                0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
                0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
                0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
                0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
                0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
                0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
                0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
                0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
                0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
                0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
                0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
                0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        };

        private readonly byte[] mixColumnsMatrix = new byte[16]
        {
            0x02, 0x03, 0x01, 0x01,
            0x01, 0x02, 0x03, 0x01,
            0x01, 0x01, 0x02, 0x03,
            0x03, 0x01, 0x01, 0x02
        };

        private string RconMatrix = "01000000020000000400000008000000100000002000000040000000800000001B00000036000000";

        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }
        public override string Encrypt(string plainText, string key)
        {
            plainText = plainText.Substring(2);
            key = key.Substring(2);
            // Rotating The matrix and the key
            string newPlainText = "";
            for (int i = 0; i < 8; i += 2)
            {
                newPlainText += plainText.Substring(i, 2);
                newPlainText += plainText.Substring(i + 8, 2);
                newPlainText += plainText.Substring(i + 16, 2);
                newPlainText += plainText.Substring(i + 24, 2);
            }
            Console.WriteLine(newPlainText);

            string newKey = "";
            for (int i = 0; i < 8; i += 2)
            {
                newKey += key.Substring(i, 2);
                newKey += key.Substring(i + 8, 2);
                newKey += key.Substring(i + 16, 2);
                newKey += key.Substring(i + 24, 2);
            }
            Console.WriteLine(newKey);

            // Previous key used in Key Schedule step
            string previousKey = newKey;

            // Initial Round
            string state = AddRoundKey(newPlainText, newKey);
            Console.WriteLine(state);
            Console.WriteLine("-------------------------------");

            // Main Rounds
            for (int i = 0; i < 9; i++)
            {
                // Substitute bytes
                string subBytesResult = SubBytes(state);
                Console.WriteLine(subBytesResult);
                // Shift Rows
                string shiftRowsResult = ShiftRows(subBytesResult);
                Console.WriteLine(shiftRowsResult);
                // Mix Columns
                string mixColumnsResult = MixColumns(shiftRowsResult);
                Console.WriteLine(mixColumnsResult);
                // Key Scedule
                string keySceduleResult = KeySchedule(previousKey, i);
                previousKey = keySceduleResult;
                Console.WriteLine(keySceduleResult);
                // AddRoundKey
                string addRoundKeyResult = AddRoundKey(mixColumnsResult, keySceduleResult);
                state = addRoundKeyResult;
                Console.WriteLine("-------------------------------");
                Console.WriteLine(addRoundKeyResult);
            }
            // Final Round
            string finalRoundSubBytesResult = SubBytes(state);
            Console.WriteLine(finalRoundSubBytesResult);
            string finalRoundshiftRowsResult = ShiftRows(finalRoundSubBytesResult);
            Console.WriteLine(finalRoundshiftRowsResult);
            string finalRoundkeySceduleResult = KeySchedule(previousKey, 9);
            Console.WriteLine(finalRoundkeySceduleResult);
            string finalRoundAddRoundKeyResult = AddRoundKey(finalRoundshiftRowsResult, finalRoundkeySceduleResult);
            Console.WriteLine(finalRoundAddRoundKeyResult);

            // Rotate the cipher text back
            string cipherText = "";
            for (int i = 0; i < 8; i += 2)
            {
                cipherText += finalRoundAddRoundKeyResult.Substring(i, 2);
                cipherText += finalRoundAddRoundKeyResult.Substring(i + 8, 2);
                cipherText += finalRoundAddRoundKeyResult.Substring(i + 16, 2);
                cipherText += finalRoundAddRoundKeyResult.Substring(i + 24, 2);
            }
            return "0x" + cipherText;
        }
        private string AddRoundKey(string plainText, string cipherKey)
        {
            string result = "";
            for (int i = 0; i < plainText.Length; i += 2)
            {
                int plainTextCell = Convert.ToInt32(plainText.Substring(i, 2), 16);
                int cipherKeyCell = Convert.ToInt32(cipherKey.Substring(i, 2), 16);

                int xorResult = plainTextCell ^ cipherKeyCell;

                result += xorResult.ToString("X2");
            }
            return result;
        }
        private string SubBytes(string state)
        {
            byte[] cells = new byte[state.Length / 2];
            for (int i = 0; i < state.Length / 2; i++)
            {
                cells[i] = Convert.ToByte(state.Substring(2 * i, 2), 16);
            }

            // Perform SubBytes operation
            for (int i = 0; i < state.Length / 2; i++)
            {
                cells[i] = sBox[cells[i]];
            }

            // Convert byte array back to string
            string output = BitConverter.ToString(cells).Replace("-", "");

            return output;
        }
        private string ShiftRows(string state)
        {
            string shiftedState = "";

            for (int row = 0; row < 4; row++)
            {
                string rowState = state.Substring(row * 8, 8);
                string shiftedRow = rowState.Substring(row * 2) + rowState.Substring(0, row * 2);
                shiftedState += shiftedRow;
            }

            return shiftedState;
        }
        private string MixColumns(string state)
        {
            // Getting the MixColumns matrix by rows not columns like the lec
            string result = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    byte a0 = Convert.ToByte(state.Substring(j * 2, 2), 16);
                    byte a1 = Convert.ToByte(state.Substring(j * 2 + 8, 2), 16);
                    byte a2 = Convert.ToByte(state.Substring(j * 2 + 16, 2), 16);
                    byte a3 = Convert.ToByte(state.Substring(j * 2 + 24, 2), 16);

                    byte multipliedCell = (byte)(GFMultiply(mixColumnsMatrix[0 + i * 4], a0) ^
                                                    GFMultiply(mixColumnsMatrix[1 + i * 4], a1) ^
                                                    GFMultiply(mixColumnsMatrix[2 + i * 4], a2) ^
                                                    GFMultiply(mixColumnsMatrix[3 + i * 4], a3));

                    result += multipliedCell.ToString("X2");
                }
            }
            return result;
        }
        private byte GFMultiply(byte a, byte b)
        {

            byte p = 0;
            byte mask = 0x01; // Mask for checking each bit of b
            for (int i = 0; i < 8; i++)
            {
                if ((b & mask) != 0) // Check if the current bit of b is set
                {
                    p ^= a; // If set, XOR a with p
                }
                byte highBit = (byte)(a & 0x80); // Check if the high bit of a is 0
                a <<= 1; // Left shift a
                if (highBit != 0) // If the high bit was 1, perform reduction
                {
                    a ^= 0x1B; // XOR with irreducible polynomial
                }
                mask <<= 1; // Shift the mask to the left for the next bit of b
            }
            return p;
        }
        private string KeySchedule(string key, int roundNumber)
        {
            // 10000111
            // 00101010
            // 10101101
            string c1 = "", c2 = "", c3 = "", c4 = "";
            for (int i = 0; i < 32; i += 8)
            {
                c1 += (key[i]);
                c1 += (key[i + 1]);
                c2 += (key[i + 2]);
                c2 += (key[i + 3]);
                c3 += (key[i + 4]);
                c3 += (key[i + 5]);
                c4 += (key[i + 6]);
                c4 += (key[i + 7]);
            }
            // Rotate the last column
            string tmp = RotateWord(c4);
            // Applying Subbytes to the last column
            tmp = SubBytes(tmp);
            // Doing XOR between first, last and racon columns
            string tmp1 = AddRoundKey(c1, tmp);
            tmp1 = AddRoundKey(tmp1, RconMatrix.Substring(roundNumber * 8, 8));
            // Getting the new key
            c1 = tmp1;
            c2 = AddRoundKey(c1, c2);
            c3 = AddRoundKey(c2, c3);
            c4 = AddRoundKey(c3, c4);

            string resultString = "";
            for (int i = 0; i < c1.Length; i += 2)
            {
                resultString += c1.Substring(i, 2);
                resultString += c2.Substring(i, 2);
                resultString += c3.Substring(i, 2);
                resultString += c4.Substring(i, 2);
            }
            return resultString;
        }
        private string RotateWord(string key)
        {
            return key.Substring(2) + key[0] + key[1];
        }
    }
}
