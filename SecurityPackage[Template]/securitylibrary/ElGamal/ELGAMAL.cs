using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        /// 

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> cipherText = new List<long>();

            // [1] Compute the Ephemeral key (KE)
            long KE = SquareAndMultiplyAlgorithm((long)alpha, (long)k, (long)q);

            // [2] Compute the Masking key (KM)
            long KM = SquareAndMultiplyAlgorithm((long)y, (long)k, (long)q);

            // [3] Encrypting the message
            long cipher = (KM * m) % q;

            cipherText.Add(KE);
            cipherText.Add(cipher);

            return cipherText;
        }
     
        public int Decrypt(int c1, int c2, int x, int q)
        {
            int plainText = 0;

            // [1] Compute the masking key KM
            int KM = SquareAndMultiplyAlgorithm((long)c1, (long)x, (long)q);

            // [2] Compute the inverse of KM
            int KM_Inverse = GetMultiplicativeInverse(KM, q);

            // [3] Decrypting the ciphertext with the KM_Inverse
            plainText = (c2 * KM_Inverse) % q;

            return plainText;
        }

        public static int SquareAndMultiplyAlgorithm(long number, long exponent, long modulus)
        {
            /// <summary>
            /// Computes fast exponentiation using the Square-and-Multiply algorithm.
            /// </summary>
            /// <param name="number">The base number.</param>
            /// <param name="exponent">The exponent.</param>
            /// <param name="modulus">The modulus.</param>
            /// <returns>The result of baseNum raised to the power of exponent modulo modulus.</returns>

            // Initialize the result to 1
            int result = 1;

            // Loop until the exponent becomes 0
            while (exponent > 0)
            {
                // If the current bit (LSP) of the exponent is 1
                if (exponent % 2 == 1)
                {
                    // [Multiply] the result by the base and take modulus
                    result = (int)((result * number) % modulus);
                }

                // [Square] the base and take modulus
                number = (number * number) % modulus;

                // Divide the exponent by 2 (right shift) (drop LSP)
                exponent = exponent / 2;


            }

            // Return the final result
            return result;
        }

        public int GetMultiplicativeInverse(int number, int baseN)
        {
            (int gcd, int inverse) = ExtendedEuclidean(0, 1, 0, baseN, 0, 1, number, baseN);

            return inverse;
        }


        public int Mod(int number, int baseN)
        {
            if (number >= 0) return number % baseN;
            else return (number % baseN) + baseN;
        }

        public (int, int) ExtendedEuclidean(int Q, int A1, int A2, int A3, int B1, int B2, int B3, int baseN)
        {
            // This recursive function implements the Extended Euclidean Algorithm that calculates
            // the GCD and the Inverse of A under the mod of B, in our case, we are dealing under mod 26.


            // Base cases
            // Check if B3 is zero so that there will be a multiplicative inverse
            if (B3 == 0)
            {
                return (A3, -1);
            }
            else if (B3 == 1)
            {
                int gcd = A3;

                int inverse = Mod(B2, baseN);
                return (gcd, inverse);
            }
            else
            {
                int newQ = A3 / B3;
                int newA1 = B1;
                int newA2 = B2;
                int newA3 = B3;
                int newB1 = A1 - (newQ * B1);
                int newB2 = A2 - (newQ * B2);
                int newB3 = A3 - (newQ * B3);


                return ExtendedEuclidean(newQ, newA1, newA2, newA3, newB1, newB2, newB3, baseN);
            }

        }


    }
}
