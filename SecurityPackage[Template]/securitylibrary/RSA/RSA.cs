using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int cipherText = 0;

            // [1] Compute n = p x q
            int n = p * q;

            // [2] Encrypt the Message by using the Squar-And-Multiply algorithm for getting the power under modulo n
            cipherText = SquareAndMultiplyAlgorithm((long)M, (long)e, (long)n);


            return cipherText;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int plainText = 0;

            // [1] Compute n = p x q
            int n = p * q;

            // [2] Compute ɸ(n) = (p -1)(q-1)
            int phi_n = (p - 1) * (q - 1);

            // [3] Compute d (private key) and this is the inverse of e
            // Using the Extended Euclidian Algorithm to get the inverse(e) under modulu ɸ(n)
            int d = GetMultiplicativeInverse(e, phi_n);

            // [4] Decrypt the Message by using the Squar-And-Multiply algorithm for getting the power under modulo n
            plainText = SquareAndMultiplyAlgorithm((long)C, (long)d, (long)n);

            return plainText;
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

    }
}
