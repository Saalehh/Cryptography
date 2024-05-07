using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary.DiffieHellman
{


    public class DiffieHellman
    {

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

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> keys= new List<int>();

             
            int A = SquareAndMultiplyAlgorithm(alpha, xa, q);
            int B = SquareAndMultiplyAlgorithm(alpha, xb, q);

            int KAB1 = SquareAndMultiplyAlgorithm(B, xa, q);
            int KAB2 = SquareAndMultiplyAlgorithm(A, xb, q);

            keys.Add(KAB1);
            keys.Add(KAB2);

            return keys;
        }
    }
}