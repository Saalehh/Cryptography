using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
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
