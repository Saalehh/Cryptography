using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {

        List<char> alphabet = new List<char> { 'A', 'B', 'C', 'D',
                                               'E', 'F', 'G', 'H',
                                               'I', 'J', 'K', 'L',
                                               'M', 'N', 'O', 'P',
                                               'Q', 'R', 'S', 'T',
                                               'U', 'V', 'W', 'X',
                                               'Y', 'Z' };


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {

            List<int> cipherText = new List<int>();


            //[1] Calculate the key dimensions
            // Asuming the Key is NxN matrix given in the for of a list of integers
            int N = SquareRoot(key.Count);

            //[2] C = P*K mod 26
            cipherText = MatrixMatrixMultiplicationMod26(plainText, key, N);

            return cipherText;
        }

        public string Encrypt(string plainText, string key)
        {
            List<int> encodedPlainText = EncodeText(plainText);
            List<int> enodedKey = EncodeText(key);


            List<int> cipherText = Encrypt(encodedPlainText, enodedKey);
            return DecodeText(cipherText);
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            if (!IsKeyValid(key)) throw new InvalidAnlysisException();

            List<int> plainText = new List<int>();

            //[1] Calculate the key dimensions
            // Asuming the Key is NxN matrix given in the for of a list of integers
            int N = SquareRoot(key.Count);

            //[2] Calculating the inverse matrix of the key 
            List<int> keyInverse = new List<int>();
            keyInverse = InverseNXN(key);

            //[3] P = C*K^-1 mod 26
            plainText = MatrixMatrixMultiplicationMod26(cipherText, keyInverse, N);
            return plainText;
        }

        public string Decrypt(string cipherText, string key)
        {
            List<int> encodedcipherText = EncodeText(cipherText);
            List<int> enodedKey = EncodeText(key);


            List<int> plainText = Decrypt(encodedcipherText, enodedKey);
            return DecodeText(plainText);
        }

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> key;

            // In the case of key is 2X2 we can try all the compinations of keys
            // and try to encrypt the plain text with it,
            // if we go the same cipher text, so that is key used in the encryption process
            for (int a = 0; a < 26; a++)
            {
                for (int b = 0; b < 26; b++)
                {
                    for (int c = 0; c < 26; c++)
                    {
                        for (int d = 0; d < 26; d++)
                        {
                            // Generating a key of a new compination each iteration
                             key = new List<int>() { a, b, c, d };
                            // Encrypting the plain text with this key and 
                            List<int> encrypted = Encrypt(plainText, key);
                            // compare the encrypted text using the new key, with the original cipher
                            bool areSame = true; // Assume they are the same until proven otherwise
                            for (int i = 0; i < cipherText.Count; i++)
                            {
                                if (encrypted[i] != cipherText[i])
                                {
                                    areSame = false; // If any character is different, set flag to false
                                    break; // No need to continue checking, we already know they're different
                                }
                            }

                            if (areSame) return key;

                        }
                    }
                }
            }
            throw new InvalidAnlysisException();
        }


        public string Analyse(string plainText, string cipherText)
        {
            
            List<int> encodedPlainText = EncodeText(plainText);
            List<int> encodedcipherText = EncodeText(cipherText);


            List<int> key = Analyse(encodedPlainText, encodedcipherText);
            return DecodeText(key);
        }



        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {

            List<int> key = new List<int>();
            // This function is resposible for analyzing Hill cipher generated throgh 2x2 Key matrix

            // We know that:
            // C = P * K      --> 1
            // P = C * c^-1   --> 2

            // We have P and C so to get K:
            // K = C * P^-1

            //[1] Getting the inverse for the plainText Matrix
            List<int> plainTextInverse = InverseNXN(plain3);
            

            key = MatrixMatrixMultiplicationMod26(Transpose(cipher3), plainTextInverse, 3);

            return key;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
           
            List<int> encodedPlainText = EncodeText(plain3);
            List<int> encodedcipherText = EncodeText(cipher3);


            List<int> key = Analyse(encodedPlainText, encodedcipherText);
            return DecodeText(key);
        }



        public int SquareRoot(int number)
        {
            if (number < 0)
            {
                throw new ArgumentException("Input must be non-negative.");
            }

            if (number == 0 || number == 1)
            {
                return number;
            }

            int start = 1;
            int end = number;
            int result = 0;

            while (start <= end)
            {
                int mid = start + (end - start) / 2; // Note that this returns interger not a float number
                int square = mid * mid;

                if (square == number)
                {
                    return mid;
                }
                else if (square < number)
                {
                    start = mid + 1;
                    result = mid; // Update result if mid*mid is less than or equal to number
                }
                else
                {
                    end = mid - 1;
                }
            }

            return result;
        }

        public bool IsKeyValid(List<int> key)
        {

            // The key is invalid if:
            //[1] If it is not a square matrix
            int N = SquareRoot(key.Count);
            if (key.Count % N != 0) //The key is not square matrix
                return false;
           

            //[2] If The determinant of the key matrix and 26 are not relatively prime.
            (int gcd, _) = ExtendedEuclidean(DetNXN(key), 26, 0, 1);
            if (gcd != 1) // not relatively prime with 26
                return false;

            return true;
        }

        public int Mod26(int number)
        {
            if (number >= 0) return number % 26;
            else return (number % 26) + 26;
        }

        public List<int> EncodeText(string text)
        {
            text = text.ToUpper();
            List<int> encodedAlphabet = new List<int>();

            foreach (char letter in text)
            {
                encodedAlphabet.Add(alphabet.IndexOf(letter));
            }
            return encodedAlphabet;
        }

        public string DecodeText(List<int> enccodedText)
        {
            string decodedAlphabet = "";

            foreach (int number in enccodedText)
            {
                decodedAlphabet += alphabet[number];
            }
            return decodedAlphabet;
        }

        public List<int> Transpose(List<int> matrix)
        {
            int N = SquareRoot(matrix.Count);
            int textIndex = 0;
            List<int> transpose = new List<int>();
            for (int i = 0; i < N; i++)
                for (int j = 0; j < N; j++)                
                     transpose.Add(matrix[i+(j*N)]);
            

            return transpose;
        }

        public List<int> MatrixVectorMultiplication(List<int> lettersVector, List<int> key)
        {
            List<int> result = new List<int>();
            int N = lettersVector.Count;
            // Applying multiplicatoin of 1xN encoded letters vector with NxN key matrix
            // C = P*K mod 26, so the task of this function is to return (P*K)
            for (int i = 0; i < N; i++)
            {
                int valueToBeAdded = 0;
                for (int j = 0; j < N; j++)
                {
                    if (i == 0) // if this is the first iteration
                    {
                        valueToBeAdded += (lettersVector[j] * key[j]);
                    }
                    else
                    {
                        valueToBeAdded += (lettersVector[j] * key[j+(i*N)]);
                    }
                }
                result.Add(valueToBeAdded);
            }
            
            return result;
        }

        public List<int> MatrixMatrixMultiplicationMod26(List<int> matrix1, List<int> matrix2, int N)
        {
            //Check that these two matrixes can be multiplied to each other
            // Getting the dimensions of matrix2, that matrix2 is a square matrix of MXM dimensions
            //We need to verify that N = M
            int M = SquareRoot(matrix2.Count);
            if (N != M) throw new Exception("These Two Matrixes Cannot Be Multipled Together");

            // Result should be (matrix1 * matrix2) mod 26
            List<int> result = new List<int>();

            // N : specifies the length of the vector that we will divid matrix1 to vectors with 1xN dimension

            //For each N elements as a 1xN vector in the matrix1 Apply matrix multiplication between them and matrix2.

            int index = 0; // To track the index of matrix1.
            for (int i = 0; i < matrix1.Count; i += N)
            {
                List<int> vector = new List<int>();
                for (int j = 0; j < N; j++)
                {
                    vector.Add(matrix1[index]);
                    index++;
                }

                List<int> multiplicationResult = MatrixVectorMultiplication(vector, matrix2);
                foreach (int number in multiplicationResult) { result.Add(Mod26(number)); }
            }

            return result;
        }

        public List<int> MatrixMatrixMultiplication(List<int> matrix1, List<int> matrix2, int N)
        {
            //Check that these two matrixes can be multiplied to each other
            // Getting the dimensions of matrix2, that matrix2 is a square matrix of MXM dimensions
            //We need to verify that N = M
            int M = SquareRoot(matrix2.Count);
            if (N != M) throw new Exception("These Two Matrixes Cannot Be Multipled Together");

            // Result should be (matrix1 * matrix2) mod 26
            List<int> result = new List<int>();

            // N : specifies the length of the vector that we will divid matrix1 to vectors with 1xN dimension

            //For each N elements as a 1xN vector in the matrix1 Apply matrix multiplication between them and matrix2.

            int index = 0; // To track the index of matrix1.
            for (int i = 0; i < matrix1.Count; i += N)
            {
                List<int> vector = new List<int>();
                for (int j = 0; j < N; j++)
                {
                    vector.Add(matrix1[index]);
                    index++;
                }

                List<int> multiplicationResult = MatrixVectorMultiplication(vector, matrix2);
                foreach (int number in multiplicationResult) { result.Add(number); }
            }

            return result;
        }


        public List<int> ScalarProduct(List<int> matrix, int multiplier)
        {
            // Multiply each element in the list with the multiplier
            for (int i = 0; i < matrix.Count; i++)
            {
                matrix[i] = Mod26(matrix[i] * multiplier);
            }

            return matrix;
        }

        public int Det2X2(List<int> matrix)
        {
            // Let matrix A = |a b|
            //                |c d|  
            // The determinant of A is given by the formula: det(A) = ad - bc

            return (matrix[0] * matrix[3]) - (matrix[1] * matrix[2]);
        }
        
        public List<int> Inverse2X2(List<int> matrix)
        {
            // Let matrix A = |a b|
            //                |c d|  
            // The inverse of A is given by the formula: 1/det(A) |d -b|
            //                                                    |-c a|

            // getting the determinent
            int det = Det2X2(matrix);
            List<int> inverse;

            // checking that the matrix is inversable
            if (det != 0)
            {                                 //     d              -b              -c              a  
                inverse = new List<int>() { matrix[3]/det, -matrix[1]/det,-matrix[2]/det, matrix[0]/det };
            }
            else throw new ArgumentException("The given matrix is irreversable.");


            return inverse;
        }
       
        public List<int> Minor(List<int> matrix, int index) 
        {
            int N = SquareRoot(matrix.Count);
            List<int> subMatrix = new List<int>();
            // This function takes an NXN matrix and an index for the element that we need to cancel its row and column
            // and returns the remaining elements (minor) as a submatrix.
            for (int i = 0; i < matrix.Count; i++)
            {
                // Check if this column should be neglected
                if (i == index)
                {
                    i += N; // neglect from a --> a+N elements (the column of target element)
                    continue;
                }
                else if(i % N == 0) // if the index element is divisable by N so it belongs to the row to be neglected
                {
                    continue;
                }
                else
                {
                    subMatrix.Add(matrix[i]);
                }
            }

            return subMatrix;
        }

        public int DetNXN(List<int> matrix)
        {
            // This functions is a recursive function that is responsible for
            // calculating the determinant of an NXN matrix.

            int N = SquareRoot(matrix.Count);
            // Base Case is when the matrix is a 2X2 matrix
            if (N == 2) return Det2X2(matrix);
            
            //                                  
            // Let matrix A is an NXN matrix:   
            /*
                   +   -   +  -  +\- accoridng to N if it is even or odd
                 |a00 a01 a02... a0n|
                 |a10 a11 a12... a1n|
                 |.        ...     .|
           A =   |.        ...     .|
                 |.        ...     .|
                 |an0      ...   ann|

             */

            // det(A) = a00 * det(A00) - a01 * det(A01) + a02 * det(A02) ..... a0n * det(A0n)
            int det = 0;
            bool sign = true; // will be used to handle changin the sign each iteration
                              // True : +ve , False : -ve

            for (int i = 0; i < matrix.Count; i+=N)
            {
                if (sign)
                {
                    det += (matrix[i] * DetNXN(Minor(matrix, i)));
                }
                else
                {
                    det -= (matrix[i] * DetNXN(Minor(matrix, i)));

                }

                sign = !sign;  // Change the sign each iteration, to used in the next one.
            }

            return det;
        }

        public List<int> Duplicate2ColumnsAnd2Rows(List<int> matrix)
        {
            // This function is responsible for duplicating two columns and rows in a given matrix
            // to use them in calculating the Adjoint of it.

            //[1] Duplicating the first two columns of a given matrix and puts them to the right of it
            List<int> duplicated = new List<int>();

            // Assuming that it is an NXN matrix
            int N = (int)Math.Sqrt(matrix.Count);

            // We need to duplicate the first two columns
            List<int> first2Columns = matrix.GetRange(0, 2 * N);

            // Append the first two columns to the end of the matrix
            matrix.AddRange(first2Columns);

            // Add the duplicated elements to the 'duplicated' list
            duplicated.AddRange(matrix);


            //[2]Duplicating the first two rows of a given matrix and puts them to the button of it
            
            // The size of the matrix after duplicating it should be:
            int dimentionOfDumplicatedMatrix = N + 2;

            int insersionIndex;  //The position at which start inseting the values of the first and second rows
            int indexOfValueToBeInserted;

            for (int i = 0; i < dimentionOfDumplicatedMatrix; i++)
            {
                insersionIndex = N + (i * dimentionOfDumplicatedMatrix);
                indexOfValueToBeInserted = insersionIndex - N;
                duplicated.Insert(insersionIndex, duplicated[indexOfValueToBeInserted]);
                duplicated.Insert(insersionIndex+1, duplicated[indexOfValueToBeInserted+1]);
            }


            return duplicated;
        }  
        
        public List<int> Adjoint(List<int> matrix)
        {
            // This function calculates the adjoint of a given matrix
            //[1] Duplicate first two columns and rows of the given matrix
            matrix = Duplicate2ColumnsAnd2Rows(matrix);

            //[2] Remove the first column and row for the duplicated matrix
            matrix = Minor(matrix, 0);

            // Getting the dimention of the resulted matrix
            int N = SquareRoot(matrix.Count);

            //[3] Calculating the adjoint using the matrix after the two previous operations
            List<int> adjoint = new List<int>();

            // Applying 2X2 determinant calculation on each 4 elements in the matrix
            for (int i = 0; i < (N - 1); i++)
            {
                for (int j = 0; j < (N - 1); j++)
                {
                    int index00 = i + (j * N);
                    int index01 = i + ((j + 1) * N);
                    List<int> minorDeterminant = new List<int>() { matrix[index00],
                                                                   matrix[index00+1],
                                                                   matrix[index01],
                                                                   matrix[index01+1]
                                                                  };

                    adjoint.Add(Mod26(Det2X2(minorDeterminant)));
                }
            }

            return adjoint;
        }

        public (int, int) ExtendedEuclidean(int A, int B, int T1, int T2)
        {
            
            // Check if both A and B are zero
            if (A == 0 && B == 0)
            {
                throw new ArgumentException("Both A and B cannot be zero.");
            }

            // Handle negative inputs by taking absolute values
            A = Math.Abs(A);
            B = Math.Abs(B);

            // This recursive function implements the Extended Euclidean Algorithm that calculates
            // the GCD and the Inverse of A under the mod of B, in our case, we are dealing under mod 26.
            if (B > A) // Check that A is greater than B
            {
                int temp = B; B = A; A = temp;
            }

            // Base case
            if (B == 0)
            {
                int gcd = A;
                //if (gcd != 1) throw new Exception("This number do not have inverse under the given mod"); 
                int inverse = Mod26(T1);
                return (gcd, inverse);
            }
            else
            {
                int T = T1 - (T2 * (A / B));
                return ExtendedEuclidean(B, (A % B), T2, T);
            }
        }

        public List<int> InverseNXN(List<int> matrix)
        {
            List<int> inverse = new List<int>();
            //Calculating the inverse of the given matrix,
            //which is defined by: inverse(K) = 1/det(K) * adj(K)

            //Calculate the matrix dimensions
            // Asuming the matrix is NxN matrix given in the for of a list of integers
            int N = SquareRoot(matrix.Count);

            //Check if the given matrix is 2X2 matrix
            if (N == 2) return Inverse2X2(matrix);
            
            //[1] Calculating the modulus 26 for the determinant of K
            int det = Mod26(DetNXN(matrix));

            //[2] Caculating the inverse of the deteminant under the mod 26 using the Extended Euclidean Algorithm
            (_, int inverseDet) = ExtendedEuclidean(det, 26, 0, 1);

            //[3] Calculating the Ajoint of K
            List<int> adjoint = Adjoint(matrix);

            //[4] finally multiplying the inverse of the det with the adjoint matrix to get the inverse of the key
            inverse = ScalarProduct(adjoint, inverseDet);

            
            return inverse;
        }
    }
}