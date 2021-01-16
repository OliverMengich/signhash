using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
namespace SignHash
{
    class Program
    {
        public static ASCIIEncoding aSCII ;
        static void Main(string[] args)
        {
            try
            {
                // Create a UnicodeEncoder to convert between byte array and string.
                 aSCII = new ASCIIEncoding();
                Console.WriteLine("Enter String");
                string input = Console.ReadLine();

                // Create byte arrays to hold original, encrypted, and decrypted data.
                byte[] data = aSCII.GetBytes(input);
                string signedData;

                // Create a new instance of the RSACryptoServiceProvider class
                // and automatically create a new key-pair.
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

                // Export the key information to an RSAParameters object.
                // You must pass true to export the private key for signing.
                // However, you do not need to export the private key
                // for verification.
                RSAParameters Key = RSAalg.ExportParameters(true);

                // Hash and sign the data.
                signedData = HashAndSignBytes(data, Key);
                Console.WriteLine(signedData);
                var x = Encoding.UTF8.GetBytes(signedData);
                // Verify the data and display the result to the
                // console.
                if (VerifySignedHash(data, x, Key))
                {
                    Console.WriteLine("The data was verified.");
                }
                else
                {
                    Console.WriteLine("The data does not match the signature.");
                }
            }
            catch (ArgumentNullException)
            {
                Console.WriteLine("The data was not signed or verified");
            }
            Console.ReadKey();
        }
        public static string HashAndSignBytes(byte[] DataToSign, RSAParameters Key)
        {
            try
            {
                
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

                RSAalg.ImportParameters(Key);

                var s = RSAalg.SignData(DataToSign, SHA256.Create());
                var x = Encoding.UTF8.GetString(s);
                return x;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }
        }
        public static bool VerifySignedHash(byte[] DataToVerify, byte[] SignedData, RSAParameters Key)
        {
            try
            {
                // Create a new instance of RSACryptoServiceProvider using the
                // key from RSAParameters.
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

                RSAalg.ImportParameters(Key);

                // Verify the data using the signature.  Pass a new instance of SHA256
                // to specify the hashing algorithm.
                return RSAalg.VerifyData(DataToVerify, SHA256.Create(), SignedData);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return false;
            }
        }
    }
}
