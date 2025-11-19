using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Aes256GcmEncryption
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            string plaintext = "password@123PASS1234567890";
            byte[] key = Encoding.UTF8.GetBytes("12345678901234567890123456789012"); // 32-byte key
            byte[] iv = new byte[12];  // Recommended IV size for GCM (12-byte -> 96-bit(12*8))
            byte[] tag = new byte[16]; // Recommended tag size for GCM (16-byte -> 128-bit(16*8))

            //Recommended to generate IV randomly and share to decryption application
            new SecureRandom().NextBytes(iv);

            Console.WriteLine("Plaintext: " + plaintext);

            // Encrypt
            var encrypted = AesGcmEncryption.Encrypt(plaintext, key, iv, tag);

            Console.WriteLine("Ciphertext (Base64): " + Convert.ToBase64String(encrypted));
            Console.WriteLine("IV (Base64): " + Convert.ToBase64String(iv));
            Console.WriteLine("Tag (Base64): " + Convert.ToBase64String(tag));


            #region TamperDataTest

            // Tamparing data test
            //byte[] plainTextTampered = Encoding.UTF8.GetBytes("password@123PASSWORDpassword@123PASSWORDpassword@123PASSWORDpassword@123PASSWORDpassword@123PASSWORDpassword@123PASSWORDpassword@123PASSWORDTamp");
            //byte[] key2 = Encoding.UTF8.GetBytes("12345678901234567890123456789012");
            //byte[] iv2 = new byte[12];
            //new SecureRandom().NextBytes(iv2);

            #endregion TamperDataTest

            #region ConverstionToModelTest
            string base64Json = AesGcmEncryption.ConvertBase64Json(Convert.ToBase64String(encrypted), Convert.ToBase64String(iv), Convert.ToBase64String(tag));
            var model = AesGcmEncryption.ConvertAesGcmModelFromBase64Json(base64Json);
            #endregion

            // Decrypt
            string decrypted = AesGcmEncryption.Decrypt(encrypted, key, iv, tag);

            Console.WriteLine("Decrypted: " + decrypted);
        }
    }

}