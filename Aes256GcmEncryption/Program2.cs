using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Aes256GcmEncryption
{
    internal class Program2
    {
        static void Main(string[] args)
        {
            string plaintext = "password@123PASS82748278728978978973298738902983832098390820830928903802803802830238083";
            byte[] key = Encoding.UTF8.GetBytes("12345678901234567890123456789012"); // 32-byte key
            var encrptedbase64String = AesGcmEncryptionUtility.Encrypt(plaintext, key);
            Console.WriteLine(encrptedbase64String);
            var decryptedString = AesGcmEncryptionUtility.Decrypt(encrptedbase64String, key);
            Console.WriteLine(decryptedString);
        }
    }
}
