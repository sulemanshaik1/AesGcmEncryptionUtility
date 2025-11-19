using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Aes256GcmEncryption
{
    public static class AesGcmEncryption
    {
        public static byte[] Encrypt(string plaintext, byte[] key, byte[] iv, byte[] tag)
        {
            //iv = new byte[12]; // Recommended IV size for GCM
            //new SecureRandom().NextBytes(iv);

            byte[] input = Encoding.UTF8.GetBytes(plaintext);

            GcmBlockCipher cipher = new GcmBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine());
            AeadParameters parameters = new AeadParameters(new KeyParameter(key), 128, iv); // 128-bit tag
            cipher.Init(true, parameters);

            byte[] output = new byte[cipher.GetOutputSize(input.Length)];
            int len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            cipher.DoFinal(output, len);

            byte[] ciphertext = new byte[output.Length - tag.Length];

            Array.Copy(output, 0, ciphertext, 0, ciphertext.Length);
            Array.Copy(output, ciphertext.Length, tag, 0, tag.Length);

            return ciphertext;
        }

        public static string Decrypt(byte[] ciphertext, byte[] key, byte[] iv, byte[] tag)
        {
            byte[] combined = new byte[ciphertext.Length + tag.Length];
            Array.Copy(ciphertext, 0, combined, 0, ciphertext.Length);
            Array.Copy(tag, 0, combined, ciphertext.Length, tag.Length);

            GcmBlockCipher cipher = new GcmBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine());
            AeadParameters parameters = new AeadParameters(new KeyParameter(key), 128, iv);
            cipher.Init(false, parameters);

            byte[] output = new byte[cipher.GetOutputSize(combined.Length)];
            int len = cipher.ProcessBytes(combined, 0, combined.Length, output, 0);
            len += cipher.DoFinal(output, len);

            return Encoding.UTF8.GetString(output, 0, len);
        }

        public static string GenerateRandom32ByteKey()
        {
            byte[] aesKey = new byte[32];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(aesKey);
            }
            string base64Key = Convert.ToBase64String(aesKey);
            return base64Key;
        }

        public static void PrintKeyLength(string random32ByteBase64Key)
        {
            byte[] sharedKey = Convert.FromBase64String(random32ByteBase64Key);
            Console.WriteLine("Key Length in bytes :" + sharedKey.Length);
        }
        public static string ConvertBase64Json(string ciphertextBase64, string iVBase64, string tagBase64)
        {
            var payload = new AesGcmPayload
            {
                Ciphertext = ciphertextBase64,
                IV = iVBase64,
                Tag = tagBase64
            };
            // Serialize to JSON and convert to Base64 string
            var serializer = Newtonsoft.Json.JsonConvert.SerializeObject(payload);
            string base64Json = Convert.ToBase64String(Encoding.UTF8.GetBytes(serializer));
            return base64Json;
        }
        public static AesGcmPayload ConvertAesGcmModelFromBase64Json(string base64Json)
        {
            string json = Encoding.UTF8.GetString(Convert.FromBase64String(base64Json));
            var payload = Newtonsoft.Json.JsonConvert.DeserializeObject<AesGcmPayload>(json);
            return payload;
        }
    }
}