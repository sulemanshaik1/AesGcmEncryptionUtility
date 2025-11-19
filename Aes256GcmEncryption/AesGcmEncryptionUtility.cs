using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Aes256GcmEncryption
{
    public static class AesGcmEncryptionUtility
    {
        private const int IvSize = 12; // 96-bit IV for GCM
        private const int TagSize = 16; // 128-bit tag for GCM
        private const int KeySize = 32; // 256-bit key

        /// <summary>
        /// Encrypts the plaintext using AES-256 GCM and returns a payload containing encrypted data
        /// </summary>
        /// <param name="plaintext">The text to encrypt</param>
        /// <param name="key">The encryption key (must be 32 bytes for AES-256)</param>
        /// <returns>Base64-encoded JSON string containing ciphertext, IV, and tag as Base64 strings</returns>
        /// <exception cref="ArgumentNullException">Thrown when plaintext or key is null</exception>
        /// <exception cref="ArgumentException">Thrown when key is not 32 bytes</exception>
        public static string Encrypt(string plaintext, byte[] key)
        {
            if (string.IsNullOrEmpty(plaintext))
                throw new ArgumentNullException(nameof(plaintext), "Plaintext cannot be null or empty");

            if (key == null)
                throw new ArgumentNullException(nameof(key), "Encryption key cannot be null");

            if (key.Length != KeySize)
                throw new ArgumentException($"Key must be {KeySize} bytes for AES-256, but was {key.Length} bytes", nameof(key));

            try
            {
                byte[] iv = new byte[IvSize];
                new SecureRandom().NextBytes(iv);

                byte[] tag = new byte[TagSize];
                byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

                GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
                AeadParameters parameters = new AeadParameters(new KeyParameter(key), TagSize * 8, iv);
                cipher.Init(true, parameters);

                byte[] output = new byte[cipher.GetOutputSize(plaintextBytes.Length)];
                int len = cipher.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, output, 0);
                len += cipher.DoFinal(output, len);

                // Split the output into ciphertext and tag
                byte[] ciphertext = new byte[output.Length - TagSize];
                Array.Copy(output, 0, ciphertext, 0, ciphertext.Length);
                Array.Copy(output, ciphertext.Length, tag, 0, TagSize);

                var payload= new AesGcmPayload
                {
                    Ciphertext = Convert.ToBase64String(ciphertext),
                    IV = Convert.ToBase64String(iv),
                    Tag = Convert.ToBase64String(tag)
                };
                var jsonBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(payload, Formatting.None));
                return Convert.ToBase64String(jsonBytes);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Encryption failed", ex);
            }
        }

        /// <summary>
        /// Decrypts the payload using AES-256 GCM
        /// </summary>
        /// <param name="base64JsonPayload">The encrypted payload containing ciphertext, IV, and tag</param>
        /// <param name="key">The decryption key (must be 32 bytes for AES-256)</param>
        /// <returns>The decrypted plaintext</returns>
        /// <exception cref="ArgumentNullException">Thrown when payload or key is null</exception>
        /// <exception cref="ArgumentException">Thrown when key is not 32 bytes or payload components are invalid</exception>
        /// <exception cref="JsonException">Thrown when invalid json trying to deserialize</exception>
        /// <exception cref="InvalidOperationException">Thrown when decryption fails (invalid tag, corrupted data, etc.)</exception>
        public static string Decrypt(string base64JsonPayload, byte[] key)
        {
            if (string.IsNullOrEmpty(base64JsonPayload))
                throw new ArgumentNullException(nameof(base64JsonPayload), "JSON payload cannot be null or empty");

            if (key == null)
                throw new ArgumentNullException(nameof(key), "Decryption key cannot be null");

            if (key.Length != KeySize)
                throw new ArgumentException($"Key must be {KeySize} bytes for AES-256, but was {key.Length} bytes", nameof(key));

            AesGcmPayload payload;
            try
            {
                string json = Encoding.UTF8.GetString(Convert.FromBase64String(base64JsonPayload));
                payload = JsonConvert.DeserializeObject<AesGcmPayload>(json);
            }
            catch (JsonException ex)
            {
                throw new ArgumentException("Invalid JSON format in payload", ex);
            }

            if (string.IsNullOrEmpty(payload.Ciphertext))
                throw new ArgumentException("Ciphertext cannot be null or empty", nameof(payload.Ciphertext));

            if (string.IsNullOrEmpty(payload.IV))
                throw new ArgumentException("IV cannot be null or empty", nameof(payload.IV));

            if (string.IsNullOrEmpty(payload.Tag))
                throw new ArgumentException("Tag cannot be null or empty", nameof(payload.Tag));
            //var payload = new AesGcmPayload
            //{
            //    Ciphertext = "/2PVq7boAGNzfDZT0g==",
            //    IV = "kDU4m51X5Ni47BQJ",
            //    Tag = "ePBZmRFpK05kfOg9As3CAw=="
            //};

            try
            {
                byte[] ciphertext = Convert.FromBase64String(payload.Ciphertext);
                byte[] iv = Convert.FromBase64String(payload.IV);
                byte[] tag = Convert.FromBase64String(payload.Tag);

                if (iv.Length != IvSize)
                    throw new ArgumentException($"IV must be {IvSize} bytes, but was {iv.Length} bytes", nameof(payload.IV));

                if (tag.Length != TagSize)
                    throw new ArgumentException($"Tag must be {TagSize} bytes, but was {tag.Length} bytes", nameof(payload.Tag));

                // Combine ciphertext and tag for decryption
                byte[] combined = new byte[ciphertext.Length + tag.Length];
                Array.Copy(ciphertext, 0, combined, 0, ciphertext.Length);
                Array.Copy(tag, 0, combined, ciphertext.Length, tag.Length);

                GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
                AeadParameters parameters = new AeadParameters(new KeyParameter(key), TagSize * 8, iv);
                cipher.Init(false, parameters);

                byte[] output = new byte[cipher.GetOutputSize(combined.Length)];
                int len = cipher.ProcessBytes(combined, 0, combined.Length, output, 0);
                len += cipher.DoFinal(output, len); // This validates the tag

                return Encoding.UTF8.GetString(output, 0, len);
            }
            catch (FormatException ex)
            {
                throw new ArgumentException("Invalid Base64 format in payload components", ex);
            }
            catch (Exception ex) when (!(ex is ArgumentException || ex is ArgumentNullException || ex is InvalidOperationException))
            {
                // GCM authentication failure typically results in generic exceptions
                throw new InvalidOperationException("Decryption failed - invalid key, IV, or corrupted data", ex);
            }
        }
    }
    public class AesGcmPayload
    {
        [JsonProperty("ciphertext")]
        public string Ciphertext { get; set; }

        [JsonProperty("iv")]
        public string IV { get; set; }

        [JsonProperty("tag")]
        public string Tag { get; set; }
    }

}
