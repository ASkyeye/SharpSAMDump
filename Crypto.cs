using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace SharpSAMDump
{
    internal static class Crypto
    {
        private enum HashType
        {
            LmPassword = 1,
            NtPassword = 2,
            LmPasswordHistory = 3,
            NtPasswordHistory = 4,
            MiscCredData = 5,
        };

        private enum EncryptionType : short
        {
            RC4 = 1,
            AES = 2,
        };

        public static byte[] UnprotectNTHash(byte[] key, byte[] encryptedHash, uint rid)
        {
            byte[] dec = UnprotectPasswordHash(key, encryptedHash, rid, HashType.NtPassword);
            if (dec == null)
            {
                return null;
            }

            byte[] hash = UnprotectPasswordHashDES(dec, rid);
            return hash;
        }

        public static byte[] UnprotectLMHash(byte[] key, byte[] encryptedHash, uint rid)
        {
            byte[] dec = UnprotectPasswordHash(key, encryptedHash, rid, HashType.LmPassword);
            if (dec == null)
            {
                return null;
            }

            byte[] hash = UnprotectPasswordHashDES(dec, rid);
            return hash;
        }

        private static byte[] UnprotectPasswordHash(byte[] key, byte[] data, uint rid, HashType type) {
            EncryptionType encryptionType = (EncryptionType)BitConverter.ToInt16(data, 2);
            switch (encryptionType)
            {
                case EncryptionType.RC4:
                    return UnprotectPasswordHashRC4(key, data, rid, type);
                case EncryptionType.AES:
                    return UnprotectPasswordHashAES(key, data);
                default:
                    throw new ArgumentException($"unknown encryption type {encryptionType}");
            }
        }

        private static byte[] UnprotectPasswordHashAES(byte[] key, byte[] data)
        {
            int length = BitConverter.ToInt32(data, 4);
            if (length == 0)
            {
                return null;
            }

            byte[] iv = new byte[16];
            Array.Copy(data, 8, iv, 0, iv.Length);

            byte[] ciphertext = new byte[data.Length - 24];
            Array.Copy(data, 8 + iv.Length, ciphertext, 0, ciphertext.Length);

            return UnprotectAES(key, iv, ciphertext);
        }
        private static byte[] UnprotectAES(byte[] key, byte[] iv, byte[] ciphertext)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                return aes.CreateDecryptor().TransformFinalBlock(ciphertext, 0, ciphertext.Length);
            }
        }

        private static byte[] UnprotectPasswordHashRC4(byte[] key, byte[] data, uint rid, HashType type)
        {
            if (data.Length < 0x14)
            {
                return null;
            }

            byte[] iv;
            switch (type)
            {
                case HashType.LmPassword: iv = Encoding.ASCII.GetBytes("LMPASSWORD\0"); break;
                case HashType.NtPassword: iv = Encoding.ASCII.GetBytes("NTPASSWORD\0"); break;
                case HashType.LmPasswordHistory: iv = Encoding.ASCII.GetBytes("LMPASSWORDHISTORY\0"); break;
                case HashType.NtPasswordHistory: iv = Encoding.ASCII.GetBytes("NTPASSWORDHISTORY\0"); break;
                case HashType.MiscCredData: iv = Encoding.ASCII.GetBytes("MISCCREDDATA\0"); break;
                default:
                    throw new ArgumentException($"unknown type {type}");
            }

            byte[] rc4KeyMaterial = Util.ConcatArrays(key, BitConverter.GetBytes(rid), iv);
            byte[] rc4Key = MD5.Create().ComputeHash(rc4KeyMaterial);

            return UnprotectRC4(rc4Key, data, 4, 16);
        }

        private static byte[] UnprotectRC4(byte[] key, byte[] data, int offset, int length)
        {
            byte[] ciphertext = new byte[length];
            Array.Copy(data, offset, ciphertext, 0, ciphertext.Length);
            return RC4Cryptography.RC4.Apply(data, key);
        }

        private static byte[] UnprotectPasswordHashDES(byte[] ciphertext, uint rid)
        {
            Tuple<byte[], byte[]> keys = GetUserDESKeys(rid);

            byte[] plaintext1 = UnprotectDES(keys.Item1, ciphertext, 0);
            byte[] plaintext2 = UnprotectDES(keys.Item1, ciphertext, 8);

            return Util.ConcatArrays(plaintext1, plaintext2);
        }

        private static Tuple<byte[], byte[]> GetUserDESKeys(uint rid)
        {
            byte[] data = BitConverter.GetBytes(rid);
            byte[] key1 = DeriveDESKey(new byte[]{ data[2], data[1], data[0], data[3], data[2], data[1], data[0]});
            byte[] key2 = DeriveDESKey(new byte[] { data[1], data[0], data[3], data[2], data[1], data[0], data[3] });
            return Tuple.Create(key1, key2);
        }

        private static byte[] DeriveDESKey(byte[] data)
        {
            byte[] kBytes = new byte[8];
            data.CopyTo(kBytes, 0);

            ulong k = BitConverter.ToUInt64(kBytes, 0);
            byte[] key = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                int j = 7 - i;
                int curr = (int)(k >> (7 * j)) & 0x7F;
                int b = curr;
                b ^= b >> 4;
                b ^= b >> 2;
                b ^= b >> 1;

                int keyByte = (curr << 1) ^ (b & 1) ^ 1;
                Debug.Assert(byte.MinValue <= keyByte && keyByte <= byte.MaxValue);

                key[i] = (byte)keyByte;
            }

            return key;
        }

        private static byte[] UnprotectDES(byte[] key, byte[] ciphertext, int offset)
        {
            using (DES des = DES.Create()) {
                des.Key = key;
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.None;
                return des.CreateDecryptor().TransformFinalBlock(ciphertext, offset, 8);
            }
        }


        public static byte[] UnprotectPasswordEncryptionKey(byte[] samKey, byte[] lsaKey)
        {
            EncryptionType encryptionType = (EncryptionType)BitConverter.ToInt32(samKey, 0x68);
            int endofs = BitConverter.ToInt32(samKey, 0x6C) + 0x68;

            int len = endofs - 0x70;
            Debug.Assert(len > 0);

            byte[] data = new byte[len];
            Array.Copy(samKey, 0x70, data, 0, data.Length);

            switch (encryptionType)
            {
                case EncryptionType.RC4:
                    return UnprotectPasswordEncryptionKeyRC4(data, lsaKey);
                case EncryptionType.AES:
                    return UnprotectPasswordEncryptionKeyAES(data, lsaKey);
                default:
                    throw new ArgumentException($"unknown encryption type {encryptionType}");
            }
        }

        private static byte[] UnprotectPasswordEncryptionKeyRC4(byte[] data, byte[] lsaKey)
        {
            byte[] qiv = Encoding.ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%");
            byte[] niv = Encoding.ASCII.GetBytes("0123456789012345678901234567890123456789");

            byte[] data16Bytes = new byte[16];
            Array.Copy(data, 0, data16Bytes, 0, 16);

            byte[] rc4KeyMaterial = Util.ConcatArrays(data16Bytes, qiv, lsaKey, niv);
            byte[] rc4Key = MD5.Create().ComputeHash(rc4KeyMaterial);
            byte[] plaintext = UnprotectRC4(rc4Key, data, 0x10, 0x20);

            byte[] pek = new byte[16];
            Array.Copy(plaintext, 0, pek, 0, pek.Length);

            byte[] hash = new byte[16];
            Array.Copy(plaintext, pek.Length, hash, 0, hash.Length);

            byte[] hashMaterial = Util.ConcatArrays(pek, niv, pek, qiv);
            byte[] actualHash = MD5.Create().ComputeHash(hashMaterial);

            if (!Util.ArrayEquals(hash, actualHash))
            {
                throw new Exception("invalid RC4 password key");
            }

            return pek;
        }

        private static byte[] UnprotectPasswordEncryptionKeyAES(byte[] data, byte[] lsaKey)
        {
            int hashLen = BitConverter.ToInt32(data, 0);
            int encLen = BitConverter.ToInt32(data, 4);

            byte[] iv = new byte[16];
            Array.Copy(data, 8, iv, 0, iv.Length);

            byte[] ciphertext = new byte[encLen];
            Array.Copy(data, 0x18, ciphertext, 0, ciphertext.Length);

            byte[] pek = UnprotectAES(lsaKey, iv, ciphertext);

            byte[] hashData = new byte[hashLen];
            Array.Copy(data, 0x18 + ciphertext.Length, hashData, 0, hashData.Length);

            byte[] hash = UnprotectAES(lsaKey, iv, hashData);

            byte[] actualHash = SHA256.Create().ComputeHash(pek);
            if (!Util.ArrayEquals(hash, actualHash))
            {
                throw new Exception("invalid AES password key");
            }

            return pek;
        }
    }
}
