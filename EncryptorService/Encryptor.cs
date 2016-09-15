using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptorService
{
    public interface IEncryptor
    {
        string EncryptText(string openText);
        string DecryptText(string encryptedText);
    }

    public class Encryptor : IEncryptor
    {
        protected byte[] c_key;
        protected byte[] c_iv;

        public Encryptor(byte[] my_Key, byte[] my_IV)
        {
            c_key = my_Key;
            c_iv = my_IV;
        }

        public Encryptor(out byte[] my_Key, out byte[] my_IV)
        {
            RijndaelManaged symmetricKey = new RijndaelManaged();

            symmetricKey.KeySize = 128;
            symmetricKey.GenerateKey();
            symmetricKey.GenerateIV();

            c_key = c_key ?? symmetricKey.Key;
            c_iv = c_iv ?? symmetricKey.IV;

            my_Key = c_key;
            my_IV = c_iv;
        }

        public string EncryptText(string openText)
        {
            RC2CryptoServiceProvider rc2CSP = new RC2CryptoServiceProvider();
            ICryptoTransform encryptor = rc2CSP.CreateEncryptor(c_key, c_iv);
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    byte[] toEncrypt = Encoding.Unicode.GetBytes(openText);

                    csEncrypt.Write(toEncrypt, 0, toEncrypt.Length);
                    csEncrypt.FlushFinalBlock();

                    byte[] encrypted = msEncrypt.ToArray();

                    return Convert.ToBase64String(encrypted);
                }
            }
        }

        public string DecryptText(string encryptedText)
        {
            RijndaelManaged symmetricKey = new RijndaelManaged();
            RC2CryptoServiceProvider rc2CSP = new RC2CryptoServiceProvider();
            ICryptoTransform decryptor = rc2CSP.CreateDecryptor(c_key, c_iv);
            using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(encryptedText)))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    List<byte> bytes = new List<byte>();
                    int b;
                    do
                    {
                        b = csDecrypt.ReadByte();
                        if (b != -1)
                        {
                            bytes.Add(Convert.ToByte(b));
                        }

                    }
                    while (b != -1);

                    return Encoding.Unicode.GetString(bytes.ToArray());
                }
            }
        }
    }
}
