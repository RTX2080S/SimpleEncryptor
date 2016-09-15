using EncryptorService;
using System;

namespace SimpleEncryptor
{
    class Program
    {
        static void Main(string[] args)
        {
            string text = Console.ReadLine();
            Console.WriteLine();
            Console.WriteLine("Original: {0}", text);

            // Use this pair to decrypt
            byte[] my_key, my_iv;

            IEncryptor myEncryptor = new Encryptor(out my_key, out my_iv);
            string encrypted = myEncryptor.EncryptText(text);

            IEncryptor herEncryptor = new Encryptor(my_key, my_iv);
            string decrypted = myEncryptor.DecryptText(encrypted);

            Console.WriteLine("Encrypted: {0}", encrypted);
            Console.WriteLine("Decrypted: {0}", decrypted);

            Console.ReadLine();
        }
    }
}
