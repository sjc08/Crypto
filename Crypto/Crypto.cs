using System.Security.Cryptography;
using System.Text;

namespace Asjc.Crypto
{
    public static class Crypto
    {
        public static HashAlgorithm DefaultHashAlgorithm { get; set; } = SHA256.Create();

        public static string GetHash(this string text)
            => GetHash(text, DefaultHashAlgorithm);

        public static string GetHash(this string text, HashAlgorithm algorithm)
            => GetHash(Encoding.Default.GetBytes(text), algorithm);

        public static string GetHash(this byte[] bytes)
            => GetHash(bytes, DefaultHashAlgorithm);

        public static string GetHash(this byte[] bytes, HashAlgorithm algorithm)
        {
            using (algorithm)
            {
                return Convert.ToHexString(algorithm.ComputeHash(bytes));
            }
        }

        public static string GetHash(this Stream stream)
            => GetHash(stream, DefaultHashAlgorithm);

        public static string GetHash(this Stream stream, HashAlgorithm algorithm)
        {
            using (stream)
            {
                using (algorithm)
                {
                    return Convert.ToHexString(algorithm.ComputeHash(stream));
                }
            }
        }

        public static string GetFileHash(this string path)
            => GetFileHash(path, DefaultHashAlgorithm);

        public static string GetFileHash(this string path, HashAlgorithm algorithm)
            => GetHash(File.OpenRead(path), algorithm);

        public static string GetFileHash(this FileInfo file)
            => GetFileHash(file, DefaultHashAlgorithm);

        public static string GetFileHash(this FileInfo file, HashAlgorithm algorithm)
            => GetHash(file.OpenRead(), algorithm);
    }
}
