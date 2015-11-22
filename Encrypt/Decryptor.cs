using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

namespace Encrypt
{
    /// <summary>
    /// 復号化を行います。
    /// </summary>
    public class Decryptor: IDisposable
    {
        /// <summary>
        /// 復号化を行う対象となる入力ストリーム。
        /// </summary>
        private readonly Stream InputStream;
        /// <summary>
        /// 実質的に復号化を行うストリーム。
        /// </summary>
        private CryptoStream CryptoStream;
        /// <summary>
        /// 復号化されたデータを圧縮するストリーム。
        /// </summary>
        private DeflateStream DeflateStream;

        /// <summary>
        /// オブジェクトが解放されたことを表すフラグ。
        /// </summary>
        private bool disposed = false;

        /// <summary>
        /// 復号化を行うストリームを取得します。
        /// </summary>
        public Stream DecryptStream { get { return DeflateStream; } }

        /// <summary>
        /// <see cref="Encrypt.Decryptor"/> クラスの新しいインスタンスを初期化します。
        /// </summary>
        /// <param name="inputStream">復号化を行う対象となる入力ストリーム。</param>
        /// <param name="password">パスワード。</param>
        public Decryptor(Stream inputStream, string password)
        {
            if (inputStream == null)
            {
                throw new ArgumentNullException("inputStream");
            }

            InputStream = inputStream;
            CreateDecryptStream(password);
        }

        /// <summary>
        /// <see cref="Encrypt.Decryptor"/> クラスの新しいインスタンスを初期化します。
        /// </summary>
        /// <param name="inputFileName">復号化を行う対象となる入力ファイル名。</param>
        /// <param name="outputFileName">復号化されたデータを出力するファイル名。</param>
        /// <param name="password">パスワード。</param>
        public Decryptor(string inputFileName, string password)
        {
            InputStream = new FileStream(inputFileName, FileMode.Open, FileAccess.Read);
            CreateDecryptStream(password);
        }

        /// <summary>
        /// AESアルゴリズムを使用した復号化を行うストリームを作成します。
        /// </summary>
        /// <param name="password">パスワード。</param>
        /// <remarks>
        /// 暗号化に使用したソルトとIVを、入力ストリームの先頭から読み込みます。
        /// </remarks>
        private void CreateDecryptStream(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException("password");
            }

            using (var aes = new AesManaged())
            {
                var settings = EncryptSettings.Instance;
                aes.BlockSize = settings.BlockSize;
                aes.KeySize = settings.KeySize;
                aes.Mode = settings.Mode;
                aes.Padding = settings.Padding;

                // ファイルの先頭からsaltを読み込む
                var salt = new byte[settings.SaltBytes];
                InputStream.Read(salt, 0, salt.Length);

                // ファイルの先頭からivを読み込む
                var iv = new byte[settings.SaltBytes];
                InputStream.Read(iv, 0, iv.Length);

                // 指定されたpasswordとsaltを使って擬似乱数を生成
                var derivedBytes = new Rfc2898DeriveBytes(password, salt);

                aes.Key = derivedBytes.GetBytes(settings.KeyBytes);
                aes.IV = iv;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                CryptoStream = new CryptoStream(InputStream, decryptor, CryptoStreamMode.Read);

                DeflateStream = new DeflateStream(CryptoStream, CompressionMode.Decompress);
            }
        }

        /// <summary>
        /// コンストラクタで設定されたストリームを使用して、復号化を行います。
        /// </summary>
        /// <param name="outputStream">復号化したデータを出力するストリーム。</param>
        public void Decrypt(Stream outputStream)
        {
            if (disposed)
            {
                return;
            }
            if (outputStream == null)
            {
                throw new ArgumentNullException("outputStream");
            }

            int readLength;
            byte[] buffer = new byte[4096];

            while ((readLength = DecryptStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                outputStream.Write(buffer, 0, readLength);
            }
        }

        /// <summary>
        /// 指定されたストリームを復号化して、指定されたストリームに出力します。
        /// </summary>
        /// <param name="inputStream">入力ストリーム。</param>
        /// <param name="outputStream">出力ストリーム。</param>
        /// <param name="password">パスワード。</param>
        public static void Decrypt(Stream inputStream, Stream outputStream, string password)
        {
            using (var decryptor = new Decryptor(inputStream, password))
            {
                decryptor.Decrypt(outputStream);
            }
        }

        /// <summary>
        /// 指定されたファイルを復号化して、指定されたファイルに上書き保存します。
        /// </summary>
        /// <param name="source">復号化するファイル名。</param>
        /// <param name="destination">復号化先のファイル名。</param>
        /// <param name="password">パスワード。</param>
        public static void Decrypt(string source, string destination, string password)
        {
            using (var decryptor = new Decryptor(source, password))
            using (var outputStream = new FileStream(destination, FileMode.Create, FileAccess.Write))
            {
                decryptor.Decrypt(outputStream);
            }
        }

        /// <summary>
        /// <see cref="Encrypt.Decryptor"/> オブジェクトが使用した全てのリソースを解放します。
        /// </summary>
        /// <remarks>
        /// <see cref="Encrypt.Decryptor"/> を使用し終わったら <see cref="Dispose"/> を呼び出してください。
        /// <see cref="Dispose"/> メソッドは <see cref="Encrypt.Encryptor"/> を使用できない状態にします。
        /// <see cref="Dispose"/> を呼び出した後は、ガベージコレクタが <see cref="Encrypt.Decryptor"/> の
        /// 占有しているメモリを再利用できるように、
        /// <see cref="Encrypt.Decryptor"/> への全ての参照を解放しなければなりません。
        /// </remarks>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// リソースを解放します。
        /// </summary>
        /// <param name="disposing"><see cref="Dispose"/> から呼び出される場合は <c>true</c>、
        /// ファイナライザから呼び出される場合は <c>false</c>。
        /// </param>
        protected void Dispose(bool disposing)
        {
            if (disposed)
            {
                return;
            }
            if (disposing)
            {
                if (DeflateStream != null)
                {
                    DeflateStream.Dispose();
                }
                if (CryptoStream != null)
                {
                    CryptoStream.Dispose();
                }
                if (InputStream != null)
                {
                    InputStream.Close();
                }
            }

            disposed = true;
        }
    }
}
