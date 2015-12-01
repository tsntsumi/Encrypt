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
        private readonly CryptoStream CryptoStream;
        /// <summary>
        /// 復号化されたデータを圧縮するストリーム。
        /// </summary>
        private readonly DeflateStream DeflateStream;

        /// <summary>
        /// オブジェクトが解放されたことを表すフラグ。
        /// </summary>
        private bool disposed = false;

        /// <summary>
        /// 復号化を行うストリームを取得します。
        /// </summary>
        public Stream DecryptStream { get { return DeflateStream; } }

        /// <summary>
        /// 入力ファイル名とパスワードを指定して、 <see cref="Encrypt.Decryptor"/> クラスの新しいインスタンスを初期化します。
        /// </summary>
        /// <param name="inputFileName">復号化を行う対象となる入力ファイル名。</param>
        /// <param name="password">パスワード。</param>
        public Decryptor(string inputFileName, string password)
            : this(new FileStream(inputFileName, FileMode.Open, FileAccess.Read), password)
        {
        }

        /// <summary>
        /// 入力ストリームとパスワードを指定して、 <see cref="Encrypt.Decryptor"/> クラスの新しいインスタンスを初期化します。
        /// </summary>
        /// <param name="inputStream">復号化を行う対象となる入力ストリーム。</param>
        /// <param name="password">パスワード。</param>
        /// <remarks>
        /// 暗号化に使用したソルトとIVを、入力ストリームの先頭から読み込みます。
        /// AESアルゴリズムを使用した復号化を行うストリームを作成します。
        /// </remarks>
        private Decryptor(Stream inputStream, string password)
        {
            if (inputStream == null)
            {
                throw new ArgumentNullException("inputStream");
            }
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException("password");
            }

            InputStream = inputStream;

            using (var aes = new AesManaged())
            {
                var settings = EncryptSettings.Instance;
                aes.BlockSize = settings.BlockSize;
                aes.KeySize = settings.KeySize;
                aes.Mode = settings.Mode;
                aes.Padding = settings.Padding;

                // ファイルの先頭からsaltを読み込む
                var salt = new byte[(settings.SaltSize + 7) / 8];
                int readSaltLength = InputStream.Read(salt, 0, salt.Length);
                if (readSaltLength < salt.Length)
                {
                    throw new EndOfStreamException("Insufficient salt length");
                }

                // ファイルの先頭からivを読み込む
                var iv = new byte[aes.BlockSize / 8];   // aes.BlockSizeは必ず8の倍数の 128
                int readIVLength = InputStream.Read(iv, 0, iv.Length);
                if (readIVLength < iv.Length)
                {
                    throw new EndOfStreamException("Insufficient IV length");
                }

                // 指定されたpasswordとsaltを使って擬似乱数を生成
                var derivedBytes = new Rfc2898DeriveBytes(password, salt);

                aes.Key = derivedBytes.GetBytes(aes.KeySize / 8);   // aes.KeySizeは必ず8の倍数
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
        /// コンストラクタで設定されたストリームから復号化して、指定されたファイルに出力します。
        /// </summary>
        /// <param name="outputFileName">復号化したデータを出力するファイル名。</param>
        public void Decrypt(string outputFileName)
        {
            if (disposed)
            {
                return;
            }
            using (var outputStream = new FileStream(outputFileName, FileMode.Create, FileAccess.Write))
            {
                Decrypt(outputStream);
            }
        }

        /// <summary>
        /// コンストラクタで設定されたストリームから、復号化して読み込んだバイトデータを返します。
        /// </summary>
        /// <returns>復号化したデータ。</returns>
        public byte[] Decrypt()
        {
            if (disposed)
            {
                return null;
            }
            byte[] data;
            using (var memoryStream = new MemoryStream())
            {
                Decrypt(memoryStream);
                data = memoryStream.ToArray();
            }
            return data;
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
        /// <see cref="Encrypt.Decryptor"/> を使用し終わったら <see cref="Dispose()"/> を呼び出してください。
        /// <see cref="Dispose()"/> メソッドは <see cref="Encrypt.Encryptor"/> を使用できない状態にします。
        /// <see cref="Dispose()"/> を呼び出した後は、ガベージコレクタが <see cref="Encrypt.Decryptor"/> の
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
        /// <param name="disposing"><see cref="Dispose()"/> から呼び出される場合は <c>true</c>、
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
                try
                {
                    if (DeflateStream != null)
                    {
                        DeflateStream.Dispose();
                    }
                    if (CryptoStream != null)
                    {
                        CryptoStream.Dispose();
                    }
                }
                catch (CryptographicException)
                {
                    // CryptoStream/DeflateStream を作成して、何も読み込まずにそれらを Dispose すると
                    // この例外が発生する。また、読み込んだバイト数が AESManeged のプロパティに設定した
                    // ブロックサイズで割り切れない状況で Dispose してもこの例外が発生する。
                    // しかし、CryptoStream/DeflateStream の Read メソッドがストリームの終端に到達した時に、
                    // 同様の状況だった場合にも同じ例外が発生する。
                    // したがって Decryptor インスタンスを using 文で生成した場合に、Decryptor.DecryptStream
                    // プロパティのストリームの Read メソッドでこの例外が発生すると、Decryptor.Dispose メソッドでも
                    // 同じ例外が発生してしまい、本当はどこで発生したのかを特定するのが困難になってしまう。
                    // そこで Dispose で発生した例外の方は無視することにする。
                }
                catch (IndexOutOfRangeException)
                {
                    // CryptographicException と同様。ただし、MONO Framework では発生しない様子。
                }
                finally
                {
                    if (InputStream != null)
                    {
                        InputStream.Close();
                    }
                }
            }

            disposed = true;
        }
    }
}
