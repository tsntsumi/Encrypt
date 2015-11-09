using System;
using System.Text;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

namespace Encrypt
{
    /// <summary>
    /// 暗号化を行います。
    /// </summary>
    public class Encryptor: IDisposable
    {
        /// <summary>
        /// 暗号化されたデータを出力するストリーム。
        /// </summary>
        private readonly Stream OutputStream;
        /// <summary>
        /// 実質的に暗号化を行うストリーム。
        /// </summary>
        private CryptoStream CryptoStream;
        /// <summary>
        /// 暗号化されたデータを圧縮するストリーム。
        /// </summary>
        private DeflateStream DeflateStream;

        /// <summary>
        /// オブジェクトが解放されたことを表すフラグ。
        /// </summary>
        private bool disposed = false;

        /// <summary>
        /// 暗号化を行うストリームを取得します。
        /// </summary>
        public Stream EncryptStream { get { return DeflateStream; } }

        /// <summary>
        /// <see cref="Encrypt.Encryptor"/> クラスの新しいインスタンスを初期化します。
        /// </summary>
        /// <param name="outputStream">暗号化されたデータを出力するストリーム。</param>
        /// <param name="password">パスワード。</param>
        public Encryptor(Stream outputStream, string password)
        {
            if (outputStream == null)
            {
                throw new ArgumentNullException("outputStream");
            }

            OutputStream = outputStream;
            CreateEncryptStream(password);
        }

        /// <summary>
        /// <see cref="Encrypt.Encryptor"/> クラスの新しいインスタンスを初期化します。
        /// </summary>
        /// <param name="outputFileName">暗号化されたデータを出力するファイル名。</param>
        /// <param name="password">パスワード。</param>
        public Encryptor(string outputFileName, string password)
        {
            OutputStream = new FileStream(outputFileName, FileMode.Create, FileAccess.Write);
            CreateEncryptStream(password);
        }

        /// <summary>
        /// AESアルゴリズムを使用した暗号化を行うストリームを作成します。
        /// </summary>
        /// <param name="password">パスワード。</param>
        /// <remarks>
        /// 暗号化に使用したソルトとIVを、出力ストリームの先頭に出力します。
        /// </remarks>
        private void CreateEncryptStream(string password)
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

                // 指定されたパスワードをベースに擬似乱数を生成
                var derivedBytes = new Rfc2898DeriveBytes(password, settings.SaltBytes);
                var salt = derivedBytes.Salt;

                aes.Key = derivedBytes.GetBytes(settings.KeyBytes);
                aes.GenerateIV();

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                CryptoStream = new CryptoStream(OutputStream, encryptor, CryptoStreamMode.Write);

                // saltとIVをファイル先頭に暗号化しないで保存する
                OutputStream.Write(salt, 0, salt.Length);
                OutputStream.Write(aes.IV, 0, aes.IV.Length);

                DeflateStream = new DeflateStream(CryptoStream, CompressionMode.Compress);
            }
        }

        /// <summary>
        /// コンストラクタで設定されたストリームを使用して、暗号化を行います。
        /// </summary>
        /// <param name="inputStream">暗号化するデータを入力するストリーム。</param>
        public void Encrypt(Stream inputStream)
        {
            if (disposed)
            {
                return;
            }
            if (inputStream == null)
            {
                throw new ArgumentNullException("inputStream");
            }

            int readLength;
            byte[] buffer = new byte[4096];

            while ((readLength = inputStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                EncryptStream.Write(buffer, 0, readLength);
            }
        }

        /// <summary>
        /// 指定されたストリームを暗号化して、指定されたストリームに出力します。
        /// </summary>
        /// <param name="inputStream">入力ストリーム。</param>
        /// <param name="outputStream">出力ストリーム。</param>
        /// <param name="password">パスワード。</param>
        public static void Encrypt(Stream inputStream, Stream outputStream, string password)
        {
            using (var encryptor = new Encryptor(outputStream, password))
            {
                encryptor.Encrypt(inputStream);
            }
        }

        /// <summary>
        /// 指定されたファイルを暗号化してコピーします。
        /// </summary>
        /// <param name="source">暗号化するファイル名。</param>
        /// <param name="destination">暗号化先のファイル名。</param>
        /// <param name="password">パスワード。</param>
        public static void CopyFile(string source, string destination, string password)
        {
            using (var inputStream = new FileStream(source, FileMode.Open, FileAccess.Read))
            using (var encryptor = new Encryptor(destination, password))
            {
                encryptor.Encrypt(inputStream);
            }
        }

        /// <summary>
        /// 暗号化されたファイルを復号化して、末尾にテキストを追加し、再度暗号化して上書き保存します。
        /// </summary>
        /// <param name="fileName">テキストを追加するファイル名。</param>
        /// <param name="text">追加するテキスト。</param>
        /// <param name="password">パスワード。</param>
        /// <param name="encoding">テキストのエンコーディング。</param>
        public static void AppendTextToFile(string fileName, string text, string password, Encoding encoding)
        {
            byte[] buffer;
            long decryptedSize;
            int capacity;
            int appendSize = text.Length + Environment.NewLine.Length;
            // 復号化したファイルの内容を読み込みます。
            // ファイルが存在しなければ、バッファを割り当てます。
            if (File.Exists(fileName))
            {
                var fileInfo = new FileInfo(fileName);
                int fileSize = (int)fileInfo.Length;
                // MemoryStreamに指定するcapacityは、復号後の予想サイズに、
                // 後で文字列textを追加することを考慮した長さを加えています。
                // 復号後の予想サイズは、暗号化されたファイルが圧縮されているため概算です。
                capacity = (fileSize * 3) / 2 + appendSize;
                using (var outputStream = new MemoryStream(capacity))
                using (var decryptor = new Decryptor(fileName, password))
                {
                    decryptor.Decrypt(outputStream);
                    buffer = outputStream.GetBuffer();
                    decryptedSize = outputStream.Length;
                    capacity = outputStream.Capacity;  // 復号中にバッファが拡張された場合のためにcapacityを更新します。
                }
            }
            else
            {
                decryptedSize = 0;
                capacity = appendSize;
                buffer = new byte[capacity];
            }
            // 読み込んだ内容に指定された文字列を追加して、暗号化して保存します。
            using (var inputStream = new MemoryStream(buffer, 0, capacity, true))
            using (var streamWriter = new StreamWriter(inputStream, encoding))
            {
                inputStream.Seek(decryptedSize, SeekOrigin.Begin);
                streamWriter.WriteLine("{0}", text);
                streamWriter.Flush();
                inputStream.Seek(0, SeekOrigin.Begin);
                using (var encryptor = new Encryptor(fileName, password))
                {
                    encryptor.Encrypt(inputStream);
                }
            }
        }

        /// <summary>
        /// 暗号化されたファイルを一時フォルダに復号化して、末尾にテキストを追加し、再度暗号化して上書き保存します。
        /// </summary>
        /// <param name="fileName">テキストを追加する暗号化されたファイル名。</param>
        /// <param name="temporaryFolderName">復号化に使用する一時フォルダ名。</param>
        /// <param name="text">追加するテキスト。</param>
        /// <param name="password">パスワード。</param>
        /// <param name="encoding">テキストのエンコーディング。</param>
        /// <remarks>>
        /// 暗号化されているファイル名と同じ名前で、一時ファイルを一時フォルダの下に作成するため、
        /// 一時フォルダは暗号化されているファイルのフォルダと同じではいけません。
        /// 同じフォルダを指定すると、ArgumentException を投げます。
        /// </remarks>
        public static void AppendTextToFileViaTemporaryFile(string fileName, string temporaryFolderName, string text, string password, Encoding encoding)
        {
            string temporaryFileName = Path.Combine(temporaryFolderName, Path.GetFileName(fileName));
            bool append;

            if (Path.GetFullPath(temporaryFileName) == Path.GetFullPath(fileName))
            {
                throw new ArgumentException("Same folder of fileName", "temporaryFolderName");
            }
            if (File.Exists(fileName))
            {
                Decryptor.CopyFile(fileName, temporaryFileName, password);
                append = true;
            }
            else
            {
                append = false;
            }
            using (var writer = new StreamWriter(temporaryFileName, append, encoding))
            {
                writer.WriteLine("{0}", text);
            }
            Encryptor.CopyFile(temporaryFileName, fileName, password);
            File.Delete(temporaryFileName);
        }

        /// <summary>
        /// <see cref="Encrypt.Encryptor"/> オブジェクトが使用した全てのリソースを解放します。
        /// </summary>
        /// <remarks>
        /// <see cref="Encrypt.Encryptor"/> を使用し終わったら <see cref="Dispose"/> を呼び出してください。
        /// <see cref="Dispose"/> メソッドは <see cref="Encrypt.Encryptor"/> を使用できない状態にします。
        /// <see cref="Dispose"/> を呼び出した後は、ガベージコレクタが <see cref="Encrypt.Encryptor"/> の
        /// 占有しているメモリを再利用できるように、
        /// <see cref="Encrypt.Encryptor"/> への全ての参照を解放しなければなりません。
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
                if (OutputStream != null)
                {
                    OutputStream.Close();
                }
            }

            disposed = true;
        }
    }
}
