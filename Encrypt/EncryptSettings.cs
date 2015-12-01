using System;
using System.Security.Cryptography;

namespace Encrypt
{
    /// <summary>
    /// AESアルゴリズムで使用する暗号化設定を格納するシングルトンオブジェクト。
    /// </summary>
    public class EncryptSettings
    {
        /// <summary>
        /// ただ一つのインスタンス。
        /// </summary>
        private static EncryptSettings instance = new EncryptSettings();
        /// <summary>
        /// 暗号化に使用するブロック長をビット数で格納します。
        /// </summary>
        private int blockSize;
        /// <summary>
        /// 暗号化に使用する鍵長をビット数で格納します。
        /// </summary>
        private int keySize;
        /// <summary>
        /// 暗号化に使用するソルト長をビット数で格納します。
        /// </summary>
        private int saltSize;

        /// <summary>
        /// 暗号化に使用するブロック長をビット数で設定または取得します。
        /// </summary>
        /// <remarks>
        /// AESアルゴリズムでは 128ビットを指定します。
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">設定した値が128ではない。</exception>
        public int BlockSize
        {
            get { return blockSize; }
            set
            {
                if (value != 128)
                {
                    throw new ArgumentOutOfRangeException("value");
                }
                blockSize = value;
            }
        }
        /// <summary>
        /// 暗号化に使用する鍵長をビット数で設定または取得します。
        /// </summary>
        /// <remarks>
        /// AESアルゴリズムでは 128, 192, 256ビットの中から指定します。
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">設定した値が 128, 192, 256 ではない。</exception>
        public int KeySize
        {
            get { return keySize; }
            set
            {
                if (value != 128 && value != 192 && value != 256)
                {
                    throw new ArgumentOutOfRangeException("value");
                }
                keySize = value;
            }
        }
        /// <summary>
        /// 暗号化に使用するブロック暗号化モードを設定または取得します。
        /// </summary>
        public CipherMode Mode { get; set; }
        /// <summary>
        /// 暗号化に使用するパディングモードを設定または取得します。
        /// </summary>
        public PaddingMode Padding { get; set; }
        /// <summary>
        /// 暗号化に使用するソルト長をビット数で設定または取得します。
        /// </summary>
        /// <remarks>
        /// 設定する値は、必ず8以上の8で割り切れなければなりません。
        /// そうでない場合は ArgumentOutOfRangeException が投げられます。
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">設定した値が負であるか、8の倍数ではない。</exception>
        public int SaltSize
        {
            get { return saltSize; }
            set
            {
                if (value <= 0 || value % 8 > 0)
                {
                    throw new ArgumentOutOfRangeException("value");
                }
                saltSize = value;
            }
        }

        /// <summary>
        /// ただ一つのインスタンスを取得します。
        /// </summary>
        public static EncryptSettings Instance { get { return instance; } }

        /// <summary>
        /// <see cref="Encrypt.EncryptSettings"/> クラスの新しいインスタンスを初期化します。
        /// </summary>
        private EncryptSettings ()
        {
            // デフォルト値の設定
            BlockSize = 128;
            KeySize = 128;
            Mode = CipherMode.CBC;
            Padding = PaddingMode.PKCS7;
            SaltSize = 128;
        }
    }
}
