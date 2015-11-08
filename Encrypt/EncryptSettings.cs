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
		/// 暗号化に使用するブロック長をビット数で設定または取得します。
		/// </summary>
		public int BlockSize { get; set; }
		/// <summary>
		/// 暗号化に使用する鍵長をビット数で設定または取得します。
		/// </summary>
		public int KeySize { get; set; }
		/// <summary>
		/// 暗号化に使用するブロック暗号化モードを設定または取得します。
		/// </summary>
		public CipherMode Mode { get; set; }
		/// <summary>
		/// 暗号化に使用するパディングモードを設定または取得します。
		/// </summary>
		public PaddingMode Padding { get; set; }
		/// <summary>
		/// 暗号化に使用するソルト長をバイト数で設定または取得します。
		/// </summary>
		public int SaltBytes { get; set; }
		/// <summary>
		/// 暗号化に使用する鍵長をバイト数で設定または取得します。
		/// </summary>
		public int KeyBytes { get; set; }

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
			SaltBytes = 16;
			KeyBytes = 16;
		}
	}
}

