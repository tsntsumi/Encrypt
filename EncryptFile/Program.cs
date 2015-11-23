using System;
using System.IO;
using Encrypt;

namespace EncryptFile
{
	/// <summary>
	/// 引数で指定されたファイルを暗号化するコンソールアプリケーション。
	/// </summary>
	/// <remarks>
	/// 暗号化したファイルの内容は、元のファイル名の末尾に .enc 拡張子をつけたファイルに保存します。
	/// すでにその名前のファイルが存在する場合は、上書きします。
	/// </remarks>
	class MainClass
	{
		/// <summary>
		/// プログラムの名前。
		/// </summary>
		private static readonly string ProgramName = "EncryptFile";

		/// <summary>
		/// プログラムのエントリーポイント。
		/// </summary>
		/// <param name="args">コマンドライン引数。</param>
		public static void Main(string[] args)
		{
			if (args.Length != 1)
			{
				Console.WriteLine("Usage: {0} FILE", ProgramName);
				return;
			}
			var inputFileName = args[0];
			var outputFileName = inputFileName + ".enc";
			var password = "Easy#Password";
			try
			{
                Encryptor.Encrypt(inputFileName, outputFileName, password);
			}
			catch (Exception ex)
			{
				Console.WriteLine("{0}: {1}", ProgramName, ex.Message);
				Console.WriteLine(ex.StackTrace);
			}
		}
	}
}
