using System;
using System.Text;
using System.IO;
using Encrypt;

namespace EncryptFileAppend
{
	/// <summary>
	/// 引数で指定された暗号化ファイルの末尾に、指定された文字列を追加するプログラム。
	/// </summary>
	/// <remarks>
	/// 指定されたファイル名に .enc 拡張子がついていない場合はエラーメッセージを表示して終了します。
	/// </remarks>
	class MainClass
	{
		/// <summary>
		/// プログラムの名前。
		/// </summary>
		private static readonly string ProgramName = "EncryptFileAppend";

		/// <summary>
		/// プログラムのエントリーポイント。
		/// </summary>
		/// <param name="args">コマンドライン引数。</param>
		public static void Main(string[] args)
		{
			if (args.Length != 2)
			{
				Console.WriteLine("Usage: {0} FILE TEXT", ProgramName);
				return;
			}
			var inputFileName = args[0];
			var appendingText = args[1];
			var extension = Path.GetExtension(inputFileName);
			if (extension != ".enc")
			{
				Console.WriteLine("{0}: Bad extension ({1})", ProgramName, extension);
				return;
			}
			try
			{
				Encryptor.AppendTextToFile(inputFileName, appendingText, "Easy#Password", new UTF8Encoding(false));
			}
			catch (Exception ex)
			{
				Console.WriteLine("{0}: {1}", ProgramName, ex.Message);
				Console.WriteLine(ex.StackTrace);
			}
		}
	}
}
