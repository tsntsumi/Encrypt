using System;
using System.IO;
using Encrypt;

namespace DecryptFile
{
	/// <summary>
	/// 引数で指定されたファイルを復号化するコンソールアプリケーション。
	/// </summary>
	/// <remarks>
	/// 復号化したファイルの内容は、指定されたファイル名の末尾の .enc 拡張子を取り除いたファイルに保存します。
	/// すでにその名前のファイルが存在する場合は、上書きします。
	/// 指定されたファイル名に .enc 拡張子がついていない場合はエラーメッセージを表示して終了します。
	/// </remarks>
	class MainClass
	{
		/// <summary>
		/// プログラムの名前。
		/// </summary>
		private static readonly string ProgramName = "DecryptFile";

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
			var extension = Path.GetExtension(inputFileName);
			if (extension != ".enc")
			{
				Console.WriteLine("{0}: Bad extension ({1})", ProgramName, extension);
				return;
			}
			var outputFileName = Path.Combine(
				Path.GetDirectoryName(inputFileName),
				Path.GetFileNameWithoutExtension(inputFileName));
			var password = "Easy#Password";
			try
			{
				Decryptor.CopyFile(inputFileName, outputFileName, password);
			}
			catch (Exception ex)
			{
				Console.WriteLine("{0}: {1}", ProgramName, ex.Message);
				Console.WriteLine(ex.StackTrace);
			}
		}
	}
}
