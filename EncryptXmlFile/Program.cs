using System;
using System.Collections.Generic;
using System.IO;
using System.Xml.Serialization;
using Encrypt;

namespace EncryptXmlFile
{
	/// <summary>
	/// UserMan.xml ファイルを読み込んで、UserMan.xml.enc に暗号化して保存し、再度復号化して読み込むサンプルプログラム。
	/// </summary>
	class MainClass
	{
		/// <summary>
		/// プログラムのエントリーポイント。
		/// </summary>
		/// <param name="args">コマンドライン引数。</param>
		public static void Main(string[] args)
		{
			var password = "Easy#Password";
			var serializer = new XmlSerializer(typeof(UserMan));
			UserMan userMan;

			// XML ファイルの内容をオブジェクトに読み込みます。
			using (var userManStream = new FileStream("UserMan.xml", FileMode.Open, FileAccess.Read))
			{
				userMan = serializer.Deserialize(userManStream) as UserMan;
				foreach (var user in userMan.UserList)
				{
					Console.WriteLine("User ID: {0}", user.UserID);
					Console.WriteLine("User Name: {0}", user.UserName);
					user.UserName = user.UserName;
				}
			}
			// オブジェクトを暗号化して保存します。
			using (var memoryStream = new MemoryStream())
			{
				serializer.Serialize(memoryStream, userMan);
				memoryStream.Seek(0, SeekOrigin.Begin);
				using (var outputStream = new FileStream("UserMan.xml.enc", FileMode.OpenOrCreate, FileAccess.Write))
				{
					Encryptor.Encrypt(memoryStream, outputStream, password);
				}
			}
			// 暗号化したファイルを復号化して、オブジェクトに読み込みます。
			using (var inputStream = new FileStream("UserMan.xml.enc", FileMode.Open, FileAccess.Read))
			using (var memoryStream = new MemoryStream())
			using (var decryptor = new Decryptor(inputStream, memoryStream, password))
			{
				decryptor.Decrypt();
				memoryStream.Seek(0, SeekOrigin.Begin);
				UserMan decryptedUserMan = serializer.Deserialize(memoryStream) as UserMan;
				foreach (var user in decryptedUserMan.UserList)
				{
					Console.WriteLine("User ID: {0}", user.UserID);
					Console.WriteLine("User Name: {0}", user.UserName);
				}
			}
		}
	}
}
