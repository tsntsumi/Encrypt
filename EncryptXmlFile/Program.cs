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
				}
			}
			// オブジェクトを暗号化して保存します。
			using (var encryptor = new Encryptor("userMan.xml.enc", password))
			{
				serializer.Serialize(encryptor.EncryptStream, userMan);
			}
			// 暗号化したファイルを復号化して、オブジェクトに読み込みます。
			using (var decryptor = new Decryptor("UserMan.xml.enc", password))
			{
				UserMan decryptedUserMan = serializer.Deserialize(decryptor.DecryptStream) as UserMan;
				foreach (var user in decryptedUserMan.UserList)
				{
					Console.WriteLine("User ID: {0}", user.UserID);
					Console.WriteLine("User Name: {0}", user.UserName);
				}
			}
		}
	}
}
