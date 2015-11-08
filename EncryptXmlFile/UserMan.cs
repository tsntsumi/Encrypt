using System;
using System.Collections.Generic;

namespace EncryptXmlFile
{
	[System.Xml.Serialization.XmlRoot]
	public class UserMan
	{
		public List<User> UserList { get; set; }
	}

	public class User
	{
		public string UserID { get; set; }
		public string UserName { get; set; }
	}
}

