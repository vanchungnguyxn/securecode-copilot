using System;
using System.Diagnostics;
using System.Runtime.Serialization.Formatters.Binary;

// demo C# snippets for scanner
class Demo {
  void Bad(string id, string host, Stream stream) {
    var cmd = new SqlCommand("SELECT * FROM Users WHERE Id=" + id, conn);
    Process.Start("cmd.exe", "/c ping " + host);
    var bf = new BinaryFormatter();
    var obj = bf.Deserialize(stream);
    Response.Write(Request.QueryString["name"]);
    string ApiKey = "sk-live-super-secret-key-123456";
  }
}
