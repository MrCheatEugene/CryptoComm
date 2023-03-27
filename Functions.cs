using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.DirectoryServices;
using System.Collections;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace Cryptocomm
{
    class Functions
    {

        public static byte[] Combine(byte[] first, byte[] second)
        {
            byte[] bytes = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, bytes, 0, first.Length);
            Buffer.BlockCopy(second, 0, bytes, first.Length, second.Length);
            return bytes;
        }

        public string MD5OfBuild()
        {
            System.Security.Cryptography.MD5CryptoServiceProvider md5 = new System.Security.Cryptography.MD5CryptoServiceProvider();
            System.IO.FileStream stream = new System.IO.FileStream(System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName, System.IO.FileMode.Open, System.IO.FileAccess.Read);

            md5.ComputeHash(stream);

            stream.Close();

            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            for (int i = 0; i < md5.Hash.Length; i++)
                sb.Append(md5.Hash[i].ToString("x2"));

            return sb.ToString().ToUpperInvariant();
        }

        public static bool PingHost(string nameOrAddress, int timeout = 20)
        {
            bool pingable = false;
            Ping pinger = null;

            try
            {
                pinger = new Ping();
                PingReply reply = pinger.Send(nameOrAddress, timeout);
                pingable = reply.Status == IPStatus.Success;
            }
            catch (PingException)
            {
                // Discard PingExceptions and return false;
            }
            finally
            {
                if (pinger != null)
                {
                    pinger.Dispose();
                }
            }

            return pingable;
        }

        public List<string> GetAddrs()// кривой-косой метод, зато рабочий ¯\_(ツ)_/¯
        {
            System.DirectoryServices.DirectoryEntry winNtDirectoryEntries = new System.DirectoryServices.DirectoryEntry("WinNT:");
            List<String> computerNames = (from DirectoryEntry availDomains in winNtDirectoryEntries.Children
                                          from DirectoryEntry pcNameEntry in availDomains.Children
                                          where pcNameEntry.SchemaClassName.ToLower().Contains("computer")
                                          select pcNameEntry.Name).ToList();
            return computerNames;
        }
    }

    public sealed class SslTcpServer
    {
        private static RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(1024);
        static X509Certificate serverCertificate = null;
        private static byte[] clientKey = new byte[4096];
        // The certificate parameter specifies the name of the file
        // containing the machine certificate.
        public static void RunServer(string certificate)

        {
            clientKey[0] = 0x00;
            Console.WriteLine(certificate);
            serverCertificate = new X509Certificate(certificate,"");
            // Create a TCP/IP (IPv4) socket and listen for incoming connections.
            TcpListener listener = new TcpListener(IPAddress.Any, 6000);
            listener.Start();
            while (true)
            {
                Console.WriteLine("Waiting for a client to connect...");
                // Application blocks while waiting for an incoming connection.
                // Type CNTL-C to terminate the server.
                TcpClient client = listener.AcceptTcpClient();
                ProcessClient(client);
            }
        }
        static void ProcessClient(TcpClient client)
        {
            // A client has connected. Create the
            // SslStream using the client's network stream.
            SslStream sslStream = new SslStream(
                client.GetStream(), false);
            // Authenticate the server but don't require the client to authenticate.
            try
            {
                sslStream.AuthenticateAsServer(serverCertificate, false, SslProtocols.Ssl3, false);
                // Display the properties and settings for the authenticated stream.
                DisplaySecurityLevel(sslStream);
                DisplaySecurityServices(sslStream);
                DisplayCertificateInformation(sslStream);
                DisplayStreamProperties(sslStream);

                // Set timeouts for the read and write to 5 seconds.
                sslStream.ReadTimeout = 5000;
                sslStream.WriteTimeout = 5000;
                // Read a message from the client.

                Console.WriteLine("Waiting for client message...");
                string messageData = ReadMessage(sslStream);
                byte[] rawmd = Encoding.UTF8.GetBytes(messageData);
                Console.WriteLine(BitConverter.ToString(rawmd));
                if (rawmd[0] == 0x05 && rawmd[1] == 0xEF && rawmd[2] == 0xBF && rawmd[3] == 0xBD && rawmd[4] == 0xEF && rawmd[5] == 0xBF && rawmd[6] == 0xBD && clientKey[0]==0x00)
                {
                    byte[] handshake = { 0x05, 0x85, 0x85, 0x01, 0x03, 0x00 };
                    clientKey = Encoding.UTF8.GetBytes(messageData.Replace(Encoding.UTF8.GetString(handshake),"")) ;
                    Console.WriteLine("Обмен ключами, ключ клиента");
                    Console.WriteLine(Encoding.UTF8.GetString(clientKey));
                    byte[] messsage = { 0x05, 0x85, 0x85, 0x01, 0x03, 0x00 };// "мой ключ - ..."
                    messsage = Functions.Combine(messsage, Encoding.UTF8.GetBytes(rsa.ToXmlString(false) + "<EOF>"));
                    sslStream.Write(messsage);
                    string prepd = Encoding.UTF8.GetString(clientKey).Replace("<RSAKeyValue><Modulus>", "").Replace("</Modulus><Exponent>AQAB</Exponent></RSAKeyValue><EOF>", "");
                    MessageBox.Show("Подключение успешно. Ключ клиента - " + prepd.Substring(0, 5) + "..." + prepd.Substring(prepd.Length - 5, 5), "Ошибка");
                }
                else
                {
                    Console.WriteLine("Received: {0}", messageData);
                    byte[] message = Encoding.UTF8.GetBytes("Hello from the server.<EOF>");
                    Console.WriteLine("Sending hello message.");
                    sslStream.Write(message);
                }

                // Write a message to the client.
            }
            catch (AuthenticationException e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                Console.WriteLine("Authentication failed - closing the connection.");
                sslStream.Close();
                client.Close();
                return;
            }
            finally
            {
                // The client stream will be closed with the sslStream
                // because we specified this behavior when creating
                // the sslStream.
                sslStream.Close();
                client.Close();
            }
        }
        static string ReadMessage(SslStream sslStream)
        {
            // Read the  message sent by the client.
            // The client signals the end of the message using the
            // "<EOF>" marker.
            byte[] buffer = new byte[2048];
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;
            do
            {
                // Read the client's test message.
                try{bytes = sslStream.Read(buffer, 0, buffer.Length);}catch(Exception e){return "";}

                // Use Decoder class to convert from bytes to UTF8
                // in case a character spans two buffers.
                Decoder decoder = Encoding.UTF8.GetDecoder();
                char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                decoder.GetChars(buffer, 0, bytes, chars, 0);
                messageData.Append(chars);
                // Check for EOF or an empty message.
                if (messageData.ToString().IndexOf("<EOF>") != -1)
                {
                    break;
                }
            } while (bytes != 0);

            return messageData.ToString();
        }
        static void DisplaySecurityLevel(SslStream stream)
        {
            Console.WriteLine("Cipher: {0} strength {1}", stream.CipherAlgorithm, stream.CipherStrength);
            Console.WriteLine("Hash: {0} strength {1}", stream.HashAlgorithm, stream.HashStrength);
            Console.WriteLine("Key exchange: {0} strength {1}", stream.KeyExchangeAlgorithm, stream.KeyExchangeStrength);
            Console.WriteLine("Protocol: {0}", stream.SslProtocol);
        }
        static void DisplaySecurityServices(SslStream stream)
        {
            Console.WriteLine("Is authenticated: {0} as server? {1}", stream.IsAuthenticated, stream.IsServer);
            Console.WriteLine("IsSigned: {0}", stream.IsSigned);
            Console.WriteLine("Is Encrypted: {0}", stream.IsEncrypted);
        }
        static void DisplayStreamProperties(SslStream stream)
        {
            Console.WriteLine("Can read: {0}, write {1}", stream.CanRead, stream.CanWrite);
            Console.WriteLine("Can timeout: {0}", stream.CanTimeout);
        }
        static void DisplayCertificateInformation(SslStream stream)
        {
            Console.WriteLine("Certificate revocation list checked: {0}", stream.CheckCertRevocationStatus);

            X509Certificate localCertificate = stream.LocalCertificate;
            if (stream.LocalCertificate != null)
            {
                Console.WriteLine("Local cert was issued to {0} and is valid from {1} until {2}.",
                    localCertificate.Subject,
                    localCertificate.GetEffectiveDateString(),
                    localCertificate.GetExpirationDateString());
            }
            else
            {
                Console.WriteLine("Local certificate is null.");
            }
            // Display the properties of the client's certificate.
            X509Certificate remoteCertificate = stream.RemoteCertificate;
            if (stream.RemoteCertificate != null)
            {
                Console.WriteLine("Remote cert was issued to {0} and is valid from {1} until {2}.",
                    remoteCertificate.Subject,
                    remoteCertificate.GetEffectiveDateString(),
                    remoteCertificate.GetExpirationDateString());
            }
            else
            {
                Console.WriteLine("Remote certificate is null.");
            }
        }
        private static void DisplayUsage()
        {
            Console.WriteLine("To start the server specify:");
            Console.WriteLine("serverSync certificateFile.cer");
            Environment.Exit(1);
        }
    }



    public class SslTcpClient
    {
        private static Aes aes = Aes.Create();
        private static Hashtable certificateErrors = new Hashtable();
        private static RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(1024);
        private static byte[] serverKey = new byte[4066];
        // The following method is invoked by the RemoteCertificateValidationDelegate.
        public static bool ValidateServerCertificate(
              object sender,
              X509Certificate certificate,
              X509Chain chain,
              SslPolicyErrors sslPolicyErrors)
        {
            return true; // костыль зато работает
        }


        public static void RunClient(string machineName, string serverName)
        {
            serverKey[0] = 0x00;
            // Create a TCP/IP client socket.
            // machineName is the host running the server application.
            TcpClient client = null;
            try
            {
                client = new TcpClient(machineName, 6000);
            }catch(SocketException e)
            {
                MessageBox.Show("Ошибка при подключении: " + e.Message, "Ошибка");
                return;
            }
            Console.WriteLine("Client connected.");
            // Create an SSL stream that will close the client's stream.
            SslStream sslStream = new SslStream(
                client.GetStream(),
                false,
                ValidateServerCertificate,
                null
                );
            // The server name must match the name on the server certificate.
            try
            {
                sslStream.AuthenticateAsClient(serverName);
            }
            catch (AuthenticationException e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                Console.WriteLine("Authentication failed - closing the connection.");
                client.Close();
                return;
            }
            byte[] helloe = { };
            helloe=rsa.Encrypt(Encoding.UTF8.GetBytes("Hello"),false);
            if (serverKey[0] == 0x00)
            {
                byte[] messsage = { 0x05, 0x85, 0x85, 0x01, 0x03, 0x00 };// "мой ключ - ..."
                messsage = Functions.Combine(messsage, Encoding.UTF8.GetBytes(rsa.ToXmlString(false) + "<EOF>"));
                // Send hello message to the server.
                sslStream.Write(messsage);
                sslStream.Flush();
            }
            else {
                sslStream.Write(helloe);
                sslStream.Flush();
            }
            // Read message from the server.
            string serverMessage = ReadMessage(sslStream);
            byte[] rawmd = Encoding.UTF8.GetBytes(serverMessage);
            if (rawmd[0] == 0x05 && rawmd[1] == 0xEF && rawmd[2] == 0xBF && rawmd[3] == 0xBD && rawmd[4] == 0xEF && rawmd[5] == 0xBF && rawmd[6] == 0xBD && serverKey[0]==0x00 )
            {
                byte[] handshake = { 0x05, 0x85, 0x85, 0x01, 0x03, 0x00 };
                serverKey = Encoding.UTF8.GetBytes(serverMessage.Replace(Encoding.UTF8.GetString(handshake), ""));
                Console.WriteLine("Обмен ключами, ключ сервера");
                Console.WriteLine(Encoding.UTF8.GetString(serverKey));
                byte[] message = { 0x05, 0x85, 0x85, 0x01, 0x03, 0x00 };// "мой ключ - ..."
                message = Functions.Combine(message, Encoding.UTF8.GetBytes(rsa.ToXmlString(false) + "<EOF>"));
                sslStream.Write(message);
                string prepd = Encoding.UTF8.GetString(serverKey).Replace("<RSAKeyValue><Modulus>", "").Replace("</Modulus><Exponent>AQAB</Exponent></RSAKeyValue><EOF>", "");
                MessageBox.Show("Подключение успешно. Ключ клиента - " + prepd.Substring(0, 5) + "..." + prepd.Substring(prepd.Length - 5, 5), "Ошибка");
            }
            else
            {
                Console.WriteLine("Server says: {0}", serverMessage);
            }
            // Close the client connection.
            client.Close();
            Console.WriteLine("Client closed.");
        }
        static string ReadMessage(SslStream sslStream)
        {
            // Read the  message sent by the server.
            // The end of the message is signaled using the
            // "<EOF>" marker.
            byte[] buffer = new byte[2048];
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;
            do
            {
                try{bytes = sslStream.Read(buffer, 0, buffer.Length);}catch(Exception e){return "";}

                // Use Decoder class to convert from bytes to UTF8
                // in case a character spans two buffers.
                Decoder decoder = Encoding.UTF8.GetDecoder();
                char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                decoder.GetChars(buffer, 0, bytes, chars, 0);
                messageData.Append(chars);
                // Check for EOF.
                if (messageData.ToString().IndexOf("<EOF>") != -1)
                {
                    break;
                }
            } while (bytes != 0);

            return messageData.ToString();
        }


        private static void DisplayUsage()
        {
            Console.WriteLine("To start the client specify:");
            Console.WriteLine("clientSync machineName [serverName]");
            Environment.Exit(1);
        }
        public static int Main2(string[] args)
        {
            string serverCertificateName = null;
            string machineName = null;
            if (args == null || args.Length < 1)
            {
                DisplayUsage();
            }
            // User can specify the machine name and server name.
            // Server name must match the name on the server's certificate.
            machineName = args[0];
            if (args.Length < 2)
            {
                serverCertificateName = machineName;
            }
            else
            {
                serverCertificateName = args[1];
            }
            SslTcpClient.RunClient(machineName, serverCertificateName);
            return 0;
        }
    }
}

