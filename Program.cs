using System.Net.Mime;

namespace ComputerNetworkFinal
{
    internal static class Program
    {
        private static readonly string IP = "192.168.123.182";
        public static void Main(string[] args)
        {
            var socket = new RawSocket(IP);
            socket.Start();
        }
    }
}