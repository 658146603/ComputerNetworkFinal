using System;
using System.Net;
using System.Net.Mime;
using System.Net.Sockets;

namespace ComputerNetworkFinal
{
    internal static class Program
    {
        private static readonly string IP = GetLocalIP();//"192.168.43.150";
        public static void Main(string[] args)
        {
            var socket = new RawSocket(IP);
            socket.Start();
        }

        public static string GetLocalIP()
        {
            try
            {
                string HostName = Dns.GetHostName(); //得到主机名
                IPHostEntry IpEntry = Dns.GetHostEntry(HostName);
                for (int i = 0; i < IpEntry.AddressList.Length; i++)
                {
                    //从IP地址列表中筛选出IPv4类型的IP地址
                    //AddressFamily.InterNetwork表示此IP为IPv4,
                    //AddressFamily.InterNetworkV6表示此地址为IPv6类型
                    if (IpEntry.AddressList[i].AddressFamily == AddressFamily.InterNetwork)
                    {
                        return IpEntry.AddressList[i].ToString();
                    }
                }
                return "";
            }
            catch (Exception) {
                return "";
            }
        }
    }
}