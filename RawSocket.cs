using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace ComputerNetworkFinal
{
    [StructLayout(LayoutKind.Explicit)]
    public struct IpHeader
    {
        [FieldOffset(0)] public readonly byte ip_version__header_length; // IP version and IP Header length
        [FieldOffset(1)] public readonly byte ip_tos; // Type of service
        [FieldOffset(2)] public readonly byte ip_total_length_0;
        [FieldOffset(3)] public readonly byte ip_total_length_1;// total length of the packet
        [FieldOffset(4)] public readonly byte ip_id_0;
        [FieldOffset(5)] public readonly byte ip_id_1;// unique identifier
        [FieldOffset(6)] public readonly byte ip_flag_offset_0;
        [FieldOffset(7)] public readonly byte ip_flag_offset_1;// flags and offset
        [FieldOffset(8)] public readonly byte ip_ttl; // Time To Live
        [FieldOffset(9)] public readonly byte ip_protocol; // protocol (TCP, UDP etc)
        [FieldOffset(10)] public readonly byte ip_checksum_0;
        [FieldOffset(11)] public readonly byte ip_checksum_1;//IP Header checksum
        [FieldOffset(12)] public readonly uint ip_src_address; //Source address
        [FieldOffset(16)] public readonly uint ip_dest_address; //Destination Address
    }

    internal class RawSocket
    {
        private readonly Socket _socket;
        private readonly byte[] _buffer;
        public RawSocket(string ip)
        {
            _buffer = new byte[65536];
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP) { Blocking = true };
            _socket.Bind(new IPEndPoint(IPAddress.Parse(ip), 0));
            _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, 1);
            byte[] IN = { 1, 0, 0, 0 };
            byte[] OUT = { 0, 0, 0, 0 };
            _socket.IOControl(IOControlCode.ReceiveAll, IN, OUT);
        }

        //转换为0.0.0.0形式的IP地址
        private string ToStandardIP(uint ip)
        {
            var bIp = new byte[4];
            bIp[0] = (byte) (ip & 0x000000ff);
            bIp[1] = (byte) ((ip & 0x0000ff00) >> 8);
            bIp[2] = (byte) ((ip & 0x00ff0000) >> 16);
            bIp[3] = (byte) ((ip & 0xff000000) >> 24);
            return bIp[0] + "." + bIp[1] + "." + bIp[2] + "." + bIp[3];
        }

        //将读取到的buffer解析出来
        private unsafe void ParseReceivedBuffer(byte[] buffer, int size)
        {
            if (buffer == null) return;

            fixed (byte* pBuffer = buffer)
            {
                var header = (IpHeader*) pBuffer;
                string ipSrcAddress = ToStandardIP(header->ip_src_address);
                string ipDestAddress = ToStandardIP(header->ip_dest_address);
                string protocol;
                switch (header->ip_protocol)
                {
                    case 1:
                        protocol = "ICMP";
                        break;
                    case 2:
                        protocol = "IGMP";
                        break;
                    case 6:
                        protocol = "TCP";
                        break;
                    case 17:
                        protocol = "UDP";
                        break;
                    case 88:
                        protocol = "EIGRP";
                        break;
                    case 89:
                        protocol = "OSPF";
                        break;
                    default:
                        protocol = "UNKNOWN";
                        break;
                }
                var totalLength = (header->ip_total_length_0 << 8) + header->ip_total_length_1;
                var id = (header->ip_id_0 << 8) + header->ip_id_1;
                var flagOffset = (header->ip_flag_offset_0 << 8) + header->ip_flag_offset_1;
                var flag = header->ip_flag_offset_0 >> 5;
                var r = (flag & 0b100) >> 2;
                var df = (flag & 0b010) >> 1;
                var mf = flag & 0b001;
                var offset = ((header->ip_flag_offset_0 & 0b00011111) << 8) + header->ip_flag_offset_1;
                var checksum = (header->ip_checksum_0 << 8) + header->ip_checksum_1;
                Console.WriteLine($"{ipSrcAddress} => {ipDestAddress}");
                Console.WriteLine($"版本 {(header->ip_version__header_length & 0xf0) >> 4} 首部长度 {header->ip_version__header_length & 0x0f}");
                Console.WriteLine($"总长度 {totalLength}");
                Console.WriteLine($"标识 {id}");
                Console.WriteLine($"标志/片偏移 {flagOffset}");
                Console.WriteLine($"R {r} DF {df} MF {mf} 片偏移 {offset}");
                Console.WriteLine($"TTL {header->ip_ttl}");
                Console.WriteLine($"协议 {protocol}");
                Console.WriteLine($"首部校验和 {checksum}");
                Console.WriteLine();

            }
        }

        private void Close()
        {
            if (_socket != null)
                try
                {
                    _socket.Shutdown(SocketShutdown.Both);
                    _socket.Close();
                }
                catch (Exception)
                {
                    Console.WriteLine("关闭socket错误!");
                }
        }

        public void Start()
        {
            while (true)
            {
                Receive();
            }
            
        }

        private void Receive()
        {
            _socket.Receive(_buffer);
            ParseReceivedBuffer(_buffer, _buffer.Length);
        }


        ~RawSocket()
        {
            Close();
        }
    }
}