using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace PIVUtil
{
    internal class Program
    {
        public const int NO_ERROR = unchecked((int)0x00000000);

        public enum scope : uint
        {
            SCARD_SCOPE_USER = 0,
            SCARD_SCOPE_TERMINAL = 1,
            SCARD_SCOPE_SYSTEM = 2
        };

        public enum share : uint
        {
            SCARD_SHARE_EXCLUSIVE = 1,
            SCARD_SHARE_SHARED = 2,
            SCARD_SHARE_DIRECT = 3
        }

        public enum protocol : uint
        {
            SCARD_PROTOCOL_UNDEFINED = 0x00000000,
            SCARD_PROTOCOL_T0 = 0x00000001,
            SCARD_PROTOCOL_T1 = 0x00000002,
            SCARD_PROTOCOL_T0orT1 = 0x00000003,
            SCARD_PROTOCOL_RAW = 0x00010000
        }

        public enum disposition : uint
        {
            SCARD_LEAVE_CARD = 0,
            SCARD_RESET_CARD = 1,
            SCARD_UNPOWER_CARD = 2,
            SCARD_EJECT_CARD = 3
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SCARD_IO_REQUEST
        {
            public protocol dwProtocol;
            public UInt32 cbPciLength;
        }

        static public IntPtr context = IntPtr.Zero;

        static public IntPtr cardHandle = IntPtr.Zero;

        static public protocol activeProtocol = 0;

        //imports
        [DllImport("winscard.dll", EntryPoint = "SCardConnectA", CharSet = CharSet.Ansi)]
        static extern uint SCardConnect(IntPtr context, String reader, share ShareMode, protocol PreferredProtocols, out IntPtr cardHandle, out protocol ActiveProtocol);
        
        [DllImport("winscard.dll")]
        static extern uint SCardDisconnect(IntPtr hCard, disposition Disposition);
        
        [DllImport("winscard.dll")]
        static extern uint SCardGetAttrib(IntPtr hCard, uint AttrId, byte[] Attrib, ref int AttribLen);
        
        [DllImport("winscard.dll", EntryPoint = "SCardListReadersA", CharSet = CharSet.Ansi)]
        static extern uint SCardListReaders(IntPtr hContext, byte[] mszGroups, byte[] mszReaders, ref UInt32 pcchReaders);
        
        [DllImport("winscard.dll")]
        static extern uint SCardEstablishContext(scope Scope, IntPtr reserved1, IntPtr reserved2, out IntPtr context);
        
        [DllImport("winscard.dll")]
        static extern uint SCardIsValidContext(IntPtr context);
        [DllImport("WinScard.dll")]
        public static extern uint SCardTransmit(IntPtr hCard, ref SCARD_IO_REQUEST pioSendRequest, Byte[] SendBuff, int SendBuffLen, ref SCARD_IO_REQUEST pioRecvRequest, Byte[] RecvBuff, ref int RecvBuffLen);

        [DllImport("winscard.dll")]
        static extern int SCardStatus(uint hCard, IntPtr szReaderName, ref int pcchReaderLen, ref int pdwState, ref uint pdwProtocol, byte[] pbAtr, ref int pcbAtrLen);

        //help functions
        public static String[] ListReaders()
        {
            string[] readers;
            UInt32 pcchReaders = 0;
            SCardListReaders(context, null, null, ref pcchReaders);
            byte[] mszReaders = new byte[pcchReaders];
            SCardListReaders(context, null, mszReaders, ref pcchReaders);
            System.Text.ASCIIEncoding asc = new System.Text.ASCIIEncoding();
            String[] Readers = asc.GetString(mszReaders).Split('\0');
            if (Readers.Length > 2)
            {
                String[] res = new String[Readers.Length - 2];
                int j = 0;
                for (int i = 0; i < Readers.Length; i++)
                {
                    if (Readers[i] != "" && Readers[i] != null)
                    {
                        res[j] = Readers[i];
                        j++;
                    }
                }
                readers = res;
                return readers;
            }
            else
            {
                readers = new String[0];
                return readers;
            }
        }

        public static bool Connect(String reader, share ShareMode, protocol PreferredProtocols)
        {
            uint ris = SCardConnect(context, reader, ShareMode, PreferredProtocols, out cardHandle, out activeProtocol);
            if (ris != 0)
                return false;
            return true;
        }

        public void Disconnect(disposition Disposition)
        {
            if (cardHandle != IntPtr.Zero)
                SCardDisconnect(cardHandle, Disposition);
            cardHandle = IntPtr.Zero;
        }

        public byte[] GetAttrib(uint attrib)
        {
            int AttrLen = 0;
            uint ris = SCardGetAttrib(cardHandle, attrib, null, ref AttrLen);
            if (ris != 0)
                return null;
            byte[] Attr = new byte[AttrLen];
            ris = SCardGetAttrib(cardHandle, attrib, Attr, ref AttrLen);
            if (ris != 0)
                return null;
            return Attr;
        }

        public static string hexDump(byte[] input)
        {
            StringBuilder sbBytes = new StringBuilder(input.Length * 2);
            for(int i = 0; i < input.Length; i++)
            {
                sbBytes.AppendFormat("{0:X2}", input[i]);
            }
            return sbBytes.ToString();
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static byte[] send(byte[] buff_send)
        {
            SCARD_IO_REQUEST io_send = new SCARD_IO_REQUEST();
            io_send.dwProtocol = activeProtocol;
            io_send.cbPciLength = (uint)Marshal.SizeOf(typeof(SCARD_IO_REQUEST));

            SCARD_IO_REQUEST io_recv = new SCARD_IO_REQUEST();
            io_recv.dwProtocol = activeProtocol;
            io_recv.cbPciLength = (uint)Marshal.SizeOf(typeof(SCARD_IO_REQUEST));

            byte[] buff_recv = new byte[1024];
            int recv_len = 1024;
            var ret = SCardTransmit(cardHandle, ref io_send, buff_send, buff_send.Length, ref io_recv, buff_recv, ref recv_len);
            
            //Console.WriteLine(String.Format("SCardTransmit: {0}, recv_len: {1}", ret, recv_len));
            //if (recv_len > 1)
            //{
            //    Console.WriteLine(hexDump(buff_recv));
            //}

            return buff_recv.Take(recv_len).ToArray();
        }

        static byte[] downloadData(byte[] command)
        {
            byte[] recv = new byte[] { };
            byte[] recv2 = new byte[] { };
            byte[] status = new byte[] { };

            //reset
            recv = send(new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00 });

            //https://docs.yubico.com/yesdk/users-manual/application-piv/piv-objects.html
            recv = send(command);
            if (recv.Length < 4)
            {
                return recv2;
            }

            recv = recv.Take(recv.Length - 2).ToArray();
            status = recv.Skip(recv.Length - 2).ToArray();
            //Console.WriteLine(hexDump(status));
            //Console.WriteLine(hexDump(recv));

            if(!status.SequenceEqual(new byte[] { 0x2A, 0x86 }))
            {
                return recv2;
            }

            //get large response
            while (true)
            {
                recv2 = send(new byte[] { 0x00, 0xC0, 0x00, 0x00 });
                recv = recv.Concat(recv2.Take(recv2.Length - 2).ToArray()).ToArray();
                status = recv2.Skip(recv2.Length - 2).ToArray();
                //Console.WriteLine(hexDump(status));
                //Console.WriteLine(hexDump(recv2));
                if (status.SequenceEqual(new byte[] { 0x90, 00 }))
                {
                    break;
                }
                if (recv2.All(singleByte => singleByte == 0))
                {
                    break;
                }
            }

            return recv;
        }

        static void PrintUsage()
        {
            Console.WriteLine("Usage: cs-smartcard.exe list");
            Console.WriteLine("Usage: cs-smartcard.exe <card name>");
            Console.WriteLine("Usage: cs-smartcard.exe <card name> <pin> <data to sign> <data to sign>");
            return;
        }

        static void Main(string[] args)
        {
            if(args.Length < 1)
            {
                PrintUsage();
                return;
            }
            if(args.Length == 1 && args[0] == "list")
            {
                Console.WriteLine();
                foreach (string r in ListReaders())
                {
                    Console.WriteLine(String.Format("[*] {0}",r));
                }
                return;
            }
            if(args.Length < 1)
            {
                PrintUsage();
                return;
            }

            string reader = args[0];
            uint ret;
            ret = SCardEstablishContext(scope.SCARD_SCOPE_SYSTEM, IntPtr.Zero, IntPtr.Zero, out context);

            if(ret == NO_ERROR)
            {
                string[] readers = ListReaders();
                if (!readers.Contains(reader))
                {
                    Console.WriteLine(String.Format("\n [-] Driver not found!"));
                    return;
                }
                Console.WriteLine(String.Format("\n [*]Using smartcard: {0}", reader));

                if (Connect(reader, share.SCARD_SHARE_SHARED, protocol.SCARD_PROTOCOL_T0orT1))
                {
                    if (args.Length > 2)
                    {
                        byte[] recv = new byte[] { };
                        byte[] recv2 = new byte[] { };
                        byte[] status = new byte[] { };

                        //reset
                        //send(new byte[] { 0x00, 0xa4, 0x04, 0x00, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08 });
                        send(new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00 });
                        //Console.WriteLine(hexDump(recv));

                        //Verify PIN
                        string pin = args[1];
                        Console.WriteLine(String.Format("[*] Using pin: {0}", pin));
                        byte[] pin_bytes = Encoding.ASCII.GetBytes(pin);
                        while (pin_bytes.Length < 8)
                        {
                            pin_bytes = pin_bytes.Concat(new byte[] { 0xff }).ToArray();
                        }
                        byte[] pin_packet = new byte[] { 0x00, 0x20, 0x00, 0x80, 0x08 };
                        pin_packet = pin_packet.Concat(pin_bytes).ToArray();
                        recv = send(pin_packet);
                        if (!recv.SequenceEqual(new byte[] { 0x90, 0x00 }))
                        {
                            Console.WriteLine(String.Format("[-] Wrong PIN! {0}", hexDump(recv)));
                            return;
                        }
                        //Console.WriteLine(hexDump(recv));

                        //Send data to sign
                        for (int i = 2; i < args.Length; i++)
                        {
                            recv = send(StringToByteArray(args[i]));
                            //Console.WriteLine(hexDump(recv));
                        }
                        recv = recv.Take(recv.Length - 2).ToArray();
                        status = recv.Skip(recv.Length - 2).ToArray();
                        //Console.WriteLine(hexDump(recv));

                        //get large response
                        while (true)
                        {
                            recv2 = send(new byte[] { 0x00, 0xC0, 0x00, 0x00 });
                            recv = recv.Concat(recv2.Take(recv2.Length - 2).ToArray()).ToArray();
                            status = recv2.Skip(recv2.Length - 2).ToArray();
                            //Console.WriteLine(hexDump(status));
                            //Console.WriteLine(hexDump(recv2));
                            if (status.SequenceEqual(new byte[] { 0x90, 00 }))
                            {
                                break;
                            }
                            if(recv2.All(singleByte => singleByte == 0))
                            {
                                break;
                            }
                        }

                        Console.WriteLine(hexDump(recv));


                    }
                    else
                    {
                        //Auth (cert) 9A
                        byte[] _9A = downloadData(new byte[] { 0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, 0x5f, 0xc1, 0x05, 0x00 });
                        if(_9A.Length > 0)
                        {
                            _9A = _9A.Skip(8).ToArray();
                            _9A = _9A.Take(_9A.Length - 5).ToArray();
                            Console.WriteLine(String.Format("[*] Public Auth (cert) Slot 9A:"));
                            Console.WriteLine(hexDump(_9A));
                        }

                        //Signature (cert) 9C
                        byte[] _9C = downloadData(new byte[] { 0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, 0x5f, 0xc1, 0x0A, 0x00 });
                        if (_9C.Length > 0)
                        {
                            _9C = _9C.Skip(8).ToArray();
                            _9C = _9C.Take(_9C.Length - 5).ToArray();
                            Console.WriteLine(String.Format("[*] Public Signature (cert) Slot 9C:"));
                            Console.WriteLine(hexDump(_9C));
                        }

                        //Key Mgmt (cert) 9D
                        byte[] _9D = downloadData(new byte[] { 0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, 0x5f, 0xc1, 0x0B, 0x00 });
                        if (_9D.Length > 0)
                        {
                            _9D = _9D.Skip(8).ToArray();
                            _9D = _9D.Take(_9D.Length - 5).ToArray();
                            Console.WriteLine(String.Format("[*] Public Key Mgmt (cert) Slot 9D:"));
                            Console.WriteLine(hexDump(_9D));
                        }

                        //Card Auth (cert) 9E
                        byte[] _9E = downloadData(new byte[] { 0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, 0x5f, 0xc1, 0x01, 0x00 });
                        if (_9E.Length > 0)
                        {
                            _9E = _9E.Skip(8).ToArray();
                            _9E = _9E.Take(_9E.Length - 5).ToArray();
                            Console.WriteLine(String.Format("[*] Public Card Auth (cert) Slot 9E:"));
                            Console.WriteLine(hexDump(_9E));
                        }
                    }
                }
            }
        }
    }
}
