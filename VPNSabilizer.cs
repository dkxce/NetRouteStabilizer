using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Text.RegularExpressions;

namespace NetRouteStabilizer
{
    public class Stabilizer
    {
        public class StabilizerConfig
        {
            public string LogDateTimeFormat { get; set; } = "dd HH:mm:ss";

            public string VPNGateway { get; set; } = "10.211.254.254";
            public long VPNGateNormalMetric { get; set; } = 1111;
            public long VPNGateTriggerMetric { get; set; } = 999;

            public string NormalGateway { get; set; } = "192.168.177.254";
            public long NormalMetric { get; set; } = 35;

            public List<string> Proxies { get; set; } = new List<string>() { 
                "161.115.230.27",
                "85.195.81.161" };
            public long ProxiesMetric { get; set; } = 20;
            public bool ProxiesKeepRestart { get; set; } = false;

            public List<string> Telegram { get; set; } = new List<string>() { 
                "149.154.160.0/255.255.240.0",
                "149.154.176.0/255.255.240.0",
                "91.108.4.0/255.255.252.0",
                "91.108.8.0/255.255.252.0",
                "91.108.12.0/255.255.252.0",
                "91.108.16.0/255.255.252.0",
                "91.108.56.0/255.255.252.0",
                "5.28.16.0/255.255.248.0",
                "5.28.24.0/255.255.248.0",
                "109.239.140.0/255.255.255.0" };
            public long TelegramMetric { get; set; } = 20;
            public bool TelegramKeepRestart { get; set; } = false;

            public bool Rotate3Proxy { get; set; } = true;
            public bool Rotate3ProxyRestart { get; set; } = true;
            public string Rotate3ProxyFileName { get; set; } = "\\3proxy-0.9.5-x64-dkxce\\bin64\\3proxy.cfg";
            public string Rotate3ProxyRegex { get; set; } = "external 10\\.211\\.\\d{1,3}.\\d{1,3}";
            public string Rotate3ProxyRegexInline { get; set; } = "\\s-e10\\.211\\.\\d{1,3}.\\d{1,3}";

            public List<string> Rotate3ProxyAfterAllCommands { get; set; } = new List<string>();

            public override string ToString()
            {
                string result = "";

                PropertyInfo[] properties = this.GetType().GetProperties();

                for (int i = 0; i < properties.Length; i++)
                {
                    string name = properties[i].Name;
                    string value = properties[i].GetValue(this)?.ToString() ?? "";
                    if (name == "Proxies")
                        result += (result.Length > 0 ? "\r\n" : "") + $"    {name}: `{this.Proxies.Count()}`";
                    else if (name == "Telegram")
                        result += (result.Length > 0 ? "\r\n" : "") + $"    {name}: `{this.Telegram.Count()}`";
                    else
                        result += (result.Length > 0 ? "\r\n" : "") + $"    {name}: `{value}`";
                };
                return result;
            }
        }

        public class RouteEntry
        {
            public string Network { get; set; }
            public string Mask { get; set; }
            public string Gateway { get; set; }
            public string Interface { get; set; }
            public int Metric { get; set; }

            public override string ToString()
            {
                return $"{Network}/{Mask} -> {Gateway} [{Metric}] ({Interface})";
            }
        }

        public static readonly StabilizerConfig config = new StabilizerConfig();

        static Stabilizer()
        {
            try
            {
                config = JsonConvert.DeserializeObject<StabilizerConfig>(File.ReadAllText(Path.Combine(GetCD(), "NetRouteStabilizer.json")));
            }
            catch
            {
                string data = JsonConvert.SerializeObject(config);
                File.WriteAllText(Path.Combine(GetCD(), "NetRouteStabilizer.json"), data);
            };
        }

        public static int Stabilize(string[] args)
        {
            Environment.ExitCode = 0;

            Console.WriteLine("=== https://github.com/dkxce/NetRouteStabilizer (C) dkxce 2026 ===");
            Console.WriteLine("===  dkxce VPNGate Stabilize   ===");
            Console.WriteLine("=== Для выхода нажмите Ctrl+C. ===\n");

            ParseCLI(config, args);
            Log($"LOADED VPNGATE CONFIG `NetRouteStabilizer.json`: \r\n{{\r\n{config}\r\n}} ...");

            Log($"DETECTING IP ADDRESSES");
            {
                IEnumerable<IPAddress> ips = GetLocalIpAddresses(
                    ipv4Only: true,
                    excludeLoopback: true,
                    excludeLinkLocal: true);

                foreach (IPAddress ip in ips)
                     Log($" - {ip}");
                if (ips.Count() == 0)
                    Log($" - FAILED TO GET IP ADDRESSES");
            };

            Log($"DETECTING DEFAULT ROUTES");
            List<RouteEntry> routes = GetIPRoutes("0.0.0.0");
            Log($"  FOUND DEFAULT ROUTES {routes.Count}");

            int exists = 0;
            foreach (RouteEntry er in routes)
            {
                Log($"   - {er}");
                if (er.Gateway == config.VPNGateway)
                    exists = er.Metric < config.VPNGateTriggerMetric ? 1 : 2;
            };
            if (routes.Count() == 0) Log($" - FAILED TO GET ROUTES");

            if (exists == 1)
            {
                Log($"  !!! PLEASE CHANGE SoftEtherVPN METRIC TO MANUAL VALUE {config.VPNGateNormalMetric} !!!","",ConsoleColor.DarkYellow);
                Normalize(args);
                Proximize(args);
                if(config.Rotate3Proxy) Rotate3Proxy(args);
                return 0;
            }
            if (exists == 2)
            {
                Log($"  NO NEED TO CHANGE DEFAULT METRICS", "", ConsoleColor.Green);
                Proximize(args);
                if (config.Rotate3Proxy) Rotate3Proxy(args);
                return 0;
            }
            if (exists == 0)
            {
                Log("  SoftEtherVPN ROUTE NOT FOUND", "", ConsoleColor.Magenta);
                VPNGateRotator.ProcessRotate(args);
                {
                    routes = GetIPRoutes("0.0.0.0");
                    exists = 0;
                    foreach (RouteEntry er in routes)
                        if (er.Gateway == config.VPNGateway)
                            exists = er.Metric < config.VPNGateTriggerMetric ? 1 : 2;
                };
                if (exists == 1) Normalize(args);
                if (exists == 2) Proximize(args);
                if (exists > 0 && config.Rotate3Proxy) Rotate3Proxy(args);
                if (exists == 0) Log("  SoftEtherVPN ROUTE NOT FOUND", "", ConsoleColor.Magenta);
                return 0;
            };
            Environment.ExitCode = 1;
            return 1;
        }

        public static void Direct(string[] args, bool fromCode = true)
        {
            Environment.ExitCode = 0;

            Console.WriteLine("=== https://github.com/dkxce/NetRouteStabilizer (C) dkxce 2026 ===");
            Console.WriteLine("===    dkxce VPNGate Direct Direct    ===");
            Console.WriteLine("===     Для выхода нажмите Ctrl+C.    ===\n");

            if(!fromCode) ParseCLI(config, args);
            Log("SWITCHING BACK DIRECT INTERNET");
            CmdRun("delete 0.0.0.0", "route");
            CmdRun($"add 0.0.0.0 mask 0.0.0.0 ${config.NormalGateway} metric ${config.NormalMetric}", "route");                                  

            Log($"DETECTING IP ADDRESSES");
            {
                IEnumerable<IPAddress> ips = GetLocalIpAddresses(
                    ipv4Only: true,
                    excludeLoopback: true,
                    excludeLinkLocal: true);

                foreach (IPAddress ip in ips)
                    Log($" - {ip}");

                if (ips.Count() == 0)
                    Log($" - FAILED TO GET IP ADDRESSES", "", ConsoleColor.Red);
            };

            Log($"DETECTING DEFAULT ROUTES");
            List<RouteEntry> routes = GetIPRoutes("0.0.0.0");
            Log($"  FOUND DEFAULT ROUTES {routes.Count}");
            foreach (RouteEntry er in routes) Log($"   - {er}");
            if (routes.Count() == 0)
                Log($" - FAILED TO GET ROUTES", "", ConsoleColor.Red);
        }

        public static void Normalize(string[] args, bool fromCode = true)
        {
            if(!fromCode)
            {
                Console.WriteLine("=== https://github.com/dkxce/NetRouteStabilizer (C) dkxce 2026 ===");
                Console.WriteLine("===  dkxce VPNGate Direct Normalize   ===");
                Console.WriteLine("===     Для выхода нажмите Ctrl+C.    ===\n");
            };

            if (!fromCode) ParseCLI(config, args);
            Log("SWITCHING BACK DIRECT INTERNET");
            CmdRun("delete 0.0.0.0", "route");
            CmdRun($"add 0.0.0.0 mask 0.0.0.0 ${config.NormalGateway} metric ${config.NormalMetric}", "route");
            CmdRun($"add 0.0.0.0 mask 0.0.0.0 ${config.VPNGateway} metric ${config.VPNGateNormalMetric}", "route");

            Log($"DETECTING IP ADDRESSES");
            {
                IEnumerable<IPAddress> ips = GetLocalIpAddresses(
                    ipv4Only: true,
                    excludeLoopback: true,
                    excludeLinkLocal: true);

                foreach (IPAddress ip in ips)
                    Log($" - {ip}");

                if (ips.Count() == 0)
                    Log($" - FAILED TO GET IP ADDRESSES");
            };

            Log($"DETECTING DEFAULT ROUTES");
            List<RouteEntry> routes = GetIPRoutes("0.0.0.0");
            Log($"  FOUND DEFAULT ROUTES {routes.Count}");
            foreach (RouteEntry er in routes) Log($"   - {er}");
            if (routes.Count() == 0)
                Log($" - FAILED TO GET ROUTES", "", ConsoleColor.Red);
        }

        public static void Proximize(string[] args, bool fromCode = true)
        {
            if (!fromCode)
            {
                Console.WriteLine("=== https://github.com/dkxce/NetRouteStabilizer (C) dkxce 2026 ===");
                Console.WriteLine("===  dkxce VPNGate Direct Proximize   ===");
                Console.WriteLine("===     Для выхода нажмите Ctrl+C.    ===\n");
            };

            if (!fromCode) ParseCLI(config, args);
            if (config.Proxies.Count > 0)
            {
                Log("RE-ASSIGN PROXY ROUTES");
                int rCount = 0;
                foreach (string s in config.Proxies)
                {
                    string kr = config.ProxiesKeepRestart ? " -p" : "";
                    CmdRun($"delete {s}", "route");
                    CmdRun($"add{kr} {s} mask 255.255.255.255 {config.VPNGateway} metric {config.ProxiesMetric}", "route");
                    List<RouteEntry> routes = GetIPRoutes(s);
                    foreach (RouteEntry er in routes) { rCount++; Log($" - {er}"); };
                };
                if (rCount == 0) Log($" - NO PROXY ROUTES FOUND", "", ConsoleColor.Yellow);
            };

            if (config.Telegram.Count > 0)
            {
                Log("RE-ASSIGN TELEGRAM ROUTES");
                int rCount = 0;
                foreach (string s in config.Telegram)
                {
                    string kr = config.TelegramKeepRestart ? " -p" : "";
                    string[] ipm = s.Split('/');
                    CmdRun($"delete {ipm[0]}", "route");
                    CmdRun($"add{kr} {ipm[0]} mask {ipm[1]} {config.VPNGateway} metric {config.TelegramMetric}", "route");
                    List<RouteEntry> routes = GetIPRoutes(ipm[0]);
                    foreach (RouteEntry er in routes) { rCount++; Log($" - {er}"); };
                };
                if (rCount == 0) Log($" - NO TELEGRAM ROUTES FOUND", "", ConsoleColor.Yellow);
            };
        }

        public static void Deletize(string[] args, bool fromCode = true)
        {
            if (!fromCode)
            {
                Console.WriteLine("=== https://github.com/dkxce/NetRouteStabilizer (C) dkxce 2026 ===");
                Console.WriteLine("===  dkxce VPNGate Direct Deletize    ===");
                Console.WriteLine("===     Для выхода нажмите Ctrl+C.    ===\n");
            };

            if (!fromCode) ParseCLI(config, args);
            if (config.Proxies.Count > 0)
            {
                Log("RE-ASSIGN PROXY ROUTES");
                int rCount = 0;
                foreach (string s in config.Proxies)
                {
                    string kr = config.ProxiesKeepRestart ? " -p" : "";
                    CmdRun($"delete {s}", "route");
                    List<RouteEntry> routes = GetIPRoutes(s);
                    foreach (RouteEntry er in routes) { rCount++; Log($" - {er}"); };
                };
                if (rCount == 0) Log($" - NO PROXY ROUTES FOUND", "", ConsoleColor.Yellow);
            };

            if (config.Telegram.Count > 0)
            {
                Log("RE-ASSIGN TELEGRAM ROUTES");
                int rCount = 0;
                foreach (string s in config.Telegram)
                {
                    string kr = config.TelegramKeepRestart ? " -p" : "";
                    string[] ipm = s.Split('/');
                    CmdRun($"delete {ipm[0]}", "route");
                    List<RouteEntry> routes = GetIPRoutes(ipm[0]);
                    foreach (RouteEntry er in routes) { rCount++; Log($" - {er}"); };
                };
                if (rCount == 0) Log($" - NO TELEGRAM ROUTES FOUND", "", ConsoleColor.Yellow);
            };
        }

        public static void Rotate3Proxy(string[] args, bool fromCode = true)
        {
            if (!fromCode)
            {
                Console.WriteLine("=== https://github.com/dkxce/NetRouteStabilizer (C) dkxce 2026 ===");
                Console.WriteLine("===  dkxce VPNGate Direct Deletize    ===");
                Console.WriteLine("===     Для выхода нажмите Ctrl+C.    ===\n");
            };

            if (!fromCode) ParseCLI(config, args);
            Log("RE-ASSIGN 3PROXY VPNGATE OUTGOING IP");
            string ipaddr = "0.0.0.0";
            IEnumerable<IPAddress> ips = GetLocalIpAddresses(
                    ipv4Only: true,
                    excludeLoopback: true,
                    excludeLinkLocal: true);
            foreach (IPAddress ip in ips)
            {
                if (ip.ToString().StartsWith("10.211"))
                    ipaddr = ip.ToString();
            };
            if (string.IsNullOrEmpty(ipaddr) || ipaddr == "0.0.0.0")
            {
                Log(" - NO CONNECTION FOUND", "", ConsoleColor.Red);
                return;
            };
            Log($" - VPNGate IP Address = {ipaddr}", "", ConsoleColor.Gray);

            string fn = config.Rotate3ProxyFileName;
            if (!fn.Contains(":"))
                fn = Path.Combine(GetCD(), fn.Trim(new char[] { '\\', '/' }));
            if (!File.Exists(fn))
            {
                Log(" - NO 3PROXY CONFIG FOUND", "",ConsoleColor.Red);
                return;
            };
            Log($" - CFG: {Path.GetFileName(fn)}", "", ConsoleColor.Yellow);

            string cfg = File.ReadAllText(fn);
            cfg = Regex.Replace(cfg, config.Rotate3ProxyRegex, $"external {ipaddr}");
            cfg = Regex.Replace(cfg, config.Rotate3ProxyRegexInline, $" -e{ipaddr}");
            File.WriteAllText(fn, cfg);
            if(config.Rotate3ProxyRestart)
            {
                CmdRun("stop 3proxy", "net");
                System.Threading.Thread.Sleep(3000);
                CmdRun("start 3proxy", "net");
                System.Threading.Thread.Sleep(3000);
                if (config.Rotate3ProxyAfterAllCommands.Count > 0)
                {
                    int j = 0;
                    string prefix = "";
                    for (int i = 0; i < config.Rotate3ProxyAfterAllCommands.Count; i++)
                    {
                        string s = config.Rotate3ProxyAfterAllCommands[i].Trim();
                        if (string.IsNullOrEmpty(s)) continue;
                        if (s.StartsWith("#")) prefix = " " + s.Substring(1);
                        else if (s.StartsWith("@"))
                        {
                            prefix = "";
                            string ln = s.Substring(1);
                            if(string.IsNullOrEmpty(ln)) continue;
                            Log(ln, $" - [{j++}]: ", ConsoleColor.Yellow);
                        }
                        else
                        {
                            string res = CmdRun($"/C {s}", "cmd.exe")?.Trim() ?? "";
                            Log(res, $" - [{j++}]{prefix}: ", ConsoleColor.Gray);
                        };
                    };
                };
            };
            Log($" - Completed");
        }

        static List<RouteEntry> GetIPRoutes(string destination = null)
        {
            List<RouteEntry> result = new List<RouteEntry>();

            string query = "SELECT Destination, Mask, NextHop, InterfaceIndex, Metric1 " +
                           "FROM Win32_IP4RouteTable WHERE";
            if (!string.IsNullOrEmpty(destination)) query += $" Destination = '{destination}'";

            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject route in searcher.Get())
            {

                int ifaceIndex = Convert.ToInt32(route["InterfaceIndex"]);
                string ifaceName = GetInterfaceName(ifaceIndex);

                result.Add(new RouteEntry()
                {
                    Network = route["Destination"].ToString(),
                    Mask = route["Mask"].ToString(),
                    Gateway = route["NextHop"].ToString(),
                    Interface = $"{ifaceIndex}-{ifaceName}",
                    Metric = int.Parse(route["Metric1"].ToString())
                });
            };
            return result;
        }

        private static string GetInterfaceName(int index)
        {
            var ni = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(n => n.GetIPProperties().GetIPv4Properties()?.Index == index);
            return $"{ni?.Name} ({ni?.Description})";
        }

        public static IEnumerable<IPAddress> GetLocalIpAddresses(
        bool ipv4Only = true,
        bool excludeLoopback = true,
        bool excludeLinkLocal = true,
        bool physicalOnly = false)
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni => ni.OperationalStatus == OperationalStatus.Up)
                .Where(ni => !physicalOnly || IsPhysicalInterface(ni))
                .SelectMany(ni => ni.GetIPProperties().UnicastAddresses)
                .Where(ua =>
                {
                    var addr = ua.Address;

                    // Фильтр по семейству
                    if (ipv4Only && addr.AddressFamily != AddressFamily.InterNetwork) return false;
                    if (!ipv4Only && addr.AddressFamily != AddressFamily.InterNetworkV6) return false;

                    // Исключаем loopback (127.0.0.1 / ::1)
                    if (excludeLoopback && IPAddress.IsLoopback(addr)) return false;

                    // Исключаем link-local (169.254.x.x / fe80::)
                    if (excludeLinkLocal)
                    {
                        if (addr.AddressFamily == AddressFamily.InterNetwork)
                        {
                            var b = addr.GetAddressBytes();
                            if (b[0] == 169 && b[1] == 254) return false;
                        }
                        else if (addr.AddressFamily == AddressFamily.InterNetworkV6 && addr.IsIPv6LinkLocal)
                        {
                            return false;
                        }
                    }

                    return true;
                })
                .Select(ua => ua.Address)
                .Distinct();
        }

        private static bool IsPhysicalInterface(NetworkInterface ni)
        {
            // Ethernet, Wi-Fi, мобильные данные и т.д.
            if (ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Ethernet) return true;
            if (ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Ethernet3Megabit) return true;
            if (ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.FastEthernetFx) return true;
            if (ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.FastEthernetT) return true;
            if (ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.GigabitEthernet) return true;
            if (ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Wireless80211) return true;
            return false;
        }

        private static string GetCD()
        {
            return System.IO.Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName);
        }

        public static void Log(string message = "", string prefix = "", ConsoleColor? color = null, ConsoleColor? background = null)
        {
            if (string.IsNullOrEmpty(message)) return;

            string[] lines = message.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None);
            string timestamp = DateTime.Now.ToString(config.LogDateTimeFormat);

            for (int i = 0; i < lines.Length; i++)
            {                
                Console.Write($"[{timestamp}] {prefix}");
                if (color != null) Console.ForegroundColor = color.Value;
                if (background != null) Console.BackgroundColor = background.Value;                
                Console.WriteLine($"{lines[i]}");
                if (color != null || background != null) Console.ResetColor();
            };
        }

        private static string CmdRun(string arguments, string prog = null)
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = prog ?? Process.GetCurrentProcess().MainModule.FileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Console.OutputEncoding,
                StandardErrorEncoding = Console.OutputEncoding
            };

            using (Process proc = new Process { StartInfo = psi })
            {
                proc.Start();
                string outStr = proc.StandardOutput.ReadToEnd();
                string errStr = proc.StandardError.ReadToEnd();
                proc.WaitForExit();
                return outStr + errStr;
            }
        }

        #region CLI Tools
        private static void ParseCLI(StabilizerConfig config, string[] args)
        {
            if (config == null || args == null) return;

            Type configType = config.GetType();
            foreach (var arg in args)
            {
                if (string.IsNullOrWhiteSpace(arg) || !arg.Contains("=")) continue;

                string trimmed = arg.TrimStart('/', '-', '+');
                string[] parts = trimmed.Split(new[] { '=' }, 2, StringSplitOptions.RemoveEmptyEntries);

                if (parts.Length != 2) continue;

                string paramName = parts[0].Trim();
                string paramValue = parts[1].Trim();

                // Ищем поле или свойство с таким именем (регистронезависимо)
                MemberInfo member = configType.GetMember(paramName,
                    BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase)
                    ?.FirstOrDefault(m => m.MemberType == MemberTypes.Field || m.MemberType == MemberTypes.Property);

                if (member == null) continue;

                try
                {
                    if (member is FieldInfo field)
                    {
                        var converted = ConvertValue(paramValue, field.FieldType);
                        field.SetValue(config, converted);
                    }
                    else if (member is PropertyInfo prop && prop.CanWrite)
                    {
                        var converted = ConvertValue(paramValue, prop.PropertyType);
                        prop.SetValue(config, converted);
                    }
                }
                catch { };
            }
        }

        private static object ConvertValue(string value, Type targetType)
        {
            if (targetType == typeof(string))
                return value;

            if (targetType == typeof(bool))
                return bool.TryParse(value, out var b) ? b : throw new FormatException("Must be true/false");

            if (targetType == typeof(int))
                return int.TryParse(value, out var i) ? i : throw new FormatException("Must be number");

            if (targetType == typeof(double) || targetType == typeof(float))
                return Convert.ToDouble(value, System.Globalization.CultureInfo.InvariantCulture);

            if (targetType.IsEnum)
                return Enum.Parse(targetType, value, ignoreCase: true);

            return Convert.ChangeType(value, targetType, System.Globalization.CultureInfo.InvariantCulture);
        }

        #endregion CLI Tools
    }
}