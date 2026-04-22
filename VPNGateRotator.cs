//** CLI: /rotate **//

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Newtonsoft.Json;

namespace NetRouteStabilizer
{
    public class VpnGateServer
    {
        public string HostName { get; set; } = "";
        public string IP { get; set; } = "";
        public string Score { get; set; } = "";
        public string Ping { get; set; } = "";
        public string Speed { get; set; } = "";
        public string CountryLong { get; set; } = "";
        public string CountryShort { get; set; } = "";
        public string NumVpnSessions { get; set; } = "";
        public string Uptime { get; set; } = "";
        public string TotalUsers { get; set; } = "";
        public string TotalTraffic { get; set; } = "";
        public string LogType { get; set; } = "";
        public string Operator { get; set; } = "";
        public string Message { get; set; } = "";
        public int TcpPort { get; set; } = 443;
        public bool TCP { get; set; } = true;
        public bool UDP { get; set; } = false;

        [JsonProperty(PropertyName = "_fetched_at")]
        public DateTime FetchedAt { get; set; } = DateTime.Now;
    }

    public class RotatorConfig
    {
        public string LogDateTimeFormat = "dd HH:mm:ss";

        public string VPNServersFile    { get; set; } = "vpngate_full_list.json";
        public string VPNServersFind    { get; set; } = "opengw.net";
        public string VPNAdapterName    { get; set; } = "VPN";
        public string VPNAccountFormat  { get; set; } = "%CountryShort% %HostName%.opengw.net";
        public string VPNServerFormat   { get; set; } = "%IP%/tcp:%TcpPort%";            
        public bool   VPNServerPing     { get; set; } = true;
        public bool   VPNHideStatus     { get; set; } = true;
        public int    VPNSkipOldDays    { get; set; } = 0;
        
        public int MaxExistingAttempts  { get; set; } = 5;
        public int MaxNewServerAttempts { get; set; } = 100;
        public int NewServerAttemptExistingStep { get; set; } = 0;

        public int ConnectDelay         { get; set; } = 15;
        public int DisconnectDelay      { get; set; } = 3;
        public int DetectDelay          { get; set; } = 5;

        public string[] Countries       { get; set; } = new string[] { "JP", "KR", "TW", "DE", "FR", "FI" };        
        public override string ToString()
        {
            string result = "";

            PropertyInfo[] properties = this.GetType().GetProperties();

            for (int i = 0; i < properties.Length; i++)
            {
                string name = properties[i].Name;
                string value = properties[i].GetValue(this)?.ToString() ?? "";
                if (name == "Countries")
                    result += (result.Length > 0 ? "\r\n" : "") + $"    {name}: `{string.Join(",", this.Countries)}`";
                else
                    result +=  (result.Length > 0 ? "\r\n" : "") + $"    {name}: `{value}`";
            };
            return result;
        }
    }

    public class VPNGateRotator
    {
        private const int EXIT_SUCCESS    = 0;
        private const int EXIT_FAILURE    = 1;
        private const int EXIT_NO_JSON    = 2;
        private const int EXIT_NO_VPNCMD  = 3;
        private const int EXIT_ALL_FAILED = 4;

        public static readonly string VpnCmdPath;
        public static readonly RotatorConfig config = new RotatorConfig();
        public static readonly Random Rng = new Random();

        public static Dictionary<string, string> VpnAccounts { get; private set; } = new Dictionary<string, string>();

        static VPNGateRotator()
        {
            string pf = Environment.GetEnvironmentVariable("ProgramW6432") ?? Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            VpnCmdPath = Path.Combine(pf, "SoftEther VPN Client", "vpncmd.exe");
            try {
                config = JsonConvert.DeserializeObject<RotatorConfig>(File.ReadAllText(Path.Combine(GetCD(), "NetRouteRotatorConfig.json")));
            } catch {
                string data = JsonConvert.SerializeObject(config);
                File.WriteAllText(Path.Combine(GetCD(), "NetRouteRotatorConfig.json"), data);
            };
        }               

        public static int ProcessRotate(string[] args)
        {
            Environment.ExitCode = EXIT_FAILURE;

            Console.WriteLine("=== https://github.com/dkxce/NetRouteStabilizer (C) dkxce 2026 ===");
            Console.WriteLine("=== dkxce VPNGate Server Rotator ===");
            Console.WriteLine("=== Для выхода нажмите Ctrl+C. ===\n");

            ParseCLI(config, args);
            Log($"LOADED VPNGATE CONFIG `NetRouteRotatorConfig.json`: \r\n{{\r\n{config}\r\n}} ...");

            if (!File.Exists(VpnCmdPath)) {
                Log("[ERROR] vpncmd.exe NOT FOUND");
                return Environment.ExitCode = EXIT_NO_VPNCMD;
            };

            Log("DETECTING EXISTING VPNGATE SERVERS");
            {
                Thread.Sleep(config.DetectDelay * 1000);
                VpnScanExistingAccounts();
            };

            string connected = "none";
            string failed = null;
            foreach (KeyValuePair<string,string> kvp in VpnAccounts)
            {
                if (kvp.Value.Equals("Connected")) connected = kvp.Key;
                if (kvp.Value.Equals("Connecting")) failed = kvp.Key;
            };
            
            Log($"Found {VpnAccounts.Count} existing accounts");
            {
                if (connected != "none" && !args.Contains("/force"))
                {
                    Log($"ALREADY CONNECTED TO: {connected}, NO NEED ROTATE");
                    return Environment.ExitCode = EXIT_SUCCESS;
                };
                if (connected != "none" && args.Contains("/force"))
                {
                    VpnBreakConnectionsRetries(failed, true);
                    failed = null;
                };
                if (!string.IsNullOrEmpty(failed))
                {
                    VpnBreakConnectionsRetries(failed, true);
                    failed = null;
                };
            };

            // Existing Servers Rotate
            int onLoadLength = VpnAccounts.Count;
            if (VpnAccounts.Count > 0)
            {
                Log($"Trying to connect existing servers: (max {config.MaxExistingAttempts} attempts)");
                int attempts = 0;
                while (connected == "none" && (attempts++ < config.MaxExistingAttempts))
                {
                    Log($"  Existing server attempt {attempts}/{config.MaxExistingAttempts}");

                    string[] keys = new string[VpnAccounts.Count];
                    VpnAccounts.Keys.CopyTo(keys, 0);
                    string current = keys[Rng.Next(VpnAccounts.Count)];

                    Log($"  Connecting to existing server: {current}");
                    {
                        if(config.VPNHideStatus)
                        {
                            string hidestCmd = $"AccountStatusHide \"{current}\"";
                            Log($".. Executing: {hidestCmd}");
                            VpnCmdRun(hidestCmd);
                        };

                        string connectCmd = $"AccountConnect \"{current}\"";
                        Log($".. Executing: {connectCmd}");
                        VpnCmdRun(connectCmd);
                        Thread.Sleep(config.ConnectDelay * 1000);

                        bool success = false;
                        string statusCmd = $"AccountStatusGet \"{current}\"";
                        string statusOut = VpnCmdRun(statusCmd);
                        foreach (string line in statusOut.Split(new char[] { '\r', '\n' }))
                            if (line.Contains("Status") && line.Contains("Completed"))
                                success = true;
                        VpnAccounts[current] = success ? "Connected" : "Failed";
                        if (success)
                        {
                            connected = current;
                            VpnAccountRename(connected); // ? 
                        }
                        else 
                            VpnBreakConnectionsRetries(current, true);

                        if (config.VPNHideStatus)
                        {
                            string showstCmd = $"AccountStatusShow \"{current}\"";
                            Log($".. Executing: {showstCmd}");
                            VpnCmdRun(showstCmd);
                        };
                    };
                }
            };
            

            // New Servers Rotate
            if (connected == "none")
            {
                Log($"Load {config.VPNServersFile} file...");
                VpnGateServer[] jsonServers = LoadVpnGateServersFromJson(config.VPNServersFile);

                if (jsonServers == null || jsonServers.Length == 0)
                {
                    Log("[WARN] JSON FILE NOT FOUND, EMPTY OR HAS NO SERVERS");
                    return Environment.ExitCode = EXIT_NO_JSON;
                }
                else
                {
                    Log($"... loaded {jsonServers.Length} servers");
                    Log($"Trying to connect to new servers: (max {config.MaxNewServerAttempts} attempts)");
                };

                int attempts = 0;
                int invalidSkips = 0;
                int maxSkips = jsonServers.Length * 3;

                while (connected == "none" && attempts < config.MaxNewServerAttempts && invalidSkips < maxSkips)
                {
                    int rnd = Rng.Next(jsonServers.Length);
                    VpnGateServer srv = jsonServers[rnd];

                    bool skip = false;
                    string skipReason = "";
                    double age = DateTime.Now.Subtract(srv.FetchedAt).TotalDays;
                    if (string.IsNullOrWhiteSpace(srv.IP)) { skip = true; skipReason += (skipReason == "" ? "" : "/") + "No IP"; };
                    if (string.IsNullOrWhiteSpace(srv.HostName)) { skip = true; skipReason += (skipReason == "" ? "" : "/") + "No HostName"; };
                    if (srv.TcpPort <= 0) { skip = true; skipReason += (skipReason == "" ? "" : "/") + "No Port"; };
                    if (srv.TCP == false) { skip = true; skipReason += (skipReason == "" ? "" : "/") + "No TCP"; }; ;
                    if ((!long.TryParse(srv.Uptime, out long uptime)) || uptime <= 1000) { skip = true; skipReason += (skipReason == "" ? "" : "/") + "Bad UpTime"; };
                    if (!config.Countries.Contains(srv.CountryShort)) { skip = true; skipReason += (skipReason == "" ? "" : "/") + "Bad Country"; };
                    if (srv.Operator.Contains("Academic Use Only")) { skip = true; skipReason += (skipReason == "" ? "" : "/") + "Academic Use Only"; };
                    if (config.VPNSkipOldDays > 0 && age > config.VPNSkipOldDays) { skip = true; skipReason += (skipReason == "" ? "" : "/") + $"Old {age:F1}d"; };

                    if (skip)
                    {
                        invalidSkips++;
                        Log($"  SKIP INVALID SERVER [{srv.CountryShort} {srv.HostName ?? "NULL"}:{srv.TcpPort}({srv.TCP})] UpTime: {uptime} ({skipReason}). Skips: {invalidSkips}");
                        continue;
                    };
                    invalidSkips = 0;
                    attempts++;                   

                    Log($"  New server attempt {attempts}/{config.MaxNewServerAttempts}");
                    {
                        Log($"  SELECTED [{rnd}]: {srv.CountryShort} {srv.HostName} ({srv.IP}:{srv.TcpPort}) | Score:{srv.Score} | Ping:{srv.Ping}ms");

                        if (config.VPNServerPing)
                        {
                            Log($"    PING: {srv.IP}...");
                            if (PingHost(srv.IP, out _))
                                Log($"    ... OK");
                            else
                            {
                                Log($"    ... Failed");
                                continue;
                            };
                        };

                        string accountName = ApplyTemplate(srv, config.VPNAccountFormat) + " - " + DateTime.Now.ToString("yyMMdd");
                        bool was_added = VpnAccounts.ContainsKey(accountName);
                        VpnAccountCreate(srv, accountName, config.VPNAdapterName); // create or update
                        VpnAccounts[accountName] = "Created";
                        Thread.Sleep(1000);

                        if(was_added)
                        {
                            VpnAccountUpdate(srv, accountName, config.VPNAdapterName); // create or update
                            VpnAccounts[accountName] = "Updated";
                            Thread.Sleep(1000);
                        };

                        Log($"  Connecting to: {accountName}");
                        {
                            if (config.VPNHideStatus)
                            {
                                string hidestCmd = $"AccountStatusHide \"{accountName}\"";
                                Log($".. Executing: {hidestCmd}");
                                VpnCmdRun(hidestCmd);
                            };

                            string connectCmd = $"AccountConnect \"{accountName}\"";
                            Log($".. Executing: {connectCmd}");
                            VpnCmdRun(connectCmd);
                            Thread.Sleep(config.ConnectDelay * 1000);
                        };

                        bool success = false;
                        {
                            string statusOut = VpnCmdRun($"AccountStatusGet \"{accountName}\"");
                            foreach (string line in statusOut.Split(new char[] { '\r', '\n' }))
                                if (line.Contains("Status") && line.Contains("Completed"))
                                    success = true;
                        };

                        if (success)
                        {
                            VpnAccounts[accountName] = "Connected";
                            connected = accountName;
                            VpnAccountRename(accountName); // ? 
                            Log($"  SUCCESSFULLY CONNECTED TO: {accountName}");

                            if (config.VPNHideStatus)
                            {
                                string showstCmd = $"AccountStatusShow \"{accountName}\"";
                                Log($".. Executing: {showstCmd}");
                                VpnCmdRun(showstCmd);
                            };
                        }
                        else
                        {
                            VpnAccounts[accountName] = "Failed";
                            Log($"  FAILED TO CONNECT TO {accountName}");
                            VpnBreakConnectionsRetries(accountName);
                            Thread.Sleep(1000);

                            if (!was_added)
                            {
                                string deleteCmd = $"AccountDelete \"{accountName}\"";
                                Log($".. Executing: {deleteCmd}");
                                VpnCmdRun(deleteCmd);
                                VpnAccounts.Remove(accountName);
                                Thread.Sleep(1000);
                            }
                            else
                            {
                                if (config.VPNHideStatus)
                                {
                                    string showstCmd = $"AccountStatusShow \"{accountName}\"";
                                    Log($".. Executing: {showstCmd}");
                                    VpnCmdRun(showstCmd);
                                };
                            };
                        };

                        // OldServerInjection Attempt
                        if((!success) && (config.NewServerAttemptExistingStep > 0) && (attempts % config.NewServerAttemptExistingStep == 0))
                        {
                            Log($"  Existing server inject {attempts}/step/{config.NewServerAttemptExistingStep}");

                            string[] keys = new string[VpnAccounts.Count];
                            VpnAccounts.Keys.CopyTo(keys, 0);
                            string injected = keys[Rng.Next(onLoadLength)];

                            Log($"  Connecting to existing server: {injected}");
                            {
                                if (config.VPNHideStatus)
                                {
                                    string hidestCmd = $"AccountStatusHide \"{injected}\"";
                                    Log($".. Executing: {hidestCmd}");
                                    VpnCmdRun(hidestCmd);
                                };

                                string connectCmd = $"AccountConnect \"{injected}\"";
                                Log($".. Executing: {connectCmd}");
                                VpnCmdRun(connectCmd);
                                Thread.Sleep(config.ConnectDelay * 1000);

                                string statusOut = VpnCmdRun($"AccountStatusGet \"{injected}\"");
                                foreach (string line in statusOut.Split(new char[] { '\r', '\n' }))
                                    if (line.Contains("Status") && line.Contains("Completed"))
                                        success = true;

                                VpnAccounts[injected] = success ? "Connected" : "Failed";
                                if (success)
                                {                                    
                                    Log($"  SUCCESSFULLY CONNECTED TO: {injected}");
                                    connected = injected;
                                    VpnAccountRename(connected); // ? 
                                }
                                else
                                {
                                    Log($"  FAILED TO CONNECT TO {injected}");
                                    VpnBreakConnectionsRetries(injected);
                                    Thread.Sleep(1000);
                                };

                                if (config.VPNHideStatus)
                                {
                                    string showstCmd = $"AccountStatusShow \"{injected}\"";
                                    Log($".. Executing: {showstCmd}");
                                    VpnCmdRun(showstCmd);
                                };
                            };
                        };
                    };
                }
            };

            // Итоговый вывод
            if (connected != "none")
            {
                Log($"SUCCESSFULLY CONNECTED TO: {connected}, NEED TO ROTATE");
                return Environment.ExitCode = EXIT_SUCCESS;
            }
            else
            {
                Log("ALL CONNECTION ATTEMPTS FAILED, TRY AGAIN LATER");
                return Environment.ExitCode = EXIT_ALL_FAILED;
            };
        }

        private static VpnGateServer[] LoadVpnGateServersFromJson(string path)
        {
            if (!File.Exists(path)) return new VpnGateServer[0];
            try
            {
                string json = File.ReadAllText(path, Encoding.UTF8);
                VpnGateServer[] list = JsonConvert.DeserializeObject<VpnGateServer[]>(json);
                return list ?? new VpnGateServer[0];
            }
            catch (Exception ex)
            {
                Log($"[JSON ERROR] {ex.Message}");
                return new VpnGateServer[0];
            }
        }

        #region VPNGateCommands

        private static void VpnScanExistingAccounts()
        {
            string accountsCmd = "AccountList";
            Log($".. Executing: {accountsCmd}");
            string output = VpnCmdRun(accountsCmd);
            string[] lines = output.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            string currentSrv = null;

            for (int i = 0; i < lines.Length; i++)
            {
                string trimmed = lines[i].Trim();
                if (trimmed.Contains("Setting Name") && trimmed.IndexOf(config.VPNServersFind) >= 0)
                {
                    string[] parts = trimmed.Split('|');
                    if (parts.Length > 1) currentSrv = parts[1].Trim();
                }
                else if (trimmed.StartsWith("Status") ||
                         trimmed.StartsWith("Setting Status"))
                {
                    if (!string.IsNullOrEmpty(currentSrv))
                    {
                        string[] parts = trimmed.Split('|');
                        string status = parts.Length > 1 ? parts[1].Trim() : "Unknown";
                        VpnAccounts[currentSrv] = status;
                        currentSrv = null;
                    }
                }
            }
        }

        private static void VpnBreakConnectionsRetries(string accountName, bool skipCheck = false)
        {
            Log($"Found failed connection: {accountName}");
            string statusOut = VpnCmdRun($"AccountStatusGet \"{accountName}\"").ToLower();

            bool needBreak = skipCheck ||
                             statusOut.Contains("started") ||
                             statusOut.Contains("retrying") ||
                             statusOut.Contains("not connected");

            if (!needBreak)
                Log($"  No need to reject server connection: {accountName}");
            else
            {
                Log($"  Break connections retries to the server: {accountName}");
                string disconnectCmd = $"AccountDisconnect \"{accountName}\"";
                Log($".. Executing: {disconnectCmd}");
                VpnCmdRun(disconnectCmd);
                Thread.Sleep(config.DisconnectDelay * 1000);
            }
        }

        private static void VpnAccountCreate(VpnGateServer srv, string accountName, string nic = "VPN")
        { 
            string serverArg = ApplyTemplate(srv, config.VPNServerFormat);
            string createCmd = $"AccountCreate \"{accountName}\" /SERVER:\"{serverArg}\" /HUB:\"VPNGate\" /USERNAME:\"vpn\" /NICNAME:\"{nic}\"";
            Log($".. Executing: {createCmd}");
            VpnCmdRun(createCmd);
        }

        private static void VpnAccountUpdate(VpnGateServer srv, string accountName, string nic = "VPN")
        { 
            string serverArg = ApplyTemplate(srv, config.VPNServerFormat);
            string updateCmd = $"AccountSet \"{accountName}\" /SERVER:\"{serverArg}\" /HUB:\"VPNGate\"";
            Log($".. Executing: {updateCmd}");
            VpnCmdRun(updateCmd);
        }

        public static void VpnAccountRename(string accountName)
        {
            string newName = accountName;
            Regex rx = new Regex(@"(?:\s\[(?<count>\d+)\])?\s-\s(?:CURRENT|\d{6}|T\d{4})$");
            Match mx = rx.Match(accountName);
            if (mx.Success)
            {
                int.TryParse(mx.Groups["count"].Value ?? "1", out int count);
                newName = rx.Replace(accountName, "") + $" [{++count}]";
                newName += " - " + DateTime.Now.ToString("yyMMdd");
            };            ;
            string updateCmd = $"AccountRename \"{accountName}\" /NEW:\"{newName}\"";
            Log($".. Executing: {updateCmd}");
            VpnCmdRun(updateCmd);
        }

        private static string VpnCmdRun(string arguments)
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = VpnCmdPath,
                Arguments = $"localhost /client /cmd:{arguments}",
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

        #endregion VPNGateCommands

        #region addit

        private static string GetCD()
        {
            return System.IO.Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName);
        }

        private static void Log(string message, string prefix = "")
        {
            if (string.IsNullOrEmpty(message)) return;

            string[] lines = message.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None);
            string timestamp = DateTime.Now.ToString(config.LogDateTimeFormat);

            for (int i = 0; i < lines.Length; i++)
                Console.WriteLine($"[{timestamp}] {prefix}{lines[i]}");
        }

        private static string ApplyTemplate(VpnGateServer server, string template)
        {
            if (string.IsNullOrEmpty(template) || server == null) return template;

            string result = template;

            // Получаем все публичные свойства типа string и int из VpnGateServer
            var properties = typeof(VpnGateServer).GetProperties(
                System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance);

            // Перебираем свойства классическим циклом (без LINQ)
            for (int i = 0; i < properties.Length; i++)
            {
                var prop = properties[i];
                string placeholder = "%" + prop.Name + "%";

                // Если плейсхолдер есть в шаблоне — заменяем
                if (result.IndexOf(placeholder, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    object value = prop.GetValue(server);
                    string replacement = value?.ToString() ?? "";
                    result = result.Replace(placeholder, replacement);
                }
            }

            return result;
        }

        private static bool PingHost(string host, out PingReply reply, int timeout = 3000)
        {
            reply = null;
            try {
                Ping ping = new Ping();
                reply = ping.Send(host, timeout);
                return (reply.Status == IPStatus.Success) ;
            } catch { };
            return false;
        }

        #endregion addit

        #region CLI Tools
        private static void ParseCLI(RotatorConfig config, string[] args)
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

        public static int ShrinkJSON()
        {
            VpnGateServer[] jsonServers = LoadVpnGateServersFromJson(config.VPNServersFile);

            if (jsonServers == null || jsonServers.Length == 0)
            {
                Log("[WARN] JSON FILE NOT FOUND, EMPTY OR HAS NO SERVERS");
                return Environment.ExitCode = EXIT_NO_JSON;
            }
            else
            {
                Log($"... loaded {jsonServers.Length} servers");
                FileInfo fi = new FileInfo(config.VPNServersFile);
                Log($"Trying to shrink {fi.Length / 1024} KB ...");
                string json = JsonConvert.SerializeObject(jsonServers, Formatting.Indented);
                File.WriteAllText(config.VPNServersFile, json);
                fi = new FileInfo(config.VPNServersFile);
                Log($"OK, Shrinked to {fi.Length / 1024} KB");
                return Environment.ExitCode = EXIT_SUCCESS;
            };
        }
    }
}