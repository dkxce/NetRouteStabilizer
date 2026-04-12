using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
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

        // _source_url, _fetched_at, _server_id
    }

    public class RotatorConfig
    {
        public string LogDateTimeFormat = "dd HH:mm:ss";

        public string VPNServersFile = "vpngate_full_list.json";
        public string VPNServersFind = "opengw.net";
        public string VPNAdapterName = "VPN";
        public string VPNAccountFormat = "%CountryShort% %HostName%.opengw.net";
        public string VPNServerFormat = "%IP%/tcp:%TcpPort%";            
        public bool   VPNServerPing = true;   
        
        public int MaxExistingAttempts = 5;
        public int MaxNewServerAttempts = 5;

        public int ConnectDelay = 15;
        public int DisconnectDelay = 3;
        public int DetectDelay = 5;

        public string[] Countries = new string[] { "JP", "KR" };
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

        public static int ProcessRotate()
        {
            Environment.ExitCode = EXIT_FAILURE;

            Log("------------------------------------");
            Log("--- dkxce VPNGate Server Rotator ---");
            Log("------------------------------------");
            Log($"ROTATE VPNGATE CONFIG `NetRouteRotatorConfig.json`: \r\n ... {JsonConvert.SerializeObject(config)} ...");

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
                if (connected != "none")
                {
                    Log($"ALREADY CONNECTED TO: {connected}, NO NEED ROTATE");
                    return Environment.ExitCode = EXIT_SUCCESS;
                };
                if (!string.IsNullOrEmpty(failed))
                {
                    VpnBreakConnectionsRetries(failed, true);
                    failed = null;
                };
            };

            // Existing Servers Rotate
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
                        string connectCmd = $"AccountConnect \"{current}\"";
                        VpnCmdRun(connectCmd);
                        Thread.Sleep(config.ConnectDelay * 1000);

                        bool success = false;
                        string statusCmd = $"AccountStatusGet \"{current}\"";
                        string statusOut = VpnCmdRun(statusCmd);
                        foreach (string line in statusOut.Split(new char[] { '\r', '\n' }))
                            if (line.Contains("Status") && line.Contains("Completed"))
                                success = true;
                        VpnAccounts[current] = success ? "Connected" : "Failed";
                        if (success) connected = current;
                        else VpnBreakConnectionsRetries(current, true);
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
                    VpnGateServer srv = jsonServers[Rng.Next(jsonServers.Length)];

                    bool skip = false;
                    if (string.IsNullOrWhiteSpace(srv.IP)) skip = true;
                    if (string.IsNullOrWhiteSpace(srv.HostName)) skip = true;
                    if (srv.TcpPort <= 0) skip = true;
                    if (srv.TCP == false) skip = true;
                    if ((!long.TryParse(srv.Uptime, out long uptime)) || uptime <= 1000) skip = true;
                    if (!config.Countries.Contains(srv.CountryShort)) skip = true;
                    if (srv.Operator.Contains("Academic Use Only")) skip = true;

                    if(skip)
                    {
                        invalidSkips++;
                        Log($"  SKIP INVALID SERVER [{srv.CountryShort} {srv.HostName ?? "NULL"}:{srv.TcpPort}({srv.TCP})] UpTime: {uptime}. Skips: {invalidSkips}");
                        continue;
                    };
                    invalidSkips = 0;
                    attempts++;                   

                    Log($"  New server attempt {attempts}/{config.MaxNewServerAttempts}");
                    {
                        Log($"  SELECTED: {srv.CountryShort} {srv.HostName} ({srv.IP}:{srv.TcpPort}) | Score:{srv.Score} | Ping:{srv.Ping}ms");

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

                        string accountName = ApplyTemplate(srv, config.VPNAccountFormat);
                        bool was_added = VpnAccounts.ContainsKey(accountName);
                        VpnAccountCreate(srv, accountName, config.VPNAdapterName); // create or update
                        VpnAccounts[accountName] = "Created";
                        Thread.Sleep(1000);

                        Log($"  Connecting to: {accountName}");
                        {
                            string connectCmd = $"AccountConnect \"{accountName}\"";
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
                            Log($"  SUCCESSFULLY CONNECTED TO: {accountName}");
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
                                VpnCmdRun(deleteCmd);
                                VpnAccounts.Remove(accountName);
                                Thread.Sleep(1000);
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
            string createCmd = $"  AccountCreate \"{accountName}\" /SERVER:\"{serverArg}\" /HUB:\"VPNGate\" /USERNAME:\"vpn\" /NICNAME:\"{nic}\"";
            Log($".. Executing: {createCmd}");
            VpnCmdRun(createCmd);
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
    }
}