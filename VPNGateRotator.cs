//** CLI: /rotate **//

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Newtonsoft.Json;
using static NetRouteStabilizer.Stabilizer;

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
        [Description("StdOut Log Line Format DateTime")]
        [JsonProperty]
        public string LogDateTimeFormat = "dd HH:mm:ss";

        [Description("JSON VPNGate Servers File from /collect")]
        [JsonProperty]
        public string VPNServersFile    { get; set; } = "vpngate_full_list.json";

        [Description("VPNGate text to find servers in VPNCmd AccountList")]
        [JsonProperty]
        public string VPNServersFind    { get; set; } = "opengw.net";

        [Description("VPNGate Atapter name (VPN/VPN2/VPN3 ...)")]
        [JsonProperty]
        public string VPNAdapterName    { get; set; } = "VPN";

        [Description("VPNGate Account Format for VPNCmd AccountCreate")]
        [JsonProperty]
        public string VPNAccountFormat  { get; set; } = "%CountryShort% %HostName%.opengw.net";

        [Description("VPNGate Hostname(Server) Format for VPNCmd AccountCreate")]
        [JsonProperty]
        public string VPNServerFormat   { get; set; } = "%IP%/tcp:%TcpPort%";

        [Description("Check ping VPNGate server before add new")]
        [JsonProperty]
        public bool   VPNServerPing     { get; set; } = true;

        [Description("Hide VPNGate account statuses on connect/retries")]
        [JsonProperty]
        public bool   VPNHideStatus     { get; set; } = true;

        [Description("Skip VPNGate server if info is to old")]
        [JsonProperty]
        public int    VPNSkipOldDays    { get; set; } = 0;

        [Description("Max attempts to connect to existings VPNGate accounts")]
        [JsonProperty]
        public int MaxExistingAttempts  { get; set; } = 5;

        [Description("Max attempts to connect to new VPNGate accounts")]
        [JsonProperty]
        public int MaxNewServerAttempts { get; set; } = 100;

        [Description("Attempts each new server XXX step to connect to existings VPNGate accounts")]
        [JsonProperty]
        public int NewServerAttemptExistingStep { get; set; } = 0;

        [Description("Connection delay timeout")]
        [JsonProperty]
        public int ConnectDelay         { get; set; } = 15;
        
        [Description("Disconnection delay timeout")]
        [JsonProperty]
        public int DisconnectDelay      { get; set; } = 3;
        
        [Description("Delete delay timeout")]
        [JsonProperty]
        public int DetectDelay          { get; set; } = 5;

        [Description("Countries to select VPNGate Servers in ...")]
        [JsonProperty]
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

        public void Save(string filePath, bool withComments = false)
        {
            if (!withComments)
            {
                string data = JsonConvert.SerializeObject(config, Formatting.Indented);
                File.WriteAllText(filePath, data);
                return;
            };

            StreamWriter writer = new StreamWriter(filePath);
            JsonTextWriter jsonWriter = new JsonTextWriter(writer)
            {
                Formatting = Formatting.Indented,
                CloseOutput = false
            };

            JsonSerializer serializer = new JsonSerializer();
            jsonWriter.WriteStartObject();

            foreach (PropertyInfo prop in GetType().GetProperties())
            {
                if (prop.GetCustomAttribute<JsonPropertyAttribute>() == null) continue;
                if (!prop.CanRead) continue;
                writer.Write("\r\n  ");
                WriteMemberWithComment(jsonWriter, serializer, prop, prop.GetValue(this), prop.Name);
            }

            foreach (var field in GetType().GetFields(BindingFlags.Public | BindingFlags.Instance))
            {
                writer.Write("\r\n  ");
                if (field.GetCustomAttribute<JsonPropertyAttribute>() == null) continue;
                WriteMemberWithComment(jsonWriter, serializer, field, field.GetValue(this), field.Name);
            }

            jsonWriter.WriteEndObject();
            jsonWriter.Close();
            writer.Close();
        }

        private void WriteMemberWithComment(
            JsonTextWriter jsonWriter,
            JsonSerializer serializer,
            MemberInfo member,
            object value,
            string memberName)
        {
            var description = member.GetCustomAttribute<DescriptionAttribute>()?.Description;
            if (!string.IsNullOrEmpty(description)) jsonWriter.WriteComment(description);
            var jsonProp = member.GetCustomAttribute<JsonPropertyAttribute>();
            string propName = jsonProp?.PropertyName ?? memberName;
            jsonWriter.WritePropertyName(propName);
            serializer.Serialize(jsonWriter, value);
        }
    }

    public class VPNGateRotator
    {
        private const int EXIT_SUCCESS    = 0;
        private const int EXIT_FAILURE    = 1;
        private const int EXIT_NO_JSON    = 2;
        private const int EXIT_NO_VPNCMD  = 3;
        private const int EXIT_ALL_FAILED = 4;

        private static Regex accountRegex = new Regex(@"(?:\s\[(?<count>\d+)\])?\s-\s(?:CURRENT|\d{6}|T\d{4})$");

        public static readonly string VpnCmdPath;
        public static readonly RotatorConfig config = new RotatorConfig();
        public static readonly Random Rng = new Random();


        public static Dictionary<string, string> VpnAccounts { get; private set; } = new Dictionary<string, string>();

        static VPNGateRotator()
        {
            string pf = Environment.GetEnvironmentVariable("ProgramW6432") ?? Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            VpnCmdPath = Path.Combine(pf, "SoftEther VPN Client", "vpncmd.exe");
            try
            {
                string fn = Path.Combine(GetCD(), "NetRouteRotatorConfig.json");
                if (!File.Exists(fn)) throw new FileNotFoundException();
                config = JsonConvert.DeserializeObject<RotatorConfig>(File.ReadAllText(fn));
                if (config == null)
                {
                    config = new RotatorConfig();
                    throw new Exception();
                };
            }
            catch
            {
                config.Save(Path.Combine(GetCD(), "NetRouteRotatorConfig.json"), true);
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
                Log("[ERROR] vpncmd.exe NOT FOUND", "", ConsoleColor.White, ConsoleColor.Red);
                return Environment.ExitCode = EXIT_NO_VPNCMD;
            };

            Log("DETECTING EXISTING VPNGATE SERVERS", "", ConsoleColor.DarkYellow);
            {
                Thread.Sleep(config.DetectDelay * 1000);
                VpnScanExistingAccounts();
            };

            string connected = "none", failed = null;
            foreach (KeyValuePair<string,string> kvp in VpnAccounts)
            {
                if (kvp.Value.Equals("Connected")) connected = kvp.Key;
                if (kvp.Value.Equals("Connecting")) failed = kvp.Key;
            };
            
            Log($"Found {VpnAccounts.Count} existing accounts");
            {
                if (connected != "none" && !args.Contains("/force"))
                {
                    Log($"ALREADY CONNECTED TO: {connected}, NO NEED ROTATE", "", ConsoleColor.White, ConsoleColor.Green);
                    return Environment.ExitCode = EXIT_SUCCESS;
                };
                if (connected != "none" && args.Contains("/force"))
                {
                    VpnBreakConnectionsRetries(connected, true);
                    connected = "none";
                };
                if (!string.IsNullOrEmpty(failed))
                {
                    VpnBreakConnectionsRetries(failed, true);
                };
            };

            // Existing Servers Rotate
            int onLoadLength = VpnAccounts.Count;
            if (VpnAccounts.Count > 0)
            {
                int attempts = 0;
                Log($"Trying to connect existing servers: (max {config.MaxExistingAttempts} attempts)");                
                while (connected == "none" && (attempts++ < config.MaxExistingAttempts))
                {
                    Log($"  Existing server attempt {attempts}/{config.MaxExistingAttempts}", "", ConsoleColor.Yellow);
                    ExistingAttempt(out connected);
                };
            };
            

            // New Servers Rotate
            if (connected == "none")
            {
                Log($"Load {config.VPNServersFile} file...");
                VpnGateServer[] jsonServers = LoadVpnGateServersFromJson(config.VPNServersFile);

                if (jsonServers == null || jsonServers.Length == 0)
                {
                    Log("[WARN] JSON FILE NOT FOUND, EMPTY OR HAS NO SERVERS", "", ConsoleColor.Red, ConsoleColor.White);
                    return Environment.ExitCode = EXIT_NO_JSON;
                }
                else
                {
                    Log($"... loaded {jsonServers.Length} servers");
                    Log($"Trying to connect to new servers: (max {config.MaxNewServerAttempts} attempts)");
                };

                int attempts = 0, invalidSkips = 0, maxSkips = jsonServers.Length * 3;
                while (connected == "none" && attempts < config.MaxNewServerAttempts && invalidSkips < maxSkips)
                {
                    // OldServerInjection Attempt (CFG: NewServerAttemptExistingStep > 0)
                    if ((attempts > 0) && (config.NewServerAttemptExistingStep > 0) && (attempts % config.NewServerAttemptExistingStep == 0))
                    {
                        Log($"  Existing server inject {attempts}/step/{config.NewServerAttemptExistingStep}", "", ConsoleColor.Yellow);
                        if(ExistingAttempt(out connected, onLoadLength)) break; else attempts++;
                    };

                    // NewServer Attempt // GET NEW SERVER //
                    int rnd = Rng.Next(jsonServers.Length);
                    VpnGateServer srv = jsonServers[rnd];

                    // IF SKIP RULES //
                    bool skip = false; {
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
                            Log($"  SKIP INVALID SERVER [{srv.CountryShort} {srv.HostName ?? "NULL"}:{srv.TcpPort}({srv.TCP})] UpTime: {uptime} ({skipReason}). Skips: {invalidSkips}", "", ConsoleColor.Gray);
                            continue;
                        };
                        invalidSkips = 0;
                    };
                            
                    // ALL IS OK //
                    attempts++;                   
                    Log($"  New server attempt {attempts}/{config.MaxNewServerAttempts}", "", ConsoleColor.Yellow);
                    {
                        Log($"  SELECTED [{rnd}]: {srv.CountryShort} {srv.HostName} ({srv.IP}:{srv.TcpPort}) | Score:{srv.Score} | Ping:{srv.Ping}ms");
                        if (config.VPNServerPing && !TryPing(srv.IP)) continue;                        
                        NewAttempt(srv, out connected);                     
                    };
                }
            };

            // Итоговый вывод
            if (connected != "none")
            {
                Log($"SUCCESSFULLY CONNECTED TO: {connected}, NEED TO ROTATE", "", ConsoleColor.Green, ConsoleColor.White);
                return Environment.ExitCode = EXIT_SUCCESS;
            }
            else
            {
                Log("ALL CONNECTION ATTEMPTS FAILED, TRY AGAIN LATER", "", ConsoleColor.Red, ConsoleColor.White);
                return Environment.ExitCode = EXIT_ALL_FAILED;
            };
        }

        private static string GetAccountNewName(string accountName, int increment)
        {
            Match mx = accountRegex.Match(accountName);
            int count = increment + (mx.Success && int.TryParse(mx.Groups["count"].Value ?? "1", out count) ? count : 0);
            string newName = accountRegex.Replace(accountName, "") + $" [{count}] - " + DateTime.Now.ToString("yyMMdd");
            return newName;
        }

        private static string AccountStartsWithExists(string startsWithText, bool fullName = false)
        {
            if (fullName) startsWithText = accountRegex.Replace(startsWithText, "");
            if (VpnAccounts == null || VpnAccounts.Count == 0) return null;
            foreach (KeyValuePair<string, string> kvp in VpnAccounts)
                if (kvp.Key.StartsWith(startsWithText))
                    return kvp.Key;
            return null;
        }

        private static bool ExistingAttempt(out string connectionName, int maxRange = 0)
        {
            connectionName = "none";            
            string[] keys = new string[VpnAccounts.Count]; VpnAccounts.Keys.CopyTo(keys, 0);
            string oldName = keys[Rng.Next(Math.Min(maxRange == 0 ? VpnAccounts.Count : maxRange, VpnAccounts.Count))];
            string curName = GetAccountNewName(oldName, +1);

            Log($"  Connecting to existing server: {oldName}");
            VpnAccountRename(oldName, curName);
            if (config.VPNHideStatus) VpnHideStatus(curName);
            VpnConnect(curName);
            bool isConnected = VpnIsConnected(curName, true);
            if (isConnected) connectionName = curName;
            else curName = VpnAccountRename(curName, oldName);
            if (config.VPNHideStatus) VpnShowStatus(curName);
            return isConnected;
        }

        private static bool NewAttempt(VpnGateServer srv, out string connectionName)
        {
            connectionName = "none";
            string tmpName = ApplyTemplate(srv, config.VPNAccountFormat);
            string oldName = AccountStartsWithExists(tmpName, false);
            string curName = GetAccountNewName(oldName ?? tmpName, +1);

            Log($"  Connecting to: {curName}");
            if (!string.IsNullOrEmpty(oldName)) VpnAccountRename(oldName, curName);            

            VpnAccountCreate(srv, curName, config.VPNAdapterName); // create
            Thread.Sleep(500);
            VpnAccountUpdate(srv, curName, config.VPNAdapterName); // update                        
            Thread.Sleep(500);

            if (config.VPNHideStatus) VpnHideStatus(curName);
            VpnConnect(curName);
            bool isConnected = VpnIsConnected(curName, true);
            if (isConnected) connectionName = curName;
            else if (string.IsNullOrEmpty(oldName)) VpnAccountDelete(curName);
            else if (config.VPNHideStatus) VpnShowStatus(curName);
            return isConnected;
        }

        private static bool TryPing(string ip)
        {
            Log($"    PING: {ip}...");
            if (PingHost(ip, out _))
            {
                Log($"    ... OK", "", ConsoleColor.Green);
                return true;
            }
            else
            {
                Log($"    ... Failed", "", ConsoleColor.DarkRed);
                return false;
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
            Log($"Found failed connection: {accountName}", "", ConsoleColor.Red, ConsoleColor.DarkBlue);
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

        public static void VpnAccountDelete(string accountName)
        {
            string deleteCmd = $"AccountDelete \"{accountName}\"";
            Log($".. Executing: {deleteCmd}");
            VpnCmdRun(deleteCmd);
            VpnAccounts.Remove(accountName);
            Thread.Sleep(1000);
        }

        public static string VpnAccountRename(string fromName, string toName)
        {
            string updateCmd = $"AccountRename \"{fromName}\" /NEW:\"{toName}\"";
            Log($".. Executing: {updateCmd}");
            VpnCmdRun(updateCmd);
            return toName;
        }

        private static void VpnHideStatus(string accountName)
        {
            string hidestCmd = $"AccountStatusHide \"{accountName}\"";
            Log($".. Executing: {hidestCmd}");
            VpnCmdRun(hidestCmd);
        }
        
        private static void VpnShowStatus(string accountName)
        {
            string showstCmd = $"AccountStatusShow \"{accountName}\"";
            Log($".. Executing: {showstCmd}");
            VpnCmdRun(showstCmd);
        }
        private static void VpnConnect(string accountName)
        {
            string connectCmd = $"AccountConnect \"{accountName}\"";
            Log($".. Executing: {connectCmd}");
            VpnCmdRun(connectCmd);
            Thread.Sleep(config.ConnectDelay * 1000);
        }
        
        private static bool VpnIsConnected(string accountName, bool breakIfFail = false)
        {
            string statusCmd = $"AccountStatusGet \"{accountName}\"";
            string statusOut = VpnCmdRun(statusCmd);
            foreach (string line in statusOut.Split(new char[] { '\r', '\n' }))
                if (line.Contains("Status") && line.Contains("Completed"))
                    return true;
            if (breakIfFail) VpnBreakConnectionsRetries(accountName, true);
            return false;
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

        private static void Log(string message, string prefix = "", ConsoleColor? color = null, ConsoleColor? background = null)
        {
            if (string.IsNullOrEmpty(message)) return;

            string[] lines = message.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None);
            string timestamp = DateTime.Now.ToString(config.LogDateTimeFormat);


            if (color != null) Console.ForegroundColor = color.Value;
            if (background != null) Console.BackgroundColor = background.Value;
            for (int i = 0; i < lines.Length; i++)
                Console.WriteLine($"[{timestamp}] {prefix}{lines[i]}");
            if (color != null || background != null) Console.ResetColor();
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

        public static int ShrinkJSON(string[] args)
        {
            VpnGateServer[] jsonServers = LoadVpnGateServersFromJson(config.VPNServersFile);

            ParseCLI(config, args);
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