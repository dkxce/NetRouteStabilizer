using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace NetRouteStabilizer
{
    public class VpnServer : Dictionary<string, object>
    {
        public string HostName
        {
            get => TryGetValue("HostName", out var v) ? v?.ToString() ?? "" : "";
            set => this["HostName"] = value;
        }
        public string IP
        {
            get => TryGetValue("IP", out var v) ? v?.ToString() ?? "" : "";
            set => this["IP"] = value;
        }
        public int TcpPort
        {
            get => TryGetValue("TcpPort", out var v) && int.TryParse(v?.ToString(), out var p) ? p : 0;
            set => this["TcpPort"] = value;
        }
        public bool TCP
        {
            get => TryGetValue("TCP", out var v) && bool.TryParse(v?.ToString(), out var t) && t;
            set => this["TCP"] = value;
        }
        public bool UDP
        {
            get => TryGetValue("UDP", out var v) && bool.TryParse(v?.ToString(), out var u) && u;
            set => this["UDP"] = value;
        }
        public string OpenVPN_ConfigData_Base64
        {
            get => TryGetValue("OpenVPN_ConfigData_Base64", out var v) ? v?.ToString() ?? "" : "";
            set => this["OpenVPN_ConfigData_Base64"] = value;
        }
        public string _source_url
        {
            get => TryGetValue("_source_url", out var v) ? v?.ToString() ?? "" : "";
            set => this["_source_url"] = value;
        }
        public string _fetched_at
        {
            get => TryGetValue("_fetched_at", out var v) ? v?.ToString() ?? "" : "";
            set => this["_fetched_at"] = value;
        }
        public string _server_id
        {
            get => TryGetValue("_server_id", out var v) ? v?.ToString() ?? "" : "";
            set => this["_server_id"] = value;
        }
        public VpnServer(IDictionary<string, object> source = null) : base(StringComparer.OrdinalIgnoreCase)
        {
            if (source != null)
                foreach (var kvp in source)
                    this[kvp.Key] = kvp.Value;
        }
    }

    public class VpnGateCollector
    {
        private const string OUTPUT_FILE = "vpngate_full_list.json";

        private static readonly List<string> MIRRORS = new List<string>()
        {
            "https://www.vpngate.net",
            "http://160.251.62.107:46080",
            "http://175.210.118.154:39744",
            "http://211.14.226.154:33477",
            "http://221.171.27.70:47201/",
            "http://118.106.179.107:12143",
            "http://p1371060-ipxg00e01okayamahigasi.okayama.ocn.ne.jp:37613/",
            "http://183.100.225.237:56531/",
            "http://220.57.84.30:62713/",
            "http://112.165.112.49:52818/",
            "http://124.18.179.190:39566/",
            "http://kd036012175158.ppp-bb.dion.ne.jp:64678/",
        };

        private static string PROXY_BASE = null;
        private static string PROXY_CRED = null;
        private const string API_PATH = "/api/iphone/";
        private const int CURL_TIMEOUT = 30;
        private const int ASQ_PERIOD = 1;

        private static readonly Regex PORT_REGEX = new Regex(
            @"^remote\s+[\w\.:]+\s+(\d+)(?:\s+(tcp|udp))?",
            RegexOptions.Multiline | RegexOptions.IgnoreCase);
        private static readonly Regex PORT_TCP_REGEX = new Regex(
            @"^\s*proto\s+tcp\s*$",
            RegexOptions.Multiline | RegexOptions.IgnoreCase);
        private static readonly Regex PORT_UDP_REGEX = new Regex(
            @"^\s*proto\s+udp\s*$",
            RegexOptions.Multiline | RegexOptions.IgnoreCase);

        private static readonly ILogger Logger = new ConsoleLogger();

        private static string GenerateServerId(VpnServer row)
        {
            string hostName = row.TryGetValue("HostName", out var hn) ? hn?.ToString() ?? "" : "";
            string ip = row.TryGetValue("IP", out var i) ? i?.ToString() ?? "" : "";
            string key = $"{hostName}:{ip}";
            MD5 md5 = MD5.Create();
            byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(key));
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        private static byte[] RunCurlRequest(string url)
        {
            List<string> args = new List<string>
            {
                "-s", "-f", "-L", "--max-time", CURL_TIMEOUT.ToString(),
                "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                url
            };

            if (!string.IsNullOrEmpty(PROXY_BASE))
            {
                args.Add("-x");
                args.Add(PROXY_BASE);
            }
            if (!string.IsNullOrEmpty(PROXY_BASE) && !string.IsNullOrEmpty(PROXY_CRED))
            {
                args.Add("-U");
                args.Add(PROXY_CRED);
            }

            var psi = new ProcessStartInfo
            {
                FileName = "curl.exe",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            psi.Arguments = string.Join(" ", args);

            try
            {
                Process process = Process.Start(psi);
                if (process == null)
                {
                    Logger.Error("Не удалось запустить процесс curl");
                    return null;
                }

                MemoryStream ms = new MemoryStream();
                process.StandardOutput.BaseStream.CopyTo(ms);
                var output = ms.ToArray();

                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    string error = process.StandardError.ReadToEnd();
                    Logger.Error($"Curl ошибка ({process.ExitCode}) для {url}: {error.Trim()}");
                    return null;
                }

                return output;
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 2)
            {
                Logger.Critical("Утилита 'curl' не найдена в системе! Установите её или добавьте в PATH.");
                return null;
            }
            catch (Exception ex)
            {
                Logger.Error($"Ошибка выполнения curl для {url}: {ex.Message}");
                return null;
            }
        }


        private static (bool parsed, bool tcp, bool udp, int port) ParseServerLine(string[] fields)
        {
            try
            {
                if (fields.Length < 7) return (false, false, false, 0);
                string base64Config = fields[fields.Length-1];

                bool tcp = false;
                bool udp = false;
                int port = 0;

                try
                {
                    byte[] configBytes = Convert.FromBase64String(base64Config);
                    string config = Encoding.UTF8.GetString(configBytes);

                    var match = PORT_REGEX.Match(config);
                    if (match.Success)
                    {
                        string portStr = match.Groups[1].Value;
                        string proto = match.Groups[2].Value;
                        if (!string.IsNullOrEmpty(portStr) && int.TryParse(portStr, out int p))
                            port = p;
                        if (!string.IsNullOrEmpty(proto))
                        {
                            if (proto.ToLowerInvariant() == "udp") udp = true;
                            else if (proto.ToLowerInvariant() == "tcp") tcp = true;
                        }
                    }

                    if (PORT_TCP_REGEX.IsMatch(config)) tcp = true;
                    if (PORT_UDP_REGEX.IsMatch(config)) udp = true;
                }
                catch { }

                return (true, tcp, udp, port);
            }
            catch { return (false, false, false, 0); }
        }

        private static List<string> ParseCsvLine(string line)
        {
            var fields = new List<string>();
            var field = new StringBuilder();
            bool inQuotes = false;
            int i = 0;

            while (i < line.Length)
            {
                char c = line[i];
                if (inQuotes)
                {
                    if (c == '"')
                    {
                        if (i + 1 < line.Length && line[i + 1] == '"')
                        {
                            field.Append('"');
                            i += 2;
                            continue;
                        }
                        inQuotes = false;
                        i++;
                    }
                    else { field.Append(c); i++; }
                }
                else
                {
                    if (c == '"') { inQuotes = true; i++; }
                    else if (c == ',') { fields.Add(field.ToString()); field.Clear(); i++; }
                    else { field.Append(c); i++; }
                }
            }
            fields.Add(field.ToString());
            return fields;
        }

        private static List<VpnServer> ParseVpnGateCsv(byte[] rawData, string sourceUrl, string fetchedAt)
        {
            var servers = new List<VpnServer>();

            string textData;
            try { textData = Encoding.GetEncoding("shift-jis").GetString(rawData); }
            catch (ArgumentException) { try { textData = Encoding.UTF8.GetString(rawData); } catch (ArgumentException) { textData = Encoding.ASCII.GetString(rawData); } }

            var lines = textData.Split('\n')
                .Select(l => l.TrimEnd('\r'))
                .Where(l => !l.StartsWith("*"))
                .ToList();

            if (lines.Count < 2) return servers;

            // Парсим заголовки (аналог: raw_headers = next(reader))
            var rawHeaders = ParseCsvLine(lines[0]);
            var headers = rawHeaders.Select(h => h.Trim('*', ' ', '#')).ToList();

            // Парсим строки данных (аналог: for row_data in reader)
            for (int i = 1; i < lines.Count; i++)
            {
                var line = lines[i];
                if (string.IsNullOrWhiteSpace(line)) continue;

                var row = ParseCsvLine(line);
                if (row == null || row.Count == 0 || row.Count < headers.Count) continue;

                var serverData = new VpnServer();
                // Аналог: server_data = dict(zip(headers, row_data))
                for (int j = 0; j < headers.Count; j++)
                {
                    serverData[headers[j]] = row[j];
                }

                var (parsed, tcp, udp, port) = ParseServerLine(row.ToArray());
                serverData["TcpPort"] = port;
                serverData["TCP"] = tcp;
                serverData["UDP"] = udp;
                serverData["_source_url"] = sourceUrl;
                serverData["_fetched_at"] = fetchedAt;
                serverData["_server_id"] = GenerateServerId(serverData);
                servers.Add(serverData);
            }

            Logger.Info($"Получено {servers.Count} серверов");
            return servers;
        }

        private static List<VpnServer> FetchMirror(string mirrorUrl)
        {
            string apiUrl = mirrorUrl.TrimEnd('/') + API_PATH;
            string fetchedAt = DateTime.UtcNow.ToString("o");
            Logger.Info($"Загрузка {apiUrl}");

            var rawContent = RunCurlRequest(apiUrl);
            if (rawContent == null) return new List<VpnServer>();
            return ParseVpnGateCsv(rawContent, mirrorUrl, fetchedAt);
        }

        private static Dictionary<string, VpnServer> LoadExisting(string filepath)
        {
            if (!File.Exists(filepath)) return new Dictionary<string, VpnServer>();
            try
            {
                var json = File.ReadAllText(filepath, Encoding.UTF8);
                var list = JsonConvert.DeserializeObject<List<VpnServer>>(json);
                var result = list?.ToDictionary(s => s["_server_id"]?.ToString(), s => s) ?? new Dictionary<string, VpnServer>();
                Logger.Info($"Загружено {result.Count} серверов из {filepath}");
                return result;
            }
            catch (Exception ex)
            {
                Logger.Error($"Ошибка чтения файла: {ex.Message}");
                return new Dictionary<string, VpnServer>();
            }
        }

        private static void SaveData(Dictionary<string, VpnServer> servers, string filepath)
        {
            List<VpnServer> data = servers.Values.ToList();

            // === JSON ===
            try
            {
                JArray jsonArray = new JArray();
                foreach (var srv in data)
                {
                    JObject obj = new JObject();
                    foreach (var kvp in srv) obj[kvp.Key] = kvp.Value is bool b ? new JValue(b) : JToken.FromObject(kvp.Value);
                    jsonArray.Add(obj);
                }
                File.WriteAllText(filepath, JsonConvert.SerializeObject(jsonArray, Formatting.Indented), Encoding.UTF8);
                Logger.Info($"Сохранено {data.Count} серверов в {filepath}");
            }
            catch (Exception ex) { Logger.Error($"Ошибка сохранения JSON: {ex.Message}"); }

            // === CSV (полный) ===
            try
            {
                string csvpath = filepath + ".csv";
                List<string> allKeys = data.FirstOrDefault()?.Keys.ToList() ?? new List<string>();
                if (allKeys.Count == 0) return;

                string[] targetKeys = new string[] { "Operator", "Message", "_source_url", "_fetched_at", "_server_id", "OpenVPN_ConfigData_Base64" };
                List<string> orderedKeys = allKeys.Where(k => !targetKeys.Contains(k)).ToList();
                foreach (var tk in targetKeys) if (allKeys.Contains(tk)) orderedKeys.Add(tk);

                StreamWriter sw = new StreamWriter(csvpath, false, Encoding.UTF8);
                sw.WriteLine(string.Join(",", orderedKeys));
                foreach (var srv in data)
                {
                    var values = orderedKeys.Select(k => EscapeCsvField(srv.TryGetValue(k, out var v) ? v?.ToString() ?? "" : "")).ToList();
                    sw.WriteLine(string.Join(",", values));
                }
                Logger.Info($"Сохранено {data.Count} серверов в {csvpath}");
            }
            catch (Exception ex) { Logger.Error($"Ошибка сохранения CSV: {ex.Message}"); }

            // === CSV (без конфига) ===
            try
            {
                string csvpath = filepath + "no_cfg.csv";
                List<string> allKeys = data.FirstOrDefault()?.Keys.ToList() ?? new List<string>();
                if (allKeys.Count == 0) return;

                string[] targetKeys = new string[] { "Operator", "Message", "_source_url", "_fetched_at", "_server_id", "OpenVPN_ConfigData_Base64" };
                List<string> orderedKeys = allKeys.Where(k => !targetKeys.Contains(k)).ToList();
                foreach (var tk in targetKeys) if (allKeys.Contains(tk) && tk != "OpenVPN_ConfigData_Base64") orderedKeys.Add(tk);

                StreamWriter sw = new StreamWriter(csvpath, false, Encoding.UTF8);
                sw.WriteLine(string.Join(",", orderedKeys));
                foreach (var srv in data)
                {
                    if (srv.TryGetValue("HostName", out var hn) && !string.IsNullOrEmpty(hn?.ToString()) && !hn.ToString().Contains("."))
                        srv["HostName"] = hn + ".opengw.net";

                    var values = orderedKeys.Where(k => k != "OpenVPN_ConfigData_Base64")
                        .Select(k => EscapeCsvField(srv.TryGetValue(k, out var v) ? v?.ToString() ?? "" : "")).ToList();
                    sw.WriteLine(string.Join(",", values));
                }
                Logger.Info($"Сохранено {data.Count} серверов в {csvpath}");
            }
            catch (Exception ex) { Logger.Error($"Ошибка сохранения CSV no_cfg: {ex.Message}"); }
        }

        private static string EscapeCsvField(string field)
        {
            if (field.Contains(',') || field.Contains('"') || field.Contains('\n') || field.Contains('\r'))
                return "\"" + field.Replace("\"", "\"\"") + "\"";
            return field;
        }

        private static void AsqMirrors()
        {
            Logger.Info("Начало сбора данных...");
            var db = LoadExisting(OUTPUT_FILE);
            var was = db.Count;

            foreach (var mirror in MIRRORS)
            {
                var servers = FetchMirror(mirror);
                if (servers.Count == 0) continue;

                foreach (var srv in servers)
                {
                    var sid = srv["_server_id"]?.ToString();
                    if (!string.IsNullOrEmpty(sid)) db[sid] = srv;
                }

                var nww = db.Count;
                Logger.Info($" ... Добавлено {nww - was} серверов.");
            }

            SaveData(db, OUTPUT_FILE);
            var final = db.Count;
            Logger.Info($"Сбор завершен. Добавлено {final - was} серверов.");
        }

        private static void Run()
        {
            Logger.Info($"Планировщик запущен: каждые {ASQ_PERIOD}H");
            AsqMirrors(); // Первый запуск

            while (true)
            {
                Thread.Sleep(TimeSpan.FromHours(ASQ_PERIOD));
                AsqMirrors();
            }
        }

        public static void Collect(string[] args)
        {
            try
            {
                if(args!= null)
                    foreach(string a in args)
                    {
                        if (a.StartsWith("--proxy_base=")) PROXY_BASE = a.Substring(13);
                        if (a.StartsWith("--proxy_cred=")) PROXY_CRED = a.Substring(13);
                    };
                Run();
            }
            catch (ThreadInterruptedException)
            {
                Logger.Info("Остановка.");
            }
            catch (Exception ex)
            {
                Logger.Error($"Критическая ошибка: {ex}");
            }
        }
    }

    // === ЛОГГЕР (как logging.basicConfig в Python) ===
    public interface ILogger
    {
        void Info(string message);
        void Error(string message);
        void Warn(string message);
        void Critical(string message);
    }

    public class ConsoleLogger : ILogger
    {
        private static readonly object LockObj = new object();

        public void Info(string message) => Log("[INFO]", message, ConsoleColor.White);
        public void Error(string message) => Log("[ERROR]", message, ConsoleColor.Red);
        public void Warn(string message) => Log("[WARN]", message, ConsoleColor.Yellow);
        public void Critical(string message) => Log("[CRITICAL]", message, ConsoleColor.DarkRed);

        private void Log(string level, string message, ConsoleColor color)
        {
            var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            var line = $"{timestamp} {level} {message}";

            lock (LockObj)
            {
                var prevColor = Console.ForegroundColor;
                Console.ForegroundColor = color;
                Console.WriteLine(line);
                Console.ForegroundColor = prevColor;

                try { File.AppendAllText("vpngate_curl.log", line + Environment.NewLine, Encoding.UTF8); }
                catch { }
            }
        }
    }
}