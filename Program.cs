using System;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Net.Sockets;
using NetRouteStabilizer;

internal class Program
{
    private static int delay = 20 * 1000; // 20 sec delay
    private static string script = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName), "NetRouteStabilizer.cmd");
    private static string csv_dnld = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName), "vpnroutes_vpngate.txt");
    private static string csv_finl = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName), "vpnroutes_vpngate_nocfg.csv");
    private static DateTime lastUpdate = DateTime.MinValue;
    private static bool isLaunchedNorm = false;

    private static readonly Regex PortRegex = new Regex(@"^remote\s+[\w\.:]+\s+(\d+)(?:\s+(tcp|udp))?", RegexOptions.Multiline | RegexOptions.IgnoreCase);
    private static readonly Regex PortTCPRegex = new Regex(@"^\s*proto\s+tcp\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase);
    private static readonly Regex PortUDPRegex = new Regex(@"^\s*proto\s+udp\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase);

    static void Main(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            if (string.Equals(args[i], "/rotate", StringComparison.OrdinalIgnoreCase)) { VPNGateRotator.ProcessRotate(args); return; };
            if (string.Equals(args[i], "/smonitor", StringComparison.OrdinalIgnoreCase)) { ScriptMonitor(args); return; };
            if (string.Equals(args[i], "/cmonitor", StringComparison.OrdinalIgnoreCase)) { CodeMonitor(args); return; };
            if (string.Equals(args[i], "/detectip", StringComparison.OrdinalIgnoreCase)) { GetIpAddressesByPrefix("10.211."); return; };
            if (string.Equals(args[i], "/stripcsv", StringComparison.OrdinalIgnoreCase)) { ParseVPNGateCSV(); return; };            
            if (string.Equals(args[i], "/shrinkvpnjson", StringComparison.OrdinalIgnoreCase)) { VPNGateRotator.ShrinkJSON(args); return; };
            if (string.Equals(args[i], "/stabilize", StringComparison.OrdinalIgnoreCase)) { Stabilizer.Stabilize(args); return; };
            if (string.Equals(args[i], "/direct", StringComparison.OrdinalIgnoreCase)) { Stabilizer.Direct(args, false); return; };
            if (string.Equals(args[i], "/normalize", StringComparison.OrdinalIgnoreCase)) { Stabilizer.Normalize(args, false); return; };
            if (string.Equals(args[i], "/proximize", StringComparison.OrdinalIgnoreCase)) { Stabilizer.Proximize(args, false); return; };
            if (string.Equals(args[i], "/deletenw", StringComparison.OrdinalIgnoreCase)) { Stabilizer.Deletize(args, false); return; };
            if (string.Equals(args[i], "/3proxy", StringComparison.OrdinalIgnoreCase)) { Stabilizer.Rotate3Proxy(args, false); return; };
            if (string.Equals(args[i], "/collect", StringComparison.OrdinalIgnoreCase)) { VpnGateCollector.Collect(args); return; };
        };
        Help();
    }

    private static void ScriptMonitor(string[] args)
    {         
        Console.WriteLine("=== https://github.com/dkxce/NetRouteStabilizer (C) dkxce 2026 ===");
        Console.WriteLine("=== Мониторинг изменений таблицы маршрутизации запущен ===");
        Console.WriteLine("=== Приложение автоматически запустит скрипт NetRouteStabilizer.cmd при изменении маршрутов. ===");
        Console.WriteLine("=== Для выхода нажмите Ctrl+C. ===\n");        

        Thread monitorThread = new Thread(StartRouteMonitoring);
        monitorThread.IsBackground = true;
        monitorThread.Start();

        while (true)
        {
            if (lastUpdate != DateTime.MinValue)
            {
                if (DateTime.UtcNow.Subtract(lastUpdate).TotalMilliseconds >= delay)
                {
                    lastUpdate = DateTime.MinValue;
                    GetRouteTableChanges();
                    RunCmdScript();
                };
            };
            Thread.Sleep(1000);
        };
    }

    private static void CodeMonitor(string[] args)
    {         
        Console.WriteLine("=== https://github.com/dkxce/NetRouteStabilizer (C) dkxce 2026 ===");
        Console.WriteLine("=== Мониторинг изменений таблицы маршрутизации запущен ===");
        Console.WriteLine("=== Приложение автоматически запустит скрипт NetRouteStabilizer.exe /stabilize при изменении маршрутов. ===");
        Console.WriteLine("=== Для выхода нажмите Ctrl+C. ===\n");        

        Thread monitorThread = new Thread(StartRouteMonitoring);
        monitorThread.IsBackground = true;
        monitorThread.Start();

        while (true)
        {
            if (lastUpdate != DateTime.MinValue)
            {
                if (DateTime.UtcNow.Subtract(lastUpdate).TotalMilliseconds >= delay)
                {
                    lastUpdate = DateTime.MinValue;
                    GetRouteTableChanges();
                    RunSelfScript(args);
                };
            };
            Thread.Sleep(1000);
        };
    }

    private static void Help()
    {
        Console.WriteLine("==========================================================================");
        Console.WriteLine("===     https://github.com/dkxce/NetRouteStabilizer (C) dkxce 2026     ===");
        Console.WriteLine("==========================================================================");
        Console.WriteLine("--- Args:                                                              ---");
        Console.WriteLine("---       /smonitor - Start Monitoring Changes in IP Route Table (cmd) ---");
        Console.WriteLine("---                   Run `NetRouteStabilizer.cmd on Detect`           ---");
        Console.WriteLine("---                                                                    ---");
        Console.WriteLine("---       /cmonitor - Start Monitoring Changes in IP Route Table (exe) ---");
        Console.WriteLine("---                   Run: - /stabilize on Detect with:                ---");
        Console.WriteLine("---                        - /rotate    (if VPNGate Disconnected)      ---");
        Console.WriteLine("---                        - /normalize (if VPNGate Metric is Low)     ---");
        Console.WriteLine("---                        - /proximize (if Connection is Alive)       ---");
        Console.WriteLine("---                        - /3proxy    (if Enabled in config)         ---");
        Console.WriteLine("---             (!) > Settings in NetRouteRotatorConfig.json (/rotate) ---");
        Console.WriteLine("---             (!) > Setting in NetRouteStabilizer.json      (others) ---");
        Console.WriteLine("---             (!) > Resettings by @ CLI @                            ---");
        Console.WriteLine("---                                                                    ---");
        Console.WriteLine("---       /rotate [/force] - Automatic Rotate VPNGate Servers          ---");
        Console.WriteLine("---                    (!) > Settings in NetRouteRotatorConfig.json    ---");
        Console.WriteLine("---                    (!) > Resettings by @ CLI @                     ---");
        Console.WriteLine("---                                                                    ---");
        Console.WriteLine("---       /stabilize       - Stabilize VPN GateConnection              ---");
        Console.WriteLine("---       /normalize       - Set Normal Direct/VPNGate Network         ---");
        Console.WriteLine("---       /proximize       - Set Normal Proxy Network                  ---");
        Console.WriteLine("---       /direct          - Set Direct Network connection             ---");
        Console.WriteLine("---       /deletenw        - Delete Proxy Network                      ---");
        Console.WriteLine("---       /3proxy          - Restart 3proxy on VPNGate IP              ---");
        Console.WriteLine("---       /shrinkvpnjson   - Shring VPNGate JSON 2 No base64cfg        ---");
        Console.WriteLine("---                    (!) > Setting in NetRouteStabilizer.json        ---");
        Console.WriteLine("---                    (!) > Resettings by @ CLI @                     ---");
        Console.WriteLine("---  Tools:                                                            ---");
        Console.WriteLine("---                                                                    ---");
        Console.WriteLine("---       /collect      - Collect VPNGate Servers                      ---");
        Console.WriteLine("---                       [proxy_base=socks5://127.0.0.1:1088]         ---");
        Console.WriteLine("---                       [proxy_cred=user:pass]                       ---");
        Console.WriteLine("---                                                                    ---");        
        Console.WriteLine("---       /detectip     - Detect IP Address of VPNGate Adapter         ---");        
        Console.WriteLine("---                                                                    ---");
        Console.WriteLine("---       /stripcsv     - Shring VPNGate CSV 2 No base64cfg            ---");
        Console.WriteLine("---                       Input  FileName: vpnroutes_vpngate.txt       ---");
        Console.WriteLine("---                       Output FileName: vpnroutes_vpngate_nocfg.csv ---");
        Console.WriteLine("---                                                                    ---");
        Console.WriteLine("==========================================================================");
        Console.WriteLine("---  SAMPLE (Direct New ServersRotate):                                ---");
        Console.WriteLine("---     /rotate /force /MaxExistingAttempts=0 /VPNServerPing=false     ---");
        Console.WriteLine("==========================================================================");
        System.Threading.Thread.Sleep(3000);
    }

    private static void GetRouteTableChanges()
    {
        try
        {
            var searcher = new ManagementObjectSearcher(
                "SELECT Destination, Mask, NextHop, Metric1, InterfaceIndex, Protocol FROM Win32_IP4RouteTable");

            Stabilizer.Log($"Текущие маршруты:");
            foreach (ManagementObject route in searcher.Get())
            {
                Stabilizer.Log($" - {route["Destination"]}/{route["Mask"]} -> {route["NextHop"]} (metric: {route["Metric1"]})");
            };
            Stabilizer.Log();
        }
        catch { };
    }

    private static void StartRouteMonitoring()
    {
        string query = "SELECT * FROM Win32_IP4RouteTableEvent";
        //string query = "SELECT * FROM __InstanceModificationEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_IP4RouteTable'";
        using (ManagementEventWatcher watcher = new ManagementEventWatcher(query))
        {
            watcher.EventArrived += (sender, e) =>
            {
                if (isLaunchedNorm) return; // изменения инициированы текущей программой         
                Stabilizer.Log($"Обнаружено изменение маршрута! Ждем {delay / 1000} секунд.");
                lastUpdate = DateTime.UtcNow;
            };

            try
            {
                watcher.Start();
                Stabilizer.Log($"Запуск листинга изменений.");
            }
            catch (ManagementException ex)
            {
                Stabilizer.Log($"  Ошибка запуска мониторинга: {ex.Message}");
                Stabilizer.Log($"  Возможно, требуются права администратора.");
            };

            Thread.Sleep(Timeout.Infinite);
        }
    }


    #region RUN
    private static void RunCmdScript()
    {
        Stabilizer.Log($"Запуск скрипта NetRouteStabilizer.cmd ...");
        isLaunchedNorm = true;
        // PingHost("ya.ru");
        RunCommandRealTime("cmd.exe", $"/c \"{script}\"");
        Thread.Sleep(5000);
        Stabilizer.Log($"Возврат к листингу изменений.");
        isLaunchedNorm = false;
    }

    private static void RunSelfScript(string[] args)
    {
        Stabilizer.Log($"Запуск скрипта NetRouteStabilizer.exe /stabilize ...");
        isLaunchedNorm = true;
        // PingHost("ya.ru");
        Stabilizer.Stabilize(args);
        Thread.Sleep(5000);
        Stabilizer.Log($"Возврат к листингу изменений.");
        isLaunchedNorm = false;
    }

    private static void RunCommand(string cmd, string args)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo(cmd, args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                Verb = "runas" // Запрос прав администратора при необходимости
            };

            using (Process p = Process.Start(psi))
            {
                string output = p.StandardOutput.ReadToEnd();
                string error = p.StandardError.ReadToEnd();
                p.WaitForExit();

                if (!string.IsNullOrWhiteSpace(output))
                    Stabilizer.Log(output.Trim());
                if (!string.IsNullOrWhiteSpace(error))
                    Console.ForegroundColor = ConsoleColor.Red;
                Stabilizer.Log($"ERR: {error.Trim()}");
                Console.ResetColor();
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Stabilizer.Log($"Ошибка выполнения команды '{cmd} {args}': {ex.Message}");
            Console.ResetColor();
        }
    }

    private static bool RunCommandRealTime(string fileName, string arguments, int timeout = 60000)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8
            }
        };

        // 1. Handle Real-time Output
        process.OutputDataReceived += (sender, e) =>
        {
            if (!string.IsNullOrEmpty(e.Data)) Stabilizer.Log(e.Data);
        };

        // 2. Handle Real-time Errors
        process.ErrorDataReceived += (sender, e) =>
        {
            if (!string.IsNullOrEmpty(e.Data))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Stabilizer.Log(e.Data);
                Console.ResetColor();
            }
        };

        process.Start();

        // 3. Begin Async Reading (Crucial for real-time)
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        // 4. Wait for completion
        if (!process.WaitForExit(timeout * 1000))
        {
            process.Kill();
            return false;
        };

        // 5. Check Success
        return process.ExitCode == 0;
    }

    #endregion RUN
    
    #region CSV

    private static void ParseVPNGateCSV()
    {
        Console.WriteLine("=== https://github.com/dkxce/NetRouteStabilizer (C) dkxce 2026 ===");
        Console.WriteLine($"=== Разбор файла {System.IO.Path.GetFileName(csv_dnld)} ===\n");

        StreamReader reader = null;
        StreamWriter writer = null;
        try
        {
            if (System.IO.File.Exists(csv_dnld))
            {
                FileInfo fi = new FileInfo(csv_dnld);
                Stabilizer.Log($"ФАЙЛ НАЙДЕН - {fi.Length} БАЙТ");
                reader = new StreamReader(csv_dnld);
                writer = new StreamWriter(csv_finl, false, Encoding.GetEncoding(1251));
            
                string line;
                int lineNumber = 0;
                
                while (true)
                {
                    if (reader.EndOfStream) break;
                    line = reader.ReadLine();
                    lineNumber++;

                    // Пропускаем магический заголовок *vpn_servers
                    if (lineNumber == 1 && line.StartsWith("*")) continue;

                    // Обрабатываем строку с заголовками столбцов
                    if (lineNumber == 2 && line.StartsWith("#"))
                    {
                        // Просто записываем заголовки без последнего поля
                        writer.WriteLine("HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,TCP,UDP,PORT");
                        writer.WriteLine($"{DateTime.UtcNow}Z,{fi.CreationTimeUtc}Z,-,-,-,-,-,-,-,-,-,-,SELECT * FROM THIS WHERE TCP = 'True' AND Operator NOT LIKE '%Only%',True,-,-");
                        continue;
                    };

                    // Обрабатываем строки с данными
                    if (!string.IsNullOrWhiteSpace(line) && !line.StartsWith("#"))
                    {
                        string cleanedLine = RemoveLastCsvField(line);
                        (bool parsed, bool tcp, bool udp, int port) = ParseServerLine(line);
                        cleanedLine += $",{tcp},{udp},{port}";
                        if (!string.IsNullOrEmpty(cleanedLine)) writer.WriteLine(cleanedLine);
                    };                    
                };
                Stabilizer.Log($"  РАЗОБРАНО {lineNumber-2} ЗАПИСЕЙ\n");                
            }
            else
            {
                Stabilizer.Log($"  ФАЙЛ НЕ НАЙДЕН !!!\n");
            };
        }
        catch { }
        finally
        {
            if (reader != null) reader.Close();
            if (writer != null) writer.Close();
        };
        try { File.Delete(csv_dnld); } catch { };
    }

    private static string RemoveLastCsvField(string csvLine)
    {
        if (string.IsNullOrEmpty(csvLine)) return csvLine;

        // Ищем последнюю запятую — всё после неё это поле с конфиг-данными
        int lastCommaIndex = csvLine.LastIndexOf(',');

        if (lastCommaIndex == -1) return string.Empty; // Неверный формат

        // Возвращаем всё до последней запятой
        return csvLine.Substring(0, lastCommaIndex);
    }

    private static (bool parsed, bool tcp, bool udp, int port) ParseServerLine(string csvLine)
    {
        try
        {
            // Находим последнюю запятую — после неё идёт Base64-конфиг
            int lastComma = csvLine.LastIndexOf(',');
            if (lastComma == -1) return (false, false, false, 0);

            // Основные поля (до конфига)
            string mainPart = csvLine.Substring(0, lastComma);
            string base64Config = csvLine.Substring(lastComma + 1);

            var fields = mainPart.Split(',');
            if (fields.Length < 7) return (false, false, false, 0);

            string hostName = fields[0];
            string ip = fields[1];
            string countryShort = fields[6];

            if (!int.TryParse(fields[2], out int score)) score = 0;
            if (!int.TryParse(fields[3], out int ping)) ping = 0;

            bool tcp = false;
            bool udp = false;
            int port = 0;
            try
            {
                byte[] configBytes = Convert.FromBase64String(base64Config.Trim());
                string config = Encoding.UTF8.GetString(configBytes);

                Match match = PortRegex.Match(config);
                if (match.Success && int.TryParse(match.Groups[1].Value, out port))
                {
                    string proto = match.Groups[2].Value.ToLower();
                    if (string.IsNullOrEmpty(proto) || proto == "tcp") tcp = true;
                };

                tcp = PortTCPRegex.IsMatch(config);
                udp = PortUDPRegex.IsMatch(config);
            }
            catch {  };
            return (true, tcp, udp, port);
        }
        catch
        {
            return (false, false, false, 0);
        };
    }

    #endregion CSV

    #region NetTools

    private static void PingHost(string host, int timeout = 3000)
    {
        try
        {
            Ping ping = new Ping();
            PingReply reply = ping.Send(host, timeout);
            if (reply.Status == IPStatus.Success) Stabilizer.Log($"Ping OK: {host} (TTL={reply.Options.Ttl})");
            else Stabilizer.Log($"Ping Fail: {host} ({reply.Status})");
        }
        catch { };
    }

    public static string GetIpAddressesByPrefix(string prefix, bool stdoud = true)
    {
        foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus == OperationalStatus.Up)
            {
                IPInterfaceProperties ipProperties = ni.GetIPProperties();
                foreach (UnicastIPAddressInformation ip in ipProperties.UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == AddressFamily.InterNetwork && ip.Address.ToString().StartsWith(prefix))
                    {                      
                        if(stdoud) Console.WriteLine(ip.Address.ToString());
                        return ip.Address.ToString();
                    };
                };
            };
        };
        if(stdoud) Console.WriteLine("0.0.0.0");
        return null;
    }

    #endregion NetTools

}
