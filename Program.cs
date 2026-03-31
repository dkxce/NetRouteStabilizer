using System;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Net.Sockets;

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
        bool has_stripcsv = false;
        bool has_detectip = false;
        for (int i = 0; i < args.Length; i++)
        {
            if (string.Equals(args[i], "/stripcsv", StringComparison.OrdinalIgnoreCase) && (has_stripcsv = true)) break;
            if (string.Equals(args[i], "/detectip", StringComparison.OrdinalIgnoreCase) && (has_detectip = true)) break;
        };

        if (has_stripcsv)
        {            
            ParseVPNGateCSV();
            return;
        };

        if (has_detectip)
        {
            GetIpAddressesByPrefix("10.211.");
            return;
        };

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

    private static void GetRouteTableChanges()
    {
        try
        {
            var searcher = new ManagementObjectSearcher(
                "SELECT Destination, Mask, NextHop, Metric1, InterfaceIndex, Protocol FROM Win32_IP4RouteTable");

            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Текущие маршруты:");
            foreach (ManagementObject route in searcher.Get())
            {
                Console.WriteLine($" - {route["Destination"]}/{route["Mask"]} -> {route["NextHop"]} (metric: {route["Metric1"]})");
            };
            Console.WriteLine();
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
                if (isLaunchedNorm) return;               
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Обнаружено изменение маршрута! Ждем {delay / 1000} секунд.");
                lastUpdate = DateTime.UtcNow;
            };

            try
            {
                watcher.Start();
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Запуск листинга изменений.");
            }
            catch (ManagementException ex)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Ошибка запуска мониторинга: {ex.Message}");
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Возможно, требуются права администратора.");
            };

            Thread.Sleep(Timeout.Infinite);
        }
    }

    private static void RunCmdScript()
    {
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Запуск скрипта NetRouteStabilizer.cmd ...");
        isLaunchedNorm = true;
        // PingHost("ya.ru");
        RunCommandRealTime("cmd.exe", $"/c \"{script}\"");
        Thread.Sleep(5000);
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Возврат к листингу изменений.");
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
                    Console.WriteLine(output.Trim());
                if (!string.IsNullOrWhiteSpace(error))
                    Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"ERR: {error.Trim()}");
                Console.ResetColor();
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"Ошибка выполнения команды '{cmd} {args}': {ex.Message}");
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
            if (!string.IsNullOrEmpty(e.Data)) Console.WriteLine(e.Data);
        };

        // 2. Handle Real-time Errors
        process.ErrorDataReceived += (sender, e) =>
        {
            if (!string.IsNullOrEmpty(e.Data))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(e.Data);
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

    private static void PingHost(string host)
    {
        try
        {
            Ping ping = new Ping();
            PingReply reply = ping.Send(host, 3000);
            if (reply.Status == IPStatus.Success) Console.WriteLine($"Ping OK: {host} (TTL={reply.Options.Ttl})");
            else Console.WriteLine($"Ping Fail: {host} ({reply.Status})");
        }
        catch {};
    }

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
                Console.WriteLine($"=== ФАЙЛ НАЙДЕН - {fi.Length} БАЙТ ===");
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
                Console.WriteLine($"=== РАЗОБРАНО {lineNumber-2} ЗАПИСЕЙ ===\n");                
            }
            else
            {
                Console.WriteLine($"=== ФАЙЛ НЕ НАЙДЕН !!! ===\n");
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

    private static string GetIpAddressesByPrefix(string prefix)
    {
        List<string> result = new List<string>();

        foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus == OperationalStatus.Up)
            {
                var ipProperties = ni.GetIPProperties();

                foreach (UnicastIPAddressInformation ip in ipProperties.UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == AddressFamily.InterNetwork &&
                        ip.Address.ToString().StartsWith(prefix))
                    {
                        result.Add(ip.Address.ToString());                        
                        Console.WriteLine(ip.Address.ToString());
                        return ip.Address.ToString();
                    };
                };
            };
        };
        Console.WriteLine("0.0.0.0");
        return null;
    }
}
