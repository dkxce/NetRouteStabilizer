using System;
using System.Diagnostics;
using System.Management;
using System.Net.NetworkInformation;
using System.Threading;

internal class Program
{
    private static int delay = 20 * 1000; // 20 sec delay
    private static string script = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName), "NetRouteStabilizer.cmd");
    private static DateTime lastUpdate = DateTime.MinValue;
    private static bool isLaunchedNorm = false;

    static void Main(string[] args)
    {
        Console.WriteLine("=== https://github.com/dkxce/NetRouteStabilizer (C) dkxce 2026 ===");
        Console.WriteLine("=== Мониторинг изменений таблицы маршрутизации запущен ===");
        Console.WriteLine("=== Приложение автоматически запустит скрипт NetRouteStabilizer.cmd при изменении маршрутов. ===");
        Console.WriteLine("Для выхода нажмите Ctrl+C.\n");        

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
                    RunCmdScript();
                };
            };
            Thread.Sleep(1000);
        };
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
}
