using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;

namespace NetRouteStabilizer
{
    

    public class ConsoleMenu
    {
        private readonly string[] _options;
        private readonly Action[] _actions;
        private readonly List<int> mapping = new List<int>();
        private readonly string _title = "MENU";
        private readonly ConsoleColor _selectedColor = ConsoleColor.Green;
        private readonly ConsoleColor _defaultColor = ConsoleColor.Gray;
        private int _countedElemnts = 0;
        private int _selectedIndex = 0;
        private int _startTop;
        private int _maxLength = 4;

        public byte   menuSpace             = 0;
        public byte   itemSpace             = 0;
        public byte   menuMinWidth          = 82;
        public bool   menuNumeration        = true;
        public bool   menuKeySelection      = true;
        public bool   menuKeyShow           = true;
        public string menuKeyShowPrefix     = ":: ";

        public string menuSymbolTopLeft     = "╔";
        public string menuSymbolHorizontal  = "═";
        public string menuSymbolTopRight    = "╗";
        public string menuSymbolBottomLeft  = "╚";
        public string menuSymbolBottomRight = "╝";
        public string menuSymbolEmptyness   = " ";
        public string menuSymbolVertical    = "║";         

        public string itemCursorPrefix      = "►";
        public string itemCursorPostfix     = "◄"; 

        public string itemSymbolTopLeft     = "┌";
        public string itemSymbolHorizontal  = "─";
        public string itemSymbolTopRight    = "┐";
        public string itemSymbolBottomLeft  = "└";
        public string itemSymbolBottomRight = "┘";
        public string itemSymbolEmptyness   = " ";
        public string itemSymbolVertical    = "│"; 
        

        public ConsoleMenu(IEnumerable<string> options, string title = null)
        {
            _options = options?.ToArray() ?? throw new ArgumentNullException(nameof(options));
            if (_options.Length == 0)  throw new ArgumentException("No options", nameof(options));

            if (!string.IsNullOrEmpty(title)) _title = title;
            _maxLength = Math.Max(menuMinWidth, title.Length);

            foreach (string option in _options)
            {
                _maxLength = Math.Max(_maxLength, option.Length);
                if (option.StartsWith("--") || option == "-") continue;
                _countedElemnts++;
            };
        }

        public ConsoleMenu(IEnumerable<KeyValuePair<string,Action>> options, string title = null)
        {
            KeyValuePair<string, Action>[] ops = options?.ToArray() ?? throw new ArgumentNullException(nameof(options));
            if (ops.Length == 0) throw new ArgumentException("No options", nameof(options));

            if (!string.IsNullOrEmpty(title)) _title = title;
            _maxLength = Math.Max(menuMinWidth, title.Length);

            _actions = new Action[ops.Length];
            _options = new string[ops.Length];
            for (int i = 0; i < ops.Length; i++)
            {
                _actions[i] = ops[i].Value;
                _options[i] = ops[i].Key;
                _maxLength = Math.Max(_maxLength, _options[i].Length);
                if (_options[i].StartsWith("--") || _options[i] == "-") continue;
                _countedElemnts++;
            };
        }

        public bool Show(out string element, out int index, bool treatControl = true)
        {
            element = "";
            index = -1;

            _startTop = Console.CursorTop;
            Console.CursorVisible = false;

            // Опционально: игнорировать Ctrl+C, чтобы не ломать цикл
            bool originalTreatControlC = Console.TreatControlCAsInput;
            if(treatControl) Console.TreatControlCAsInput = true;

            while (_options[_selectedIndex].StartsWith("--") || _options[_selectedIndex] == "-") _selectedIndex++;
            if (_selectedIndex >= _options.Length) _selectedIndex = 0;
            int _currentTop = Draw();
            ConsoleKey key;
            do
            {
                key = Console.ReadKey(true).Key;
                if (key == ConsoleKey.UpArrow || key == ConsoleKey.LeftArrow)
                {
                    _selectedIndex--;                    
                    if (_selectedIndex < 0) _selectedIndex = _options.Length - 1;
                    if (_options[_selectedIndex].StartsWith("--") || _options[_selectedIndex] == "-") _selectedIndex--;
                    if (_selectedIndex < 0) _selectedIndex = _options.Length - 1;
                }
                else if (key == ConsoleKey.DownArrow || key == ConsoleKey.RightArrow)
                {
                    _selectedIndex++;
                    if (_selectedIndex >= _options.Length) _selectedIndex = 0;
                    if (_options[_selectedIndex].StartsWith("--") || _options[_selectedIndex] == "-") _selectedIndex++;
                    if (_selectedIndex >= _options.Length) _selectedIndex = 0;
                }
                else if (menuKeySelection)
                {
                    int ind = -1;
                    if (key >= ConsoleKey.D0 && key <= ConsoleKey.D9) ind = (char)key - '0' - 1;
                    if (key >= ConsoleKey.NumPad0 && key <= ConsoleKey.NumPad9) ind = (byte)key - 96 - 1;
                    if (key >= ConsoleKey.A && key <= ConsoleKey.Z) ind = 10 + (int)key - 'A' - 1;
                    if (ind >= 0 && ind < mapping.Count)
                    {
                        _selectedIndex = mapping[ind];
                        if (_selectedIndex < 0) _selectedIndex = _options.Length - 1;
                        if (_selectedIndex >= _options.Length) _selectedIndex = 0;
                        if (_options[_selectedIndex].StartsWith("--") || _options[_selectedIndex] == "-") _selectedIndex++;
                        if (_selectedIndex >= _options.Length) _selectedIndex = 0;
                    };
                };
                _currentTop = Draw();
            } while (key != ConsoleKey.Enter && key != ConsoleKey.Escape);

            Console.CursorVisible = true;
            if (treatControl) Console.TreatControlCAsInput = originalTreatControlC;
            Console.ResetColor();
            Console.SetCursorPosition(0, _currentTop);

            if (key == ConsoleKey.Escape) return false;

            index = _selectedIndex;
            element = _options[_selectedIndex];
            _actions?[_selectedIndex]?.Invoke();
            return true;
        }

        private int Draw()
        {
            string line = "";
            int firstLine = _startTop;
            int ttlLength = 2 + _maxLength + (itemCursorPrefix.Length > 0 ? itemCursorPrefix.Length + 1 : 0) + (itemCursorPostfix.Length > 0 ? itemCursorPostfix.Length + 1 : 0);
            if (menuNumeration) ttlLength += _countedElemnts.ToString().Length + 3;
            if (menuKeyShow) ttlLength += 2 + menuKeyShowPrefix.Length;
            string frmt = "D" + _countedElemnts.ToString().Length.ToString();

            mapping.Clear();

            // Рисуем заголовок
            if (!string.IsNullOrEmpty(_title))
            {
                Console.SetCursorPosition(0, firstLine);
                Console.ForegroundColor = ConsoleColor.Cyan;

                line = menuSymbolTopLeft + "".PadRight(ttlLength, menuSymbolHorizontal[0]) + menuSymbolTopRight;
                Console.WriteLine(line);
                line = menuSymbolVertical + "".PadRight(ttlLength, menuSymbolEmptyness[0]) + menuSymbolVertical;
                for(int i = 0;i< menuSpace;i++) Console.WriteLine(line);
                Console.WriteLine(CenterInsert(line,_title,line.Length));
                for (int i = 0; i < menuSpace; i++) Console.WriteLine(line);
                line = menuSymbolBottomLeft + "".PadRight(ttlLength, menuSymbolHorizontal[0]) + menuSymbolBottomRight;
                Console.WriteLine(line);

                line = itemSymbolTopLeft + "".PadRight(ttlLength, itemSymbolHorizontal[0]) + itemSymbolTopRight;
                Console.WriteLine(line);
                line = itemSymbolVertical + "".PadRight(ttlLength, itemSymbolEmptyness[0]) + itemSymbolVertical;
                for (int i = 0; i < itemSpace; i++) Console.WriteLine(line);                

                ClearLine(Console.BufferWidth, line.Length);
                firstLine += (3 + menuSpace * 2) + (1 + itemSpace * 2);
            };

            // Рисуем пункты меню
            for (int i = 0; i < _options.Length; i++)
            {
                string current = _options[i];
                Console.SetCursorPosition(0, firstLine + i);                
                Console.ForegroundColor = (i == _selectedIndex) ? _selectedColor : _defaultColor;

                if (current.StartsWith("--") || current == "-")
                {
                    string prefix = "".PadRight(itemCursorPrefix.Length);
                    if (prefix.Length > 0) prefix += " ";
                    string postfix = "".PadRight(itemCursorPostfix.Length);
                    if (postfix.Length > 0) postfix = " " + postfix;
                    string inline = $"{itemSymbolVertical} {prefix}"
                        .PadRight(line.Length - postfix.Length - 2, itemSymbolHorizontal[0])
                        + $"{postfix} {itemSymbolVertical}";
                    if (current.StartsWith("--"))
                    {
                        string hr = current.Substring(2).Trim();
                        if (hr.Length > 0)
                        {
                            hr = " " + hr + " ";
                            inline = CenterInsert(inline, hr, line.Length);
                        };
                    };
                    Console.Write(inline);
                }
                else
                {
                    mapping.Add(i);
                    if (menuNumeration) current = $"[{mapping.Count.ToString(frmt)}] {current}";
                    string prefix = (i == _selectedIndex) ? itemCursorPrefix : "".PadRight(itemCursorPrefix.Length);
                    if (prefix.Length > 0) prefix += " ";
                    string postfix = (i == _selectedIndex) ? itemCursorPostfix : "".PadRight(itemCursorPostfix.Length);
                    if (postfix.Length > 0) postfix = " " + postfix;
                    if(menuKeyShow)
                    {
                        char c = '?';
                        if (mapping.Count < 10) c = (char)('0' + mapping.Count);
                        else c = (char)('A' + mapping.Count - 10d);
                        postfix = $" {menuKeyShowPrefix}{c}" + postfix;
                    };
                    string inline = $"{itemSymbolVertical} {prefix}{current}";
                    inline = inline.PadRight(line.Length - postfix.Length - 2) + $"{postfix} {itemSymbolVertical}";
                    Console.Write(inline);                   
                };
                ClearLine(Console.BufferWidth, line.Length);
            };

            // Рисуем футер
            if(true)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                for (int i = 0; i < itemSpace; i++) Console.WriteLine(line);
                Console.WriteLine(CenterInsert(line, ".: Use Arrows" + (menuKeyShow ? " or char/numeric keys" : "") + " to Select :.",line.Length));
                line = itemSymbolBottomLeft + "".PadRight(ttlLength, itemSymbolHorizontal[0]) + itemSymbolBottomRight;
                Console.WriteLine(line);
                firstLine += _options.Length + (1 + itemSpace * 2) + 1;
            };

            Console.ResetColor();
            return firstLine;
        }

        // Вспомогательный метод для очистки остатка строки (предотвращает артефакты при разной длине пунктов)
        private static void ClearLine(int bufferWidth, int textLength)
        {
            int remaining = Math.Max(0, bufferWidth - textLength);
            if (remaining > 0) Console.Write(new string(' ', remaining));
        }

        private static string CenterInsert(string original, string newText, int totalLength)
        {
            if (string.IsNullOrEmpty(original) || original.Length < newText.Length)
                return original.PadRight(totalLength); // Or handle error

            // Calculate center
            int totalToRemove = newText.Length;
            int startRemove = (original.Length - totalToRemove) / 2;

            // Build the string
            string leftPart = original.Substring(0, startRemove);
            string rightPart = original.Substring(startRemove + totalToRemove);

            string result = leftPart + newText + rightPart;

            // Ensure fixed length
            return result.PadRight(totalLength).Substring(0, totalLength);
        }

        public static void Test()
        {
            var menu = new ConsoleMenu(
                new[] { "Запустить", "Настройки", "Документация", "--", "Справка", "--", "Выход" },
                title: "Главное меню"
            );

            Console.WriteLine("Нажмите Enter для выбора, Esc для отмены.");
            Console.WriteLine(new string('-', 40));

            menu.Show(out string choice,out _);

            if (choice == null)
                Console.WriteLine("Выбор отменён.");
            else
                Console.WriteLine($"Вы выбрали: {choice}");
            Console.ReadKey();
        }

        public static void Test2()
        {
            List<KeyValuePair<string, Action>> elems = new List<KeyValuePair<string, Action>>();
            elems.Add(new KeyValuePair<string, Action>("Запустить", () => Console.WriteLine("RUN")));
            elems.Add(new KeyValuePair<string, Action>("Настройки", () => Console.WriteLine("SETUP")));
            elems.Add(new KeyValuePair<string, Action>("Документация", () => Console.WriteLine("DOCS")));
            elems.Add(new KeyValuePair<string, Action>("--Еще:", null));
            elems.Add(new KeyValuePair<string, Action>("Справка", () => Console.WriteLine("HELP")));
            elems.Add(new KeyValuePair<string, Action>("--", null));
            elems.Add(new KeyValuePair<string, Action>("Выход", () => Console.WriteLine("EXIT")));
            var menu = new ConsoleMenu(elems, title: "Главное меню (with Actions)");

            Console.WriteLine("Нажмите Enter для выбора, Esc для отмены.");
            Console.WriteLine(new string('-', 40));

            menu.Show(out string choice, out _);
            Console.ReadKey();
        }
    }
}
