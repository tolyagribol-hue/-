# Security.py - ФИКС СТАТИСТИКИ
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog, filedialog
import os
import psutil
import platform
from datetime import datetime
import csv

# ==================== БАЗОВЫЕ КОМПОНЕНТЫ ====================

class BasicFileScanner:
    """Базовый сканер файлов"""
    
    def __init__(self):
        self.suspicious_extensions = ['.exe', '.bat', '.vbs', '.ps1', '.js']
        self.scan_results = []
        self.unique_files_scanned = set()  # Для отслеживания уникальных файлов
    
    def quick_scan(self, path=None):
        """Быстрое сканирование"""
        if not path:
            path = os.path.expanduser('~\\Downloads')
        
        threats = []
        try:
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        filepath = os.path.join(root, file)
                        file_id = f"{filepath}_{os.path.getsize(filepath) if os.path.exists(filepath) else 0}"
                        
                        # Проверяем, сканировали ли уже этот файл
                        if file_id in self.unique_files_scanned:
                            continue
                        
                        self.unique_files_scanned.add(file_id)
                        ext = os.path.splitext(file)[1].lower()
                        
                        if ext in self.suspicious_extensions:
                            threats.append({
                                'file': filepath,
                                'type': 'FILE',
                                'reason': f'Подозрительное расширение {ext}',
                                'timestamp': datetime.now()
                            })
        
        except Exception as e:
            print(f"Ошибка сканирования: {e}")
        
        # Добавляем только новые угрозы
        for threat in threats:
            if not any(t['file'] == threat['file'] for t in self.scan_results):
                self.scan_results.append(threat)
        
        return threats

class BasicProcessMonitor:
    """Базовый монитор процессов"""
    
    def __init__(self):
        pass
    
    def get_processes(self):
        """Получение списка процессов"""
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    info = proc.info
                    processes.append({
                        'pid': info['pid'],
                        'name': info['name'],
                        'cpu': info['cpu_percent'],
                        'memory': info['memory_percent']
                    })
                except:
                    continue
        except:
            pass
        return processes

class BasicNetworkMonitor:
    """Базовый сетевой монитор"""
    
    def __init__(self):
        pass
    
    def get_connections(self):
        """Получение сетевых соединений"""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    if conn.raddr:
                        connections.append({
                            'pid': conn.pid,
                            'local': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                            'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                            'status': conn.status
                        })
                except:
                    continue
        except:
            pass
        return connections

# ==================== ГЛАВНОЕ ПРИЛОЖЕНИЕ ====================

class SecurityMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ МОНИТОР БЕЗОПАСНОСТИ")
        self.root.geometry("1400x800")
        self.root.configure(bg='#0a1929')
        
        # Инициализация компонентов
        self.file_scanner = BasicFileScanner()
        self.process_monitor = BasicProcessMonitor()
        self.network_monitor = BasicNetworkMonitor()
        
        # Цветовая схема
        self.colors = {
            'critical': '#ff4757',
            'high': '#ff6b81',
            'medium': '#ffa502',
            'low': '#2ed573',
            'info': '#1e90ff',
            'dark_bg': '#0a1929',
            'panel_bg': '#1e2a3a',
            'text': '#f1f2f6',
            'border': '#2f3542',
            'danger': '#ff4757',
            'primary': '#1e90ff',
            'warning': '#ffa502',
            'success': '#2ed573'
        }
        
        # Статистика (реальная, не накручивается)
        self.stats = {
            'files_scanned': 0,
            'threats_found': 0,  # Теперь будет показывать реальное количество уникальных угроз
            'processes': 0,
            'connections': 0
        }
        
        # Инициализация интерфейса
        self.init_ui()
        
        # Начальная загрузка данных
        self.update_all_data()
    
    def init_ui(self):
        """Инициализация интерфейса"""
        # Основной контейнер
        main_container = tk.Frame(self.root, bg=self.colors['dark_bg'])
        main_container.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Заголовок
        self.create_header(main_container)
        
        # Вкладки
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill='both', expand=True, pady=10)
        
        # Создание вкладок
        self.create_dashboard_tab()
        self.create_file_scanner_tab()
        self.create_process_monitor_tab()
        self.create_network_tab()
        
    def create_header(self, parent):
        """Создание заголовка"""
        header = tk.Frame(parent, bg=self.colors['panel_bg'], height=80)
        header.pack(fill='x', pady=(0, 10))
        header.pack_propagate(False)
        
        # Заголовок
        tk.Label(
            header,
            text="🛡️ СИСТЕМА МОНИТОРИНГА БЕЗОПАСНОСТИ",
            font=('Arial', 18, 'bold'),
            fg=self.colors['text'],
            bg=self.colors['panel_bg']
        ).pack(side='left', padx=20, pady=20)
        
        # Кнопки управления
        control_frame = tk.Frame(header, bg=self.colors['panel_bg'])
        control_frame.pack(side='right', padx=20, pady=20)
        
        tk.Button(
            control_frame,
            text="🔍 Быстрое сканирование",
            command=self.quick_scan_action,
            bg=self.colors['primary'],
            fg='white',
            font=('Arial', 10),
            padx=15
        ).pack(side='left', padx=5)
        
        tk.Button(
            control_frame,
            text="🔄 Обновить всё",
            command=self.update_all_data,
            bg=self.colors['info'],
            fg='white',
            font=('Arial', 10),
            padx=15
        ).pack(side='left', padx=5)
        
        # Статистика
        stats_frame = tk.Frame(header, bg=self.colors['panel_bg'])
        stats_frame.pack(side='right', padx=30)
        
        self.stats_labels = {}
        stats_info = [
            ("📁 Файлы", "files_scanned", "#1e90ff"),
            ("⚠️ Угрозы", "threats_found", "#ff4757"),
            ("🖥️ Процессы", "processes", "#2ed573"),
            ("🌐 Соединения", "connections", "#ffa502")
        ]
        
        for text, key, color in stats_info:
            frame = tk.Frame(stats_frame, bg=self.colors['panel_bg'])
            frame.pack(side='left', padx=10)
            
            tk.Label(
                frame,
                text=text,
                font=('Arial', 9),
                fg='#94a3b8',
                bg=self.colors['panel_bg']
            ).pack()
            
            self.stats_labels[key] = tk.Label(
                frame,
                text="0",
                font=('Arial', 14, 'bold'),
                fg=color,
                bg=self.colors['panel_bg']
            )
            self.stats_labels[key].pack()
    
    def create_dashboard_tab(self):
        """Вкладка дашборда"""
        tab = tk.Frame(self.notebook, bg=self.colors['dark_bg'])
        self.notebook.add(tab, text='📊 Дашборд')
        
        # Левая панель - система
        left_frame = tk.LabelFrame(
            tab,
            text="🖥️ Информация о системе",
            font=('Arial', 11, 'bold'),
            bg=self.colors['panel_bg'],
            fg=self.colors['text'],
            padx=15,
            pady=15
        )
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        # Информация о системе
        sys_info = f"""
Операционная система: {platform.system()} {platform.release()}
Процессор: {platform.processor()}
Версия Python: {platform.python_version()}
Пользователь: {os.getlogin()}
Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        sys_text = scrolledtext.ScrolledText(
            left_frame,
            height=10,
            font=('Consolas', 9),
            bg='#1a1a1a',
            fg='white'
        )
        sys_text.pack(fill='both', expand=True)
        sys_text.insert('1.0', sys_info)
        sys_text.config(state='disabled')
        
        # Правая панель - активность
        right_frame = tk.LabelFrame(
            tab,
            text="📋 Последние события",
            font=('Arial', 11, 'bold'),
            bg=self.colors['panel_bg'],
            fg=self.colors['text'],
            padx=15,
            pady=15
        )
        right_frame.pack(side='right', fill='both', expand=True, padx=5, pady=5)
        
        self.activity_text = scrolledtext.ScrolledText(
            right_frame,
            height=25,
            font=('Consolas', 9),
            bg='#1a1a1a',
            fg='white',
            insertbackground='white'
        )
        self.activity_text.pack(fill='both', expand=True)
        
        # Начальное сообщение
        self.update_activity("Система запущена")
    
    def create_file_scanner_tab(self):
        """Вкладка сканирования файлов"""
        tab = tk.Frame(self.notebook, bg=self.colors['dark_bg'])
        self.notebook.add(tab, text='📁 Сканер файлов')
        
        # Управление
        control_frame = tk.LabelFrame(
            tab,
            text="🔍 Управление сканированием",
            font=('Arial', 11, 'bold'),
            bg=self.colors['panel_bg'],
            fg=self.colors['text'],
            padx=15,
            pady=15
        )
        control_frame.pack(fill='x', padx=10, pady=10)
        
        # Выбор пути
        path_frame = tk.Frame(control_frame, bg=self.colors['panel_bg'])
        path_frame.pack(fill='x', pady=5)
        
        tk.Label(
            path_frame,
            text="Путь для сканирования:",
            font=('Arial', 9),
            fg=self.colors['text'],
            bg=self.colors['panel_bg']
        ).pack(side='left', padx=5)
        
        self.scan_path_var = tk.StringVar(value=os.path.expanduser('~\\Downloads'))
        path_entry = tk.Entry(
            path_frame,
            textvariable=self.scan_path_var,
            width=50,
            bg='#2d3748',
            fg='white'
        )
        path_entry.pack(side='left', padx=5)
        
        tk.Button(
            path_frame,
            text="Обзор",
            command=self.browse_path,
            bg=self.colors['info'],
            fg='white',
            font=('Arial', 9)
        ).pack(side='left', padx=5)
        
        # Кнопки сканирования
        button_frame = tk.Frame(control_frame, bg=self.colors['panel_bg'])
        button_frame.pack(fill='x', pady=10)
        
        tk.Button(
            button_frame,
            text="🚀 Быстрое сканирование",
            command=self.quick_scan_action,
            bg=self.colors['primary'],
            fg='white',
            font=('Arial', 10),
            padx=20
        ).pack(side='left', padx=5)
        
        tk.Button(
            button_frame,
            text="🎯 Полное сканирование",
            command=self.full_scan_action,
            bg=self.colors['warning'],
            fg='white',
            font=('Arial', 10),
            padx=20
        ).pack(side='left', padx=5)
        
        # Результаты
        results_frame = tk.LabelFrame(
            tab,
            text="📋 Результаты сканирования",
            font=('Arial', 11, 'bold'),
            bg=self.colors['panel_bg'],
            fg=self.colors['text'],
            padx=15,
            pady=15
        )
        results_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Таблица результатов
        columns = ('Файл', 'Тип', 'Статус', 'Время')
        self.scan_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.scan_tree.heading(col, text=col)
            self.scan_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(results_frame, orient='vertical', command=self.scan_tree.yview)
        self.scan_tree.configure(yscrollcommand=scrollbar.set)
        
        self.scan_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Кнопки управления
        manage_frame = tk.Frame(results_frame, bg=self.colors['panel_bg'])
        manage_frame.pack(fill='x', pady=5)
        
        tk.Button(
            manage_frame,
            text="🗑️ Очистить результаты",
            command=self.clear_scan_results,
            bg=self.colors['danger'],
            fg='white',
            font=('Arial', 9)
        ).pack(side='left', padx=2)
        
        tk.Button(
            manage_frame,
            text="💾 Экспорт в CSV",
            command=self.export_scan_results,
            bg=self.colors['success'],
            fg='white',
            font=('Arial', 9)
        ).pack(side='left', padx=2)
    
    def create_process_monitor_tab(self):
        """Вкладка процессов"""
        tab = tk.Frame(self.notebook, bg=self.colors['dark_bg'])
        self.notebook.add(tab, text='🖥️ Монитор процессов')
        
        # Управление
        control_frame = tk.LabelFrame(
            tab,
            text="🖥️ Управление процессами",
            font=('Arial', 11, 'bold'),
            bg=self.colors['panel_bg'],
            fg=self.colors['text'],
            padx=15,
            pady=15
        )
        control_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Button(
            control_frame,
            text="🔄 Обновить процессы",
            command=self.update_processes,
            bg=self.colors['primary'],
            fg='white',
            font=('Arial', 10),
            padx=15
        ).pack(side='left', padx=5)
        
        # Таблица процессов
        table_frame = tk.LabelFrame(
            tab,
            text="📋 Запущенные процессы",
            font=('Arial', 11, 'bold'),
            bg=self.colors['panel_bg'],
            fg=self.colors['text'],
            padx=15,
            pady=15
        )
        table_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        columns = ('PID', 'Имя', 'CPU %', 'Память %')
        self.process_tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.process_tree.heading(col, text=col)
            self.process_tree.column(col, width=120)
        
        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=scrollbar.set)
        
        self.process_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Инициализация процессов
        self.update_processes()
    
    def create_network_tab(self):
        """Вкладка сети"""
        tab = tk.Frame(self.notebook, bg=self.colors['dark_bg'])
        self.notebook.add(tab, text='🌐 Сетевой монитор')
        
        # Управление
        control_frame = tk.LabelFrame(
            tab,
            text="🌐 Сетевые соединения",
            font=('Arial', 11, 'bold'),
            bg=self.colors['panel_bg'],
            fg=self.colors['text'],
            padx=15,
            pady=15
        )
        control_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Button(
            control_frame,
            text="🔄 Обновить соединения",
            command=self.update_network,
            bg=self.colors['primary'],
            fg='white',
            font=('Arial', 10),
            padx=15
        ).pack(side='left', padx=5)
        
        # Таблица соединений
        table_frame = tk.LabelFrame(
            tab,
            text="📋 Сетевые соединения",
            font=('Arial', 11, 'bold'),
            bg=self.colors['panel_bg'],
            fg=self.colors['text'],
            padx=15,
            pady=15
        )
        table_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        columns = ('PID', 'Локальный адрес', 'Удаленный адрес', 'Статус')
        self.network_tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.network_tree.heading(col, text=col)
            self.network_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.network_tree.yview)
        self.network_tree.configure(yscrollcommand=scrollbar.set)
        
        self.network_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Инициализация сети
        self.update_network()
    
    # ==================== ОСНОВНЫЕ МЕТОДЫ ====================
    
    def quick_scan_action(self):
        """Быстрое сканирование"""
        path = self.scan_path_var.get()
        self.update_activity(f"Начинаю быстрое сканирование: {path}")
        
        # Сканируем
        new_threats = self.file_scanner.quick_scan(path)
        
        # Обновляем статистику (реальные данные)
        self.stats['files_scanned'] = len(self.file_scanner.unique_files_scanned)
        self.stats['threats_found'] = len(self.file_scanner.scan_results)
        
        # Обновление таблицы
        self.update_scan_results(new_threats)
        
        # Обновление активности
        self.update_activity(f"Сканирование завершено. Найдено новых угроз: {len(new_threats)}")
        self.update_stats_display()
        
        if new_threats:
            messagebox.showwarning("Результаты", f"Найдено {len(new_threats)} новых угроз. Всего угроз в базе: {self.stats['threats_found']}")
        else:
            messagebox.showinfo("Результаты", "Новых угроз не найдено")
    
    def full_scan_action(self):
        """Полное сканирование"""
        self.update_activity("Начинаю полное сканирование системы...")
        
        # Сканирование основных директорий
        scan_paths = [
            os.path.expanduser('~\\Downloads'),
            os.path.expanduser('~\\Desktop'),
            os.path.expanduser('~\\Documents')
        ]
        
        all_new_threats = []
        for path in scan_paths:
            new_threats = self.file_scanner.quick_scan(path)
            all_new_threats.extend(new_threats)
        
        # Обновляем реальную статистику
        self.stats['files_scanned'] = len(self.file_scanner.unique_files_scanned)
        self.stats['threats_found'] = len(self.file_scanner.scan_results)
        
        # Обновление таблицы
        self.update_scan_results(all_new_threats)
        
        # Обновление активности
        self.update_activity(f"Полное сканирование завершено. Найдено новых угроз: {len(all_new_threats)}")
        self.update_stats_display()
        
        messagebox.showinfo(
            "Сканирование завершено", 
            f"Всего просканировано файлов: {self.stats['files_scanned']}\n"
            f"Всего угроз в базе: {self.stats['threats_found']}\n"
            f"Новых угроз в этом сканировании: {len(all_new_threats)}"
        )
    
    def update_scan_results(self, threats):
        """Обновление результатов сканирования"""
        # Очистка таблицы
        for item in self.scan_tree.get_children():
            self.scan_tree.delete(item)
        
        # Показываем последние 50 угроз
        recent_threats = self.file_scanner.scan_results[-50:] if len(self.file_scanner.scan_results) > 50 else self.file_scanner.scan_results
        
        for threat in recent_threats:
            file_path = threat.get('file', '')
            file_name = os.path.basename(file_path) if file_path else 'Неизвестно'
            
            self.scan_tree.insert('', 'end', values=(
                file_name[:40] + '...' if len(file_name) > 40 else file_name,
                threat.get('type', 'ФАЙЛ'),
                threat.get('reason', 'Подозрительный файл'),
                threat.get('timestamp', datetime.now()).strftime('%H:%M:%S')
            ))
    
    def clear_scan_results(self):
        """Очистка результатов сканирования"""
        if messagebox.askyesno("Подтверждение", "Очистить все результаты сканирования?"):
            for item in self.scan_tree.get_children():
                self.scan_tree.delete(item)
            
            self.file_scanner.scan_results.clear()
            self.file_scanner.unique_files_scanned.clear()
            
            # Сбрасываем статистику
            self.stats['files_scanned'] = 0
            self.stats['threats_found'] = 0
            
            self.update_stats_display()
            self.update_activity("Результаты сканирования полностью очищены")
            messagebox.showinfo("Очистка", "Все результаты сканирования удалены")
    
    def export_scan_results(self):
        """Экспорт результатов сканирования"""
        if not self.file_scanner.scan_results:
            messagebox.showinfo("Экспорт", "Нет данных для экспорта")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV файлы", "*.csv"), ("Все файлы", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Файл', 'Тип', 'Причина', 'Время', 'Статус'])
                    
                    for threat in self.file_scanner.scan_results:
                        writer.writerow([
                            threat.get('file', ''),
                            threat.get('type', ''),
                            threat.get('reason', ''),
                            threat.get('timestamp', datetime.now()).strftime('%Y-%m-%d %H:%M:%S'),
                            'Обнаружено'
                        ])
                
                self.update_activity(f"Экспортировано {len(self.file_scanner.scan_results)} записей в {file_path}")
                messagebox.showinfo("Экспорт", f"Сохранено {len(self.file_scanner.scan_results)} записей")
                
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось экспортировать: {e}")
    
    def update_processes(self):
        """Обновление списка процессов"""
        # Очистка таблицы
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        try:
            processes = self.process_monitor.get_processes()
            self.stats['processes'] = len(processes)
            
            # Показываем первые 100 процессов
            for proc in processes[:100]:
                self.process_tree.insert('', 'end', values=(
                    proc.get('pid', ''),
                    proc.get('name', '')[:20],
                    f"{proc.get('cpu', 0):.1f}",
                    f"{proc.get('memory', 0):.1f}"
                ))
            
            self.update_stats_display()
            
        except Exception as e:
            self.update_activity(f"Ошибка обновления процессов: {e}")
    
    def update_network(self):
        """Обновление сетевых соединений"""
        # Очистка таблицы
        for item in self.network_tree.get_children():
            self.network_tree.delete(item)
        
        try:
            connections = self.network_monitor.get_connections()
            self.stats['connections'] = len(connections)
            
            # Показываем первые 100 соединений
            for conn in connections[:100]:
                self.network_tree.insert('', 'end', values=(
                    conn.get('pid', ''),
                    conn.get('local', ''),
                    conn.get('remote', ''),
                    conn.get('status', '')
                ))
            
            self.update_stats_display()
            
        except Exception as e:
            self.update_activity(f"Ошибка обновления сети: {e}")
    
    def browse_path(self):
        """Выбор пути для сканирования"""
        path = filedialog.askdirectory(title="Выберите папку для сканирования")
        if path:
            self.scan_path_var.set(path)
    
    def update_all_data(self):
        """Обновление всех данных"""
        self.update_processes()
        self.update_network()
        self.update_stats_display()
        self.update_activity("Все данные обновлены")
    
    def update_activity(self, message):
        """Обновление активности"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.activity_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.activity_text.see(tk.END)
    
    def update_stats_display(self):
        """Обновление отображения статистики"""
        # Обновляем все метки статистики
        self.stats_labels['files_scanned'].config(text=str(self.stats['files_scanned']))
        self.stats_labels['threats_found'].config(text=str(self.stats['threats_found']))
        self.stats_labels['processes'].config(text=str(self.stats['processes']))
        self.stats_labels['connections'].config(text=str(self.stats['connections']))
    
    def on_closing(self):
        """Обработка закрытия"""
        self.root.destroy()

def main():
    root = tk.Tk()
    app = SecurityMonitor(root)
    
    # Обработка закрытия
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    # Запуск
    root.mainloop()

if __name__ == "__main__":
    main()