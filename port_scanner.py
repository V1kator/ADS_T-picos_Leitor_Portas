import socket
import threading
import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from queue import Queue, Empty
import csv
import json

class PortScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner Avançado")
        self.root.geometry("880x760")
        self.root.resizable(True, True)

        # Estado
        self.scanning = False
        self.stopped_by_user = False
        self.queue = Queue()
        self.threads = []
        self.scan_results = []  # cada item: dict {ip, port, status, proto}
        self.total_tasks = 0
        self.completed_tasks = 0
        self.lock = threading.Lock()

        self.create_widgets()

    def create_widgets(self):
        main = ttk.Frame(self.root, padding=10)
        main.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        title = ttk.Label(main, text="Port Scanner Avançado", font=("Arial", 16, "bold"))
        title.grid(row=0, column=0, columnspan=4, pady=8)

        ttk.Label(main, text="Endereço IP, Range ou CIDR:").grid(row=1, column=0, sticky=tk.W)
        self.ip_entry = ttk.Entry(main, width=36)
        self.ip_entry.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=4)
        self.ip_entry.insert(0, "127.0.0.1")
        ttk.Label(main, text="Ex: 192.168.1.1, 192.168.1.10-192.168.1.50, 192.168.1.0/24").grid(row=2, column=1, sticky=tk.W)

        ttk.Label(main, text="Tipo de Escaneamento:").grid(row=3, column=0, sticky=tk.W, pady=6)
        self.scan_type = tk.StringVar(value="TCP")
        stf = ttk.Frame(main)
        stf.grid(row=3, column=1, sticky=tk.W)
        ttk.Radiobutton(stf, text="TCP", variable=self.scan_type, value="TCP").pack(side=tk.LEFT)
        ttk.Radiobutton(stf, text="UDP", variable=self.scan_type, value="UDP").pack(side=tk.LEFT, padx=12)

        # Porta específica
        ttk.Label(main, text="Porta específica (opcional):").grid(row=4, column=0, sticky=tk.W, pady=4)
        self.single_port = ttk.Entry(main, width=15)
        self.single_port.grid(row=4, column=1, sticky=tk.W, pady=4)
        ttk.Label(main, text="(se preenchido, ignora o range de portas)").grid(row=4, column=2, sticky=tk.W)

        # Portas range
        ttk.Label(main, text="Porta Inicial:").grid(row=5, column=0, sticky=tk.W, pady=4)
        self.port_start = ttk.Entry(main, width=12)
        self.port_start.grid(row=5, column=1, sticky=tk.W)
        self.port_start.insert(0, "1")

        ttk.Label(main, text="Porta Final:").grid(row=6, column=0, sticky=tk.W, pady=4)
        self.port_end = ttk.Entry(main, width=12)
        self.port_end.grid(row=6, column=1, sticky=tk.W)
        self.port_end.insert(0, "1024")

        # Botões principais
        btnf = ttk.Frame(main)
        btnf.grid(row=7, column=0, columnspan=4, pady=10)
        self.scan_button = ttk.Button(btnf, text="Iniciar Escaneamento", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=6)
        self.stop_button = ttk.Button(btnf, text="Parar Escaneamento", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=6)

        # Export
        ttk.Button(btnf, text="Exportar CSV", command=self.export_csv).pack(side=tk.LEFT, padx=6)
        ttk.Button(btnf, text="Exportar JSON", command=self.export_json).pack(side=tk.LEFT, padx=6)

        # Filtro
        ttk.Label(main, text="Filtrar por status:").grid(row=8, column=0, sticky=tk.W, pady=6)
        self.filter_var = tk.StringVar(value="Todos")
        self.filter_combo = ttk.Combobox(main, textvariable=self.filter_var, width=20,
                                         values=["Todos", "Aberta", "Fechada", "Filtrada", "Aberta|Filtrada", "Inacessível", "Erro"])
        self.filter_combo.grid(row=8, column=1, sticky=tk.W)
        self.filter_combo.bind('<<ComboboxSelected>>', self.apply_filter)

        # Barra de progresso (determinate configurada ao iniciar)
        self.progress = ttk.Progressbar(main, mode='determinate')
        self.progress.grid(row=9, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=10)

        # Resultados
        resf = ttk.Frame(main)
        resf.grid(row=10, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S))
        ttk.Label(resf, text="Resultados:").grid(row=0, column=0, sticky=tk.W)
        self.result_count = ttk.Label(resf, text="Total: 0 | Abertas: 0 | Fechadas: 0 | Filtradas: 0 | Ambíguas: 0")
        self.result_count.grid(row=0, column=1, sticky=tk.E)

        columns = ("ip", "port_proto", "status")
        self.tree = ttk.Treeview(resf, columns=columns, show='headings', height=18)
        self.tree.heading('ip', text='IP')
        self.tree.heading('port_proto', text='Porta/Proto')
        self.tree.heading('status', text='Status')
        self.tree.column('ip', width=160)
        self.tree.column('port_proto', width=120)
        self.tree.column('status', width=140)
        self.tree.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=6)

        sb = ttk.Scrollbar(resf, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.grid(row=1, column=3, sticky=(tk.N, tk.S))

        # Layout stretch
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)
        resf.columnconfigure(1, weight=1)
        resf.rowconfigure(1, weight=1)

    # ------------------- Validação e geração de IPs -------------------
    def validate_inputs(self):
        try:
            ip_input = self.ip_entry.get().strip()
            if '/' in ip_input:
                if not self.is_valid_cidr(ip_input):
                    messagebox.showerror("Erro", "Formato CIDR inválido. Use: IP/MÁSCARA (ex: 192.168.1.0/24)")
                    return False
                net = ipaddress.ip_network(ip_input, strict=False)
                if net.num_addresses > 256:
                    messagebox.showerror("Erro", "CIDR muito grande. Limite /24 (256 endereços).")
                    return False
            elif '-' in ip_input:
                parts = ip_input.split('-')
                if len(parts) != 2:
                    messagebox.showerror("Erro", "Formato de range inválido. Use: IP_INICIAL-IP_FINAL")
                    return False
                if '.' in parts[1]:
                    start_ip = ipaddress.ip_address(parts[0].strip())
                    end_ip = ipaddress.ip_address(parts[1].strip())
                    if start_ip > end_ip:
                        messagebox.showerror("Erro", "IP inicial deve ser menor que IP final.")
                        return False
                else:
                    ipaddress.ip_address(parts[0].strip())
            else:
                ipaddress.ip_address(ip_input)
        except ValueError:
            messagebox.showerror("Erro", "Endereço IP, range ou CIDR inválido.")
            return False

        # Porta específica valida
        sp = self.single_port.get().strip()
        if sp:
            try:
                p = int(sp)
                if not (1 <= p <= 65535):
                    messagebox.showerror("Erro", "Porta específica inválida (1-65535).")
                    return False
            except ValueError:
                messagebox.showerror("Erro", "Porta específica deve ser um número inteiro.")
                return False
        else:
            try:
                start_p = int(self.port_start.get())
                end_p = int(self.port_end.get())
                if not (1 <= start_p <= 65535) or not (1 <= end_p <= 65535):
                    messagebox.showerror("Erro", "Portas devem estar entre 1 e 65535.")
                    return False
                if start_p > end_p:
                    messagebox.showerror("Erro", "Porta inicial deve ser menor ou igual à porta final.")
                    return False
            except ValueError:
                messagebox.showerror("Erro", "Portas devem ser números inteiros.")
                return False

        return True

    def is_valid_cidr(self, cidr):
        try:
            if cidr.count('/') != 1:
                return False
            ip, mask = cidr.split('/')
            ipaddress.ip_address(ip)
            mask = int(mask)
            return 0 <= mask <= 32
        except Exception:
            return False

    def get_ip_list(self):
        ip_input = self.ip_entry.get().strip()
        out = []
        try:
            if '/' in ip_input:
                net = ipaddress.ip_network(ip_input, strict=False)
                for ip in net.hosts():
                    out.append(str(ip))
            elif '-' in ip_input:
                parts = ip_input.split('-')
                if '.' in parts[1]:
                    start_ip = ipaddress.ip_address(parts[0].strip())
                    end_ip = ipaddress.ip_address(parts[1].strip())
                    cur = start_ip
                    while cur <= end_ip:
                        out.append(str(cur))
                        cur += 1
                else:
                    out.append(parts[0].strip())
            else:
                out.append(ip_input)
        except ValueError as e:
            messagebox.showerror("Erro", f"Erro ao processar range de IPs: {e}")
            return []
        return out

    # ------------------- Scanners -------------------
    def scan_tcp_port(self, ip, port, timeout=1.5):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            res = sock.connect_ex((ip, port))
            sock.close()
            return "Aberta" if res == 0 else "Fechada"
        except socket.timeout:
            return "Filtrada"
        except socket.error as e:
            try:
                if e.errno == 113:
                    return "Inacessível"
            except Exception:
                pass
            return "Erro"
        except Exception:
            return "Erro"

    def scan_udp_port(self, ip, port, timeout=2.0):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b'', (ip, port))
            try:
                _data, _addr = sock.recvfrom(1024)
                return "Aberta"
            except socket.timeout:
                return "Aberta|Filtrada"
            except socket.error as e:
                try:
                    if e.errno == 111:
                        return "Fechada"
                except Exception:
                    pass
                return "Filtrada"
            finally:
                sock.close()
        except socket.error as e:
            try:
                if e.errno == 113:
                    return "Inacessível"
            except Exception:
                pass
            return "Erro"
        except Exception:
            return "Erro"

    # ------------------- Worker e UI updates -------------------
    def worker(self):
        while True:
            try:
                ip, port, proto = self.queue.get(timeout=0.4)
            except Empty:
                if not self.scanning and self.queue.empty():
                    break
                continue

            # Se o usuário pediu parada, libera a tarefa e sai
            if not self.scanning and self.stopped_by_user:
                self.queue.task_done()
                break

            status = self.scan_tcp_port(ip, port) if proto == "TCP" else self.scan_udp_port(ip, port)

            entry = {"ip": ip, "port": port, "status": status, "proto": proto}
            self.scan_results.append(entry)

            # Atualizar UI com segurança
            self.root.after(0, self.update_tree, entry)

            with self.lock:
                self.completed_tasks += 1
                # Atualiza progresso no thread principal
                self.root.after(0, lambda v=self.completed_tasks: self.progress.config(value=v))

            self.queue.task_done()

    def update_tree(self, entry):
        ip = entry["ip"]
        port = entry["port"]
        status = entry["status"]
        proto = entry["proto"]

        f = self.filter_var.get()
        show = (
            f == "Todos" or
            status == f or
            (f == "Aberta" and status in ("Aberta", "Aberta|Filtrada")) or
            (f == "Filtrada" and status in ("Filtrada", "Aberta|Filtrada"))
        )
        if not show:
            # atualiza contadores mesmo que não mostre
            self.update_result_count()
            return

        self.tree.insert('', 'end', values=(ip, f"{port}/{proto}", status))
        self.update_result_count()

    def update_result_count(self):
        total = len(self.scan_results)
        abertas = sum(1 for r in self.scan_results if r["status"] == "Aberta")
        fechadas = sum(1 for r in self.scan_results if r["status"] == "Fechada")
        filtradas = sum(1 for r in self.scan_results if r["status"] == "Filtrada")
        ambiguas = sum(1 for r in self.scan_results if r["status"] == "Aberta|Filtrada")
        inacessiveis = sum(1 for r in self.scan_results if r["status"] == "Inacessível")
        erros = sum(1 for r in self.scan_results if r["status"] == "Erro")

        self.result_count.config(text=f"Total: {total} | Abertas: {abertas} | Fechadas: {fechadas} | Filtradas: {filtradas} | Ambíguas: {ambiguas} | Inacessíveis: {inacessiveis} | Erros: {erros}")

    def apply_filter(self, event=None):
        # limpa tree e aplica filtro atual
        for it in self.tree.get_children():
            self.tree.delete(it)

        f = self.filter_var.get()
        for r in self.scan_results:
            status = r["status"]
            proto = r["proto"]
            show = (
                f == "Todos" or
                status == f or
                (f == "Aberta" and status in ("Aberta", "Aberta|Filtrada")) or
                (f == "Filtrada" and status in ("Filtrada", "Aberta|Filtrada"))
            )
            if show:
                self.tree.insert('', 'end', values=(r["ip"], f"{r["port"]}/{proto}", status))

    # ------------------- Controle de execução -------------------
    def start_scan(self):
        if not self.validate_inputs():
            return

        # Reset UI/estado
        for it in self.tree.get_children():
            self.tree.delete(it)
        self.scan_results = []
        self.total_tasks = 0
        self.completed_tasks = 0
        self.stopped_by_user = False

        ip_list = self.get_ip_list()
        if not ip_list:
            return

        # determina portas
        ports = []
        sp = self.single_port.get().strip()
        if sp:
            ports = [int(sp)]
        else:
            start_p = int(self.port_start.get())
            end_p = int(self.port_end.get())
            ports = list(range(start_p, end_p + 1))

        proto_now = self.scan_type.get()
        self.total_tasks = len(ip_list) * len(ports)

        # configura barra de progresso
        self.progress.config(mode='determinate', maximum=self.total_tasks, value=0)

        # preencher fila com protocolo fixo no momento do start
        for ip in ip_list:
            for p in ports:
                self.queue.put((ip, p, proto_now))

        # interface
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        # threads
        num_threads = max(1, min(100, self.total_tasks))
        self.threads = []
        for _ in range(num_threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            self.threads.append(t)

        # agendar verificação
        self.root.after(200, self.check_threads)

    def check_threads(self):
        alive = any(t.is_alive() for t in self.threads)
        done_by_tasks = (self.completed_tasks >= self.total_tasks) and self.queue.empty()

        if (not alive and self.queue.empty()) or done_by_tasks or (not self.scanning and self.stopped_by_user):
            # finaliza
            self.scanning = False
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            try:
                self.progress.stop()
            except Exception:
                pass

            if self.stopped_by_user:
                messagebox.showinfo("Info", "Escaneamento interrompido pelo usuário.")
            else:
                messagebox.showinfo("Info", "Escaneamento concluído!")
            return

        # continua checando
        self.root.after(200, self.check_threads)

    def stop_scan(self):
        # sinaliza parada e drena a fila sem bloquear
        self.stopped_by_user = True
        self.scanning = False
        try:
            while True:
                self.queue.get_nowait()
                self.queue.task_done()
        except Empty:
            pass
        # desabilita botao de stop e habilita start
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    # ------------------- Export -------------------
    def _get_export_list(self, filtered_only=False):
        if not filtered_only or self.filter_var.get() == "Todos":
            return list(self.scan_results)
        f = self.filter_var.get()
        out = []
        for r in self.scan_results:
            st = r["status"]
            if st == f or (f == "Aberta" and st in ("Aberta", "Aberta|Filtrada")) or (f == "Filtrada" and st in ("Filtrada", "Aberta|Filtrada")):
                out.append(r)
        return out

    def export_csv(self):
        if not self.scan_results:
            messagebox.showwarning("Aviso", "Nenhum resultado para exportar.")
            return
        filtered_only = messagebox.askyesno("Exportar", "Exportar apenas os resultados filtrados? (Aplicar filtro atual)")
        data = self._get_export_list(filtered_only=filtered_only)
        file = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV files', '*.csv')])
        if not file:
            return
        try:
            with open(file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['ip', 'port/proto', 'status'])
                for r in data:
                    writer.writerow([r['ip'], f"{r['port']}/{r['proto']}", r['status']])
            messagebox.showinfo("Sucesso", f"Resultados exportados para {file}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao exportar CSV: {e}")

    def export_json(self):
        if not self.scan_results:
            messagebox.showwarning("Aviso", "Nenhum resultado para exportar.")
            return
        filtered_only = messagebox.askyesno("Exportar", "Exportar apenas os resultados filtrados? (Aplicar filtro atual)")
        data = self._get_export_list(filtered_only=filtered_only)
        file = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON files', '*.json')])
        if not file:
            return
        try:
            with open(file, 'w', encoding='utf-8') as f:
                out = [{
                    'ip': r['ip'],
                    'port/proto': f"{r['port']}/{r['proto']}",
                    'status': r['status']
                } for r in data]
                json.dump(out, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("Sucesso", f"Resultados exportados para {file}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao exportar JSON: {e}")


if __name__ == '__main__':
    root = tk.Tk()
    app = PortScanner(root)
    root.mainloop()
