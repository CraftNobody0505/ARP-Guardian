# --- START OF FILE arp2.py ---

import ctypes
import sys
import os
import platform  # 确保 platform 已导入

# 管理员权限提升逻辑 - 应该放在脚本的最顶部
# 在导入其他可能需要管理员权限的库（如 wmi 或 scapy 的原始套接字功能）之前
if platform.system() == "Windows":  # 确保只在Windows上运行
    try:
        is_admin_flag = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin_flag = False

    if not is_admin_flag:
        print("当前不是管理员权限，尝试提权...")
        try:
            # 请求UAC提权
            script_path = os.path.abspath(sys.argv[0])
            params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])  # 正确处理带空格的参数

            # 调试信息
            print(f"Python路径: {sys.executable}")
            print(f"脚本路径: {script_path}")
            print(f"参数: {params}")

            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, f'"{script_path}" {params}', None, 1)  # 将脚本路径也用引号括起来

            if ret <= 32:  # 返回值≤32表示失败
                error_msg = f"提权失败 (错误代码: {ret}). 请以管理员身份运行此脚本。"
                print(error_msg)
                # 如果控制台可用且已打印错误，可以考虑不显示 MessageBox
                ctypes.windll.user32.MessageBoxW(0, error_msg, "错误", 0x10)
            sys.exit()  # 提权尝试后退出，新进程将会运行（如果成功）
        except Exception as e:
            print(f"提权过程中发生错误: {e}")
            sys.exit()
    # else: # 如果已经是管理员或提权成功
    # print("已获得管理员权限") # 新的提权进程会执行到这里，可以取消注释用于调试

# --- 其他导入放在管理员权限检查之后 ---
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
# import os # 已在顶部导入
# import platform # 已在顶部导入
import subprocess
from collections import defaultdict
from datetime import datetime
import re
import logging
import wmi  # Windows管理接口库

# 尝试导入Scapy库
try:
    from scapy.all import sniff, ARP, Ether, conf, get_if_list, get_if_hwaddr, get_if_addr, sendp, getmacbyip

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("警告: Scapy库未安装或导入失败，部分核心功能将受限。")

# 配置日志记录
logging.basicConfig(
    filename='arp_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


# MAC地址规范化函数
def normalize_mac_address(mac_address):
    if not mac_address:
        return ""
    # 移除非法字符，并转换为小写
    clean_mac = re.sub(r'[^0-9a-fA-F]', '', str(mac_address)).lower()
    if len(clean_mac) == 12:
        # 格式化为 xx:xx:xx:xx:xx:xx
        return ":".join(clean_mac[i:i + 2] for i in range(0, 12, 2))
    # 如果不是标准12位MAC（例如 "incomplete"），返回原始小写形式或特定标记
    if str(mac_address).lower() == "incomplete":
        return "incomplete"
    return str(mac_address).lower()


class WindowsARPSecurityMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows局域网ARP安全监控系统 v1.1")  # 版本更新
        self.root.geometry("900x700")
        self.root.resizable(True, True)

        # 系统状态变量
        self.monitoring = False
        self.defense_active = False
        self.interface = ""  # WMI 接口描述
        self.scapy_interface_name = None  # Scapy 使用的接口名
        self.my_ip = ""
        self.my_mac = ""
        self.gateway_ip = ""
        self.gateway_mac = ""  # 网关的MAC地址，会动态获取和验证
        self.packet_count = 0

        # 存储设备信息
        self.devices = {}  # IP -> {"mac": "xx:xx..", "last_seen": timestamp, "status": "在线/离线"}
        self.traffic_stats = defaultdict(lambda: {"sent": 0, "received": 0})
        self.arp_table = {}  # 从系统'arp -a'获取的IP->MAC映射，作为信任来源之一
        self.alerts = []

        # 创建主框架
        self.create_widgets()

        # 获取网络接口
        self.get_network_interfaces()

        # 更新UI (初始时可能不需要立即调用，等待接口选择)
        # self.update_ui() # 移到接口选择后或定期调用
        self.root.after(5000, self.periodic_updates)  # 启动定期更新

    # ... (create_widgets, create_dashboard_tab, create_monitor_tab, etc. 保持不变)
    def create_widgets(self):
        # 创建标签页
        self.tab_control = ttk.Notebook(self.root)

        # 创建标签页
        self.dashboard_tab = ttk.Frame(self.tab_control)
        self.monitor_tab = ttk.Frame(self.tab_control)
        self.defense_tab = ttk.Frame(self.tab_control)
        self.alerts_tab = ttk.Frame(self.tab_control)

        self.tab_control.add(self.dashboard_tab, text='控制面板')
        self.tab_control.add(self.monitor_tab, text='网络监控')
        self.tab_control.add(self.defense_tab, text='ARP防御')
        self.tab_control.add(self.alerts_tab, text='安全警报')

        self.tab_control.pack(expand=1, fill="both", padx=10, pady=10)

        # 控制面板标签页
        self.create_dashboard_tab()

        # 网络监控标签页
        self.create_monitor_tab()

        # ARP防御标签页
        self.create_defense_tab()

        # 安全警报标签页
        self.create_alerts_tab()

        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        self.status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Scapy状态提示
        if not SCAPY_AVAILABLE:
            scapy_status_text = "警告: Scapy库未安装或加载失败，ARP嗅探和主动防御功能将无法使用。请尝试以管理员身份运行 'pip install scapy'。"
            scapy_status_label = tk.Label(self.root, text=scapy_status_text, fg="red", bg="yellow",
                                          wraplength=self.root.winfo_width())
            scapy_status_label.pack(side=tk.BOTTOM, fill=tk.X)
            self.root.bind('<Configure>', lambda e: scapy_status_label.config(wraplength=e.width - 20))

    def create_dashboard_tab(self):
        # 接口选择
        interface_frame = tk.LabelFrame(self.dashboard_tab, text="网络接口设置")
        interface_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(interface_frame, text="选择网络接口:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(interface_frame, textvariable=self.interface_var, width=50,
                                               state="readonly")
        self.interface_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        self.interface_dropdown.bind("<<ComboboxSelected>>", self.interface_selected)

        # 本机信息
        self.my_info_var = tk.StringVar()
        self.my_info_var.set("本机IP: \n本机MAC: ")
        tk.Label(interface_frame, textvariable=self.my_info_var, justify=tk.LEFT).grid(row=1, column=0, columnspan=2,
                                                                                       padx=5, pady=5, sticky=tk.W)

        # 网关信息
        self.gateway_info_var = tk.StringVar()
        self.gateway_info_var.set("网关IP: \n网关MAC: ")
        tk.Label(interface_frame, textvariable=self.gateway_info_var, justify=tk.LEFT).grid(row=2, column=0,
                                                                                            columnspan=2, padx=5,
                                                                                            pady=5, sticky=tk.W)

        # 控制按钮
        control_frame = tk.Frame(self.dashboard_tab)
        control_frame.pack(fill=tk.X, padx=10, pady=10)

        self.start_btn = tk.Button(control_frame, text="启动监控", command=self.start_monitoring, width=15, height=2)
        self.start_btn.pack(side=tk.LEFT, padx=10)

        self.stop_btn = tk.Button(control_frame, text="停止监控", command=self.stop_monitoring, state=tk.DISABLED,
                                  width=15, height=2)
        self.stop_btn.pack(side=tk.LEFT, padx=10)

        self.defense_btn = tk.Button(control_frame, text="启用ARP防御", command=self.toggle_defense, width=15, height=2)
        self.defense_btn.pack(side=tk.LEFT, padx=10)

        self.refresh_btn = tk.Button(control_frame, text="刷新接口", command=self.refresh_interfaces, width=15,
                                     height=2)
        self.refresh_btn.pack(side=tk.LEFT, padx=10)

        # 系统状态
        status_frame = tk.LabelFrame(self.dashboard_tab, text="系统状态")
        status_frame.pack(fill=tk.X, padx=10, pady=5)

        self.monitor_status_var = tk.StringVar()
        self.monitor_status_var.set("监控状态: 未运行")
        tk.Label(status_frame, textvariable=self.monitor_status_var, font=("Arial", 10)).pack(anchor=tk.W, padx=5,
                                                                                              pady=5)

        self.defense_status_var = tk.StringVar()
        self.defense_status_var.set("防御状态: 未启用")
        tk.Label(status_frame, textvariable=self.defense_status_var, font=("Arial", 10)).pack(anchor=tk.W, padx=5,
                                                                                              pady=5)

        self.packet_count_var = tk.StringVar()
        self.packet_count_var.set("已处理ARP包: 0")  # 更明确是ARP包
        tk.Label(status_frame, textvariable=self.packet_count_var, font=("Arial", 10)).pack(anchor=tk.W, padx=5, pady=5)

        self.scapy_status_var = tk.StringVar()
        scapy_status = "Scapy状态: " + ("可用" if SCAPY_AVAILABLE else "不可用或加载失败")
        self.scapy_status_var.set(scapy_status)
        tk.Label(status_frame, textvariable=self.scapy_status_var, font=("Arial", 10)).pack(anchor=tk.W, padx=5, pady=5)

    def create_monitor_tab(self):
        # 设备列表
        device_frame = tk.LabelFrame(self.monitor_tab, text="网络设备列表 (基于捕获的ARP包)")
        device_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        columns = ("ip", "mac", "status", "last_seen")
        self.device_tree = ttk.Treeview(device_frame, columns=columns, show="headings")

        self.device_tree.heading("ip", text="IP地址")
        self.device_tree.heading("mac", text="MAC地址 (最后观察到)")
        self.device_tree.heading("status", text="状态")
        self.device_tree.heading("last_seen", text="最后活跃")

        self.device_tree.column("ip", width=150, anchor=tk.W)
        self.device_tree.column("mac", width=180, anchor=tk.W)
        self.device_tree.column("status", width=80, anchor=tk.CENTER)
        self.device_tree.column("last_seen", width=150, anchor=tk.CENTER)

        scrollbar_y = ttk.Scrollbar(device_frame, orient="vertical", command=self.device_tree.yview)
        scrollbar_x = ttk.Scrollbar(device_frame, orient="horizontal", command=self.device_tree.xview)
        self.device_tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 流量统计 (当前是模拟，实际需要pcap或winpcap等更底层库支持精确统计)
        traffic_frame = tk.LabelFrame(self.monitor_tab, text="流量统计 (模拟数据)")
        traffic_frame.pack(fill=tk.X, padx=10, pady=5)

        self.traffic_text = scrolledtext.ScrolledText(traffic_frame, height=8, wrap=tk.WORD)
        self.traffic_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.traffic_text.config(state=tk.DISABLED)

    def create_defense_tab(self):
        # ARP绑定设置
        binding_frame = tk.LabelFrame(self.defense_tab, text="ARP静态绑定设置 (需要管理员权限)")
        binding_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(binding_frame, text="IP地址:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.bind_ip_var = tk.StringVar()
        tk.Entry(binding_frame, textvariable=self.bind_ip_var, width=15).grid(row=0, column=1, padx=5, pady=5)

        tk.Label(binding_frame, text="MAC地址:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.bind_mac_var = tk.StringVar()
        tk.Entry(binding_frame, textvariable=self.bind_mac_var, width=17).grid(row=0, column=3, padx=5, pady=5)

        bind_btn = tk.Button(binding_frame, text="添加/更新绑定", command=self.add_arp_binding)  # 更改文本
        bind_btn.grid(row=0, column=4, padx=10, pady=5)

        # 绑定列表
        bind_list_frame = tk.LabelFrame(self.defense_tab, text="当前静态ARP绑定 (通过 'arp -s' 命令设置)")
        bind_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        columns = ("bind_ip", "bind_mac")
        self.bind_tree = ttk.Treeview(bind_list_frame, columns=columns, show="headings")

        self.bind_tree.heading("bind_ip", text="IP地址")
        self.bind_tree.heading("bind_mac", text="MAC地址 (规范格式)")

        self.bind_tree.column("bind_ip", width=150, anchor=tk.W)
        self.bind_tree.column("bind_mac", width=180, anchor=tk.W)

        scrollbar_y_bind = ttk.Scrollbar(bind_list_frame, orient="vertical", command=self.bind_tree.yview)
        scrollbar_x_bind = ttk.Scrollbar(bind_list_frame, orient="horizontal", command=self.bind_tree.xview)
        self.bind_tree.configure(yscrollcommand=scrollbar_y_bind.set, xscrollcommand=scrollbar_x_bind.set)

        scrollbar_y_bind.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbar_x_bind.pack(side=tk.BOTTOM, fill=tk.X)
        self.bind_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 绑定列表右键菜单
        self.bind_tree_menu = tk.Menu(self.bind_tree, tearoff=0)
        self.bind_tree_menu.add_command(label="删除选定绑定", command=self.delete_selected_binding)
        self.bind_tree.bind("<Button-3>", self.show_bind_tree_menu)

        # 防御操作按钮
        defense_btn_frame = tk.Frame(self.defense_tab)
        defense_btn_frame.pack(fill=tk.X, padx=10, pady=5)

        self.bind_gateway_btn = tk.Button(defense_btn_frame, text="绑定网关", command=self.bind_gateway_static)
        self.bind_gateway_btn.pack(side=tk.LEFT, padx=5)

        # 本机绑定通常不需要，因为本机 MAC 一般不会被篡改到 ARP 表中，但可以保留作为选项
        # self.bind_local_btn = tk.Button(defense_btn_frame, text="绑定本机", command=self.bind_local_static)
        # self.bind_local_btn.pack(side=tk.LEFT, padx=5)

        self.load_static_bindings_btn = tk.Button(defense_btn_frame, text="加载系统静态绑定",
                                                  command=self.load_static_arp_entries_from_system)
        self.load_static_bindings_btn.pack(side=tk.LEFT, padx=5)

        self.clear_bindings_btn = tk.Button(defense_btn_frame, text="清除所有显示绑定",
                                            command=self.clear_displayed_bindings)  # 更改文本和功能
        self.clear_bindings_btn.pack(side=tk.LEFT, padx=5)

        # 防御日志
        log_frame = tk.LabelFrame(self.defense_tab, text="防御及操作日志")
        log_frame.pack(fill=tk.X, padx=10, pady=5)

        self.defense_log = scrolledtext.ScrolledText(log_frame, height=6, wrap=tk.WORD)
        self.defense_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.defense_log.config(state=tk.DISABLED)

    def create_alerts_tab(self):
        # 警报列表
        alert_frame = tk.LabelFrame(self.alerts_tab, text="安全警报")
        alert_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        columns = ("time", "type", "source_ip", "details")  # source -> source_ip
        self.alert_tree = ttk.Treeview(alert_frame, columns=columns, show="headings")

        self.alert_tree.heading("time", text="时间")
        self.alert_tree.heading("type", text="类型")
        self.alert_tree.heading("source_ip", text="源IP")
        self.alert_tree.heading("details", text="详细信息")

        self.alert_tree.column("time", width=100, anchor=tk.CENTER)
        self.alert_tree.column("type", width=120, anchor=tk.W)
        self.alert_tree.column("source_ip", width=120, anchor=tk.W)
        self.alert_tree.column("details", width=430, anchor=tk.W)  # 增加宽度

        scrollbar_y_alert = ttk.Scrollbar(alert_frame, orient="vertical", command=self.alert_tree.yview)
        scrollbar_x_alert = ttk.Scrollbar(alert_frame, orient="horizontal", command=self.alert_tree.xview)
        self.alert_tree.configure(yscrollcommand=scrollbar_y_alert.set, xscrollcommand=scrollbar_x_alert.set)

        scrollbar_y_alert.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbar_x_alert.pack(side=tk.BOTTOM, fill=tk.X)
        self.alert_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 警报操作按钮
        alert_btn_frame = tk.Frame(self.alerts_tab)
        alert_btn_frame.pack(fill=tk.X, padx=10, pady=5)

        self.clear_alerts_btn = tk.Button(alert_btn_frame, text="清除所有警报", command=self.clear_alerts)
        self.clear_alerts_btn.pack(side=tk.LEFT, padx=5)

        # 警报详情
        detail_frame = tk.LabelFrame(self.alerts_tab, text="警报详情")
        detail_frame.pack(fill=tk.X, padx=10, pady=5)

        self.alert_detail = scrolledtext.ScrolledText(detail_frame, height=6, wrap=tk.WORD)
        self.alert_detail.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.alert_detail.config(state=tk.DISABLED)

        # 绑定选择事件
        self.alert_tree.bind("<<TreeviewSelect>>", self.show_alert_details)

    def get_network_interfaces(self):
        """获取可用的网络接口 (WMI)"""
        interfaces_map = {}  # 存储描述 -> WMI对象，或更详细信息
        display_names = []

        try:
            c = wmi.WMI()
            # 优先选择具有 IP 地址和物理适配器的接口
            for iface_config in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                adapter = iface_config.associators(wmi_result_class="Win32_NetworkAdapter")[0]
                if adapter.Description and adapter.MACAddress:  # 确保有描述和MAC
                    # 使用更详细的名称，如果可用
                    name_to_display = f"{adapter.Description} ({iface_config.IPAddress[0] if iface_config.IPAddress else 'No IP'})"
                    interfaces_map[name_to_display] = {
                        "description": adapter.Description,
                        "ip": iface_config.IPAddress[0] if iface_config.IPAddress else None,
                        "mac": normalize_mac_address(adapter.MACAddress),
                        "wmi_config": iface_config,  # 存储原始对象以备后用
                        "wmi_adapter": adapter
                    }
                    display_names.append(name_to_display)

            if not display_names:  # 如果没有IPEnabled的，退而求其次
                for adapter in c.Win32_NetworkAdapter():
                    if adapter.Description and adapter.MACAddress and adapter.NetConnectionID:
                        name_to_display = f"{adapter.Description} (未配置IP)"
                        if name_to_display not in interfaces_map:  # 避免重复
                            interfaces_map[name_to_display] = {
                                "description": adapter.Description,
                                "ip": None,
                                "mac": normalize_mac_address(adapter.MACAddress),
                                "wmi_adapter": adapter
                            }
                            display_names.append(name_to_display)

        except Exception as e:
            logging.error(f"WMI 获取网络接口失败: {str(e)}")
            messagebox.showerror("错误", f"获取网络接口失败 (WMI): {str(e)}\n请确保WMI服务正在运行。")
            display_names = ["未知接口"]

        self.wmi_interfaces_map = interfaces_map  # 保存映射
        self.interface_dropdown['values'] = display_names
        if display_names and display_names[0] != "未知接口":
            self.interface_var.set(display_names[0])
            self.interface_selected()
        else:
            self.my_info_var.set("本机IP: 未选择接口\n本机MAC: 未选择接口")
            self.gateway_info_var.set("网关IP: 未选择接口\n网关MAC: 未选择接口")

    def refresh_interfaces(self):
        """刷新网络接口列表"""
        self.get_network_interfaces()
        self.status_var.set("网络接口已刷新")
        logging.info("网络接口已刷新")

    def interface_selected(self, event=None):
        """当选择网络接口时更新本机信息"""
        selected_display_name = self.interface_var.get()
        if not selected_display_name or selected_display_name == "未知接口":
            return

        iface_details = self.wmi_interfaces_map.get(selected_display_name)
        if not iface_details:
            logging.error(f"无法从映射中找到接口详情: {selected_display_name}")
            return

        self.interface = iface_details["description"]  # WMI 描述用于日志或内部逻辑
        self.my_ip = iface_details["ip"] if iface_details["ip"] else self.get_interface_ip(self.interface)  # 再次确认
        self.my_mac = iface_details["mac"] if iface_details["mac"] else self.get_interface_mac(self.interface)

        # 确定 Scapy 使用的接口名
        self.scapy_interface_name = self.determine_scapy_interface_name()
        if self.scapy_interface_name:
            conf.iface = self.scapy_interface_name  # 设置 Scapy 全局接口
            logging.info(f"Scapy 接口已设置为: {conf.iface}")
        else:
            conf.iface = None  # 清除旧的 Scapy 接口设置
            logging.warning(f"未能为 {self.interface} 确定匹配的 Scapy 接口名。嗅探和主动防御可能失败。")
            if SCAPY_AVAILABLE:  # 仅当Scapy本身可用时才提示
                messagebox.showwarning("Scapy接口警告",
                                       f"未能为选定接口 '{self.interface}' 找到匹配的Scapy接口。\n网络嗅探和主动ARP防御功能可能无法正常工作。")

        # 获取网关信息 (需要基于当前选定接口)
        self.gateway_ip = self.get_gateway_ip_for_interface(iface_details.get("wmi_config"))

        # 尝试通过 ARP 或 Scapy 获取网关 MAC (如果网关IP已知)
        if self.gateway_ip:
            self.gateway_mac = self.get_mac_address_for_ip(self.gateway_ip)
        else:
            self.gateway_mac = ""

        self.my_info_var.set(f"本机IP: {self.my_ip or 'N/A'}\n本机MAC: {self.my_mac or 'N/A'}")
        self.gateway_info_var.set(f"网关IP: {self.gateway_ip or 'N/A'}\n网关MAC: {self.gateway_mac or 'N/A'}")

        self.update_arp_table_from_system()  # 更新系统ARP表显示
        self.load_static_arp_entries_from_system()  # 加载静态绑定到UI

        logging.info(
            f"接口已选择: {self.interface}, IP: {self.my_ip}, MAC: {self.my_mac}, 网关: {self.gateway_ip}, 网关MAC: {self.gateway_mac}, Scapy接口: {self.scapy_interface_name}")
        self.status_var.set(f"当前接口: {self.interface.split('(')[0].strip()}")

    def get_interface_ip(self, interface_description):
        """(辅助) 获取指定WMI接口描述的IP地址"""
        try:
            c = wmi.WMI()
            # Win32_NetworkAdapterConfiguration 的 Description 可能与 Win32_NetworkAdapter 不同
            # 通常需要通过关联来查找
            for adapter in c.Win32_NetworkAdapter(Description=interface_description):
                for config in adapter.associators(wmi_result_class="Win32_NetworkAdapterConfiguration"):
                    if config.IPEnabled and config.IPAddress:
                        return config.IPAddress[0]
            return ""
        except Exception as e:
            logging.error(f"WMI 获取接口 '{interface_description}' IP失败: {str(e)}")
            return ""

    def get_interface_mac(self, interface_description):
        """(辅助) 获取指定WMI接口描述的MAC地址"""
        try:
            c = wmi.WMI()
            for adapter in c.Win32_NetworkAdapter(Description=interface_description):
                if adapter.MACAddress:
                    return normalize_mac_address(adapter.MACAddress)
            return ""
        except Exception as e:
            logging.error(f"WMI 获取接口 '{interface_description}' MAC失败: {str(e)}")
            return ""

    def get_gateway_ip_for_interface(self, iface_config_wmi=None):
        """获取指定网络接口配置的默认网关IP"""
        if iface_config_wmi:  # 如果传入了WMI的NetworkAdapterConfiguration对象
            if iface_config_wmi.DefaultIPGateway:
                return iface_config_wmi.DefaultIPGateway[0]

        # Fallback: 如果没有传入wmi_config，尝试通过 WMI 描述查找
        # 但这可能不准确，因为一个描述可能对应多个配置（理论上）
        # 或者使用全局路由表，但这不保证是当前活跃接口的网关
        if self.interface:  # self.interface 是WMI接口描述
            try:
                c = wmi.WMI()
                for config in c.Win32_NetworkAdapterConfiguration(Description=self.interface, IPEnabled=True):
                    if config.DefaultIPGateway:
                        return config.DefaultIPGateway[0]
            except Exception as e:
                logging.error(f"通过WMI描述 '{self.interface}' 获取网关IP失败: {e}")

        # 终极 Fallback: 使用 route print (可能不精确对应选定接口)
        try:
            result = subprocess.run("route print -4 0.0.0.0", shell=True, capture_output=True, text=True, check=True)
            # Example output line for default route:
            #   0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.101     25
            # We need the gateway address (third IP usually)
            for line in result.stdout.splitlines():
                if line.strip().startswith("0.0.0.0"):
                    parts = line.strip().split()
                    if len(parts) >= 3:  # gateway is often parts[2]
                        # Validate it's an IP
                        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parts[2]):
                            return parts[2]
            return ""
        except subprocess.CalledProcessError as e:
            logging.error(f"执行 'route print' 获取网关IP失败: {e}")
            return ""
        except Exception as e:  # 其他未知错误
            logging.error(f"获取网关IP时发生未知错误: {e}")
            return ""

    def get_mac_address_for_ip(self, ip_address):
        """尝试通过多种方式获取IP对应的MAC地址，优先Scapy"""
        if not ip_address:
            return ""

        # 优先使用 Scapy (如果可用且接口已配置)
        if SCAPY_AVAILABLE and conf.iface and ip_address != self.my_ip:  # 不对自己用getmacbyip
            try:
                # Scapy 的 getmacbyip 会主动发送 ARP 请求
                logging.debug(f"尝试使用 Scapy getmacbyip 获取 {ip_address} 的 MAC (接口: {conf.iface})")
                mac = getmacbyip(ip_address)  # conf.iface 应该已经设置
                if mac:
                    norm_mac = normalize_mac_address(mac)
                    logging.info(f"Scapy getmacbyip 成功: {ip_address} -> {norm_mac}")
                    return norm_mac
            except Exception as e:
                logging.warning(f"Scapy getmacbyip 获取 {ip_address} MAC 失败: {e}")

        # 其次，检查系统ARP缓存
        self.update_arp_table_from_system()  # 确保arp_table是新的
        if ip_address in self.arp_table:
            mac_from_cache = self.arp_table[ip_address]
            logging.info(f"从系统ARP缓存找到 {ip_address} -> {mac_from_cache}")
            return mac_from_cache  # arp_table中的MAC已经是规范化的

        # Fallback: 使用 'arp -a <ip>' 命令 (这也会查缓存，但可以作为独立尝试)
        try:
            logging.debug(f"尝试使用 'arp -a {ip_address}' 获取 MAC")
            # 在Windows上，arp -a <ip> 可能不会主动发送ARP，主要查缓存
            # 为了触发ARP解析，可以先ping一下，但这会增加复杂性和延迟
            # subprocess.run(f"ping -n 1 -w 200 {ip_address}", shell=True, capture_output=True) # 可选的ping

            result = subprocess.run(f"arp -a {ip_address}", shell=True, capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line_lower = line.lower()
                    if ip_address in line_lower:
                        # 正则表达式匹配 IP 和 MAC (xx-xx-xx-xx-xx-xx 或 xx:xx:xx:xx:xx:xx)
                        match = re.search(
                            r"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)\s+([0-9a-f]{2}[-:]?[0-9a-f]{2}[-:]?[0-9a-f]{2}[-:]?[0-9a-f]{2}[-:]?[0-9a-f]{2}[-:]?[0-9a-f]{2})\s+",
                            line_lower, re.IGNORECASE)
                        if match and match.group(1) == ip_address:
                            mac = normalize_mac_address(match.group(2))
                            if mac and mac != "incomplete":
                                logging.info(f"'arp -a {ip_address}' 成功: {ip_address} -> {mac}")
                                return mac
            else:
                logging.warning(f"'arp -a {ip_address}' 命令失败或未找到条目. Stderr: {result.stderr}")

        except subprocess.TimeoutExpired:
            logging.warning(f"'arp -a {ip_address}' 命令超时.")
        except Exception as e:
            logging.error(f"执行 'arp -a {ip_address}' 获取MAC失败: {str(e)}")

        logging.warning(f"未能获取IP地址 {ip_address} 的MAC地址。")
        return ""

    def update_arp_table_from_system(self):
        """更新 self.arp_table 从系统 'arp -a' 命令 (动态和静态条目)"""
        temp_arp_table = {}
        try:
            # arp -a 会列出动态和静态条目
            result = subprocess.run("arp -a", shell=True, capture_output=True, text=True, check=True)
            # Windows 'arp -a' 输出格式示例:
            # Interface: 192.168.1.101 --- 0xb
            #   Internet Address      Physical Address      Type
            #   192.168.1.1           00-11-22-33-44-55     dynamic
            #   192.168.1.254         aa-bb-cc-dd-ee-ff     static
            current_interface_ip_prefix = None
            if self.my_ip:  # 尝试只解析与当前接口相关的ARP条目
                # 获取当前接口IP的前三段，例如 "192.168.1."
                ip_parts = self.my_ip.split('.')
                if len(ip_parts) == 4:
                    current_interface_ip_prefix = ".".join(ip_parts[:3]) + "."

            parsing_interface_block = False
            for line in result.stdout.splitlines():
                line_strip = line.strip()
                if line_strip.lower().startswith("interface:"):
                    # 检查此接口块是否与我们当前选择的接口相关
                    if self.my_ip and self.my_ip in line_strip:
                        parsing_interface_block = True
                    elif not self.my_ip:  # 如果没有选定接口的IP，则解析所有
                        parsing_interface_block = True
                    else:
                        parsing_interface_block = False
                    continue

                if parsing_interface_block or not self.my_ip:  # 如果在相关块内，或不过滤接口
                    # 正则表达式匹配IP, MAC和类型
                    match = re.match(
                        r"^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2})\s+(dynamic|static)\s*$",
                        line_strip.lower())
                    if match:
                        ip = match.group(1)
                        mac = normalize_mac_address(match.group(2))
                        # type = match.group(3) # 'dynamic' or 'static'
                        if mac and mac != "incomplete":
                            # 如果设置了 current_interface_ip_prefix，则只添加相同网段的
                            if current_interface_ip_prefix and not ip.startswith(current_interface_ip_prefix):
                                continue
                            temp_arp_table[ip] = mac

            # 比较新旧ARP表，记录变化
            added_ips = temp_arp_table.keys() - self.arp_table.keys()
            removed_ips = self.arp_table.keys() - temp_arp_table.keys()
            changed_ips = {
                ip: (self.arp_table[ip], temp_arp_table[ip])
                for ip in self.arp_table.keys() & temp_arp_table.keys()
                if self.arp_table[ip] != temp_arp_table[ip]
            }

            if added_ips: logging.info(f"系统ARP表新增: {added_ips}")
            if removed_ips: logging.info(f"系统ARP表移除: {removed_ips}")
            if changed_ips: logging.warning(f"系统ARP表MAC地址变更: {changed_ips}")  # MAC变更可能是欺骗信号

            self.arp_table = temp_arp_table
            # self.log_defense("系统ARP缓存表已更新。") # 日志过于频繁，改为debug
            logging.debug(f"系统ARP缓存表已更新，包含 {len(self.arp_table)} 条目。")

        except subprocess.CalledProcessError as e:
            logging.error(f"更新系统ARP表失败 (arp -a): {e.stderr or e}")
            # self.log_defense(f"错误: 更新系统ARP表失败: {e}")
        except Exception as e:
            logging.error(f"更新系统ARP表时发生未知错误: {str(e)}")

    def load_static_arp_entries_from_system(self):
        """从系统加载静态ARP条目到UI的静态绑定列表"""
        self.update_arp_table_from_system()  # 确保self.arp_table最新

        # 清空当前显示的绑定树（不是清除系统中的）
        for item in self.bind_tree.get_children():
            self.bind_tree.delete(item)

        static_bindings_found = 0
        try:
            result = subprocess.run("arp -a", shell=True, capture_output=True, text=True, check=True)
            current_interface_block = False
            for line in result.stdout.splitlines():
                line_strip = line.strip()
                if line_strip.lower().startswith("interface:"):
                    current_interface_block = self.my_ip and self.my_ip in line_strip.lower()
                    continue

                if (self.my_ip and current_interface_block) or (not self.my_ip):  # 仅处理当前接口或所有接口的静态条目
                    match = re.match(
                        r"^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2})\s+static\s*$",
                        line_strip.lower())
                    if match:
                        ip = match.group(1)
                        mac = normalize_mac_address(match.group(2))
                        if mac and mac != "incomplete":
                            # 避免重复添加 (虽然上面清空了，但以防万一)
                            is_duplicate = False
                            for row_id in self.bind_tree.get_children():
                                if self.bind_tree.item(row_id)['values'][0] == ip:
                                    is_duplicate = True
                                    break
                            if not is_duplicate:
                                self.bind_tree.insert("", "end", values=(ip, mac))
                                static_bindings_found += 1

            msg = f"已从系统加载 {static_bindings_found} 条静态ARP绑定到显示列表。"
            self.log_defense(msg)
            logging.info(msg)
            self.status_var.set(msg)

        except subprocess.CalledProcessError as e:
            logging.error(f"加载系统静态ARP条目失败: {e.stderr or e}")
            self.log_defense(f"错误: 加载系统静态ARP条目失败: {e}")
        except Exception as e:
            logging.error(f"加载系统静态ARP条目时发生未知错误: {str(e)}")

    def start_monitoring(self):
        if not self.interface:
            messagebox.showerror("错误", "请先选择一个网络接口。")
            return

        if not SCAPY_AVAILABLE:
            messagebox.showerror("错误", "Scapy库未安装或加载失败，无法进行网络监控。")
            return

        if not self.scapy_interface_name:
            messagebox.showerror("错误",
                                 f"未能确定 '{self.interface}' 对应的Scapy接口名，无法启动监控。请检查接口选择或Scapy安装。")
            return

        if self.monitoring:
            messagebox.showinfo("提示", "监控已经在运行中。")
            return

        self.monitoring = True
        self.packet_count = 0  # 重置计数器
        self.packet_count_var.set("已处理ARP包: 0")
        self.monitor_status_var.set("监控状态: 运行中")
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.interface_dropdown.config(state=tk.DISABLED)  # 监控时不允许切换接口
        self.refresh_btn.config(state=tk.DISABLED)
        self.status_var.set(f"监控已在接口 '{self.scapy_interface_name}' 上启动")

        self.log_defense(f"准备在Scapy接口 '{self.scapy_interface_name}' (WMI: '{self.interface}') 上启动ARP嗅探...")

        # 确保 Scapy 使用正确的接口
        conf.iface = self.scapy_interface_name

        self.monitor_thread = threading.Thread(target=self.sniff_network_packets, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        if not self.monitoring:
            # messagebox.showinfo("提示", "监控尚未启动。") # 可能不需要这个提示
            return

        self.monitoring = False  # 设置标志，让嗅探线程停止
        # sniff 函数的 stop_filter 会检测到这个变化

        # 等待嗅探线程结束 (可选，但有助于确保资源释放)
        if hasattr(self, 'monitor_thread') and self.monitor_thread.is_alive():
            try:
                self.monitor_thread.join(timeout=2.0)  # 等待2秒
                if self.monitor_thread.is_alive():
                    logging.warning("监控线程在超时后仍未结束。")
            except Exception as e:
                logging.error(f"停止监控线程时出错: {e}")

        self.monitor_status_var.set("监控状态: 已停止")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.interface_dropdown.config(state="readonly")  # 恢复接口选择
        self.refresh_btn.config(state=tk.NORMAL)
        self.status_var.set("监控已停止")
        self.log_defense("网络监控已停止。")
        logging.info("网络监控已停止。")

    def toggle_defense(self):
        self.defense_active = not self.defense_active

        if self.defense_active:
            if not self.monitoring:  # 防御通常需要监控配合
                messagebox.showwarning("提示", "ARP防御已启用，但网络监控未运行。建议同时启动监控以检测威胁。")

            self.defense_status_var.set("防御状态: 已启用 (主动响应)")
            self.defense_btn.config(text="禁用ARP防御")
            self.log_defense("ARP主动防御已启用。将对检测到的欺骗尝试发送纠正ARP包。")
            self.status_var.set("ARP主动防御已启用")

            # 考虑在启用防御时自动绑定已知重要设备 (如网关)
            if self.gateway_ip and self.gateway_mac:
                self.bind_gateway_static()  # 尝试静态绑定网关
            else:
                self.log_defense("警告: 网关信息不完整，无法在启用防御时自动绑定网关。")
        else:
            self.defense_status_var.set("防御状态: 未启用")
            self.defense_btn.config(text="启用ARP防御")
            self.log_defense("ARP主动防御已禁用。")
            self.status_var.set("ARP主动防御已禁用")

    def add_arp_binding(self):
        ip = self.bind_ip_var.get().strip()
        mac_raw = self.bind_mac_var.get().strip()

        if not ip or not mac_raw:
            messagebox.showerror("错误", "请输入IP和MAC地址。")
            return

        # 验证IP地址格式
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            messagebox.showerror("错误", "IP地址格式不正确。")
            return

        mac = normalize_mac_address(mac_raw)
        if not mac or len(mac) != 17:  # 规范化后应为 xx:xx:xx:xx:xx:xx
            messagebox.showerror("错误",
                                 f"MAC地址 '{mac_raw}' 格式不正确或无法规范化。请使用如 00:1A:2B:3C:4D:5E 或 00-1A-2B-3C-4D-5E 的格式。")
            return

        # 设置静态ARP绑定 (系统层面)
        if self.set_arp_static_entry(ip, mac):
            # 更新UI中的绑定列表
            # 检查是否已存在此IP的绑定，如果存在则更新，否则添加
            updated = False
            for item_id in self.bind_tree.get_children():
                if self.bind_tree.item(item_id, 'values')[0] == ip:
                    self.bind_tree.item(item_id, values=(ip, mac))
                    updated = True
                    break
            if not updated:
                self.bind_tree.insert("", "end", values=(ip, mac))

            self.log_defense(f"已添加/更新静态ARP绑定: {ip} -> {mac}")
            self.status_var.set(f"静态ARP绑定: {ip} -> {mac} 设置成功。")
            self.bind_ip_var.set("")  # 清空输入框
            self.bind_mac_var.set("")
        else:
            # set_arp_static_entry 内部会记录日志和显示消息
            self.status_var.set(f"静态ARP绑定: {ip} -> {mac} 设置失败。")

    def set_arp_static_entry(self, ip, mac):
        """设置静态ARP条目到系统中 (arp -s)"""
        if not ip or not mac:
            logging.error("设置静态ARP错误: IP或MAC为空。")
            return False

        mac_for_cmd = mac.replace(":", "-")  # arp -s 命令通常接受 xx-xx-xx-xx-xx-xx 格式

        try:
            # Windows 'arp -s' 命令需要管理员权限
            # 删除可能已存在的该IP的任何ARP条目 (动态或静态)
            # 'arp -d ip_address'
            # subprocess.run(f"arp -d {ip}", shell=True, capture_output=True, text=True)
            # 上面的删除可能没有必要，arp -s 会覆盖

            # 添加静态ARP条目: arp -s <IP地址> <MAC地址> [接口IP地址]
            # 如果不指定接口IP，会添加到第一个匹配的接口，这可能不总是期望的。
            # 为了精确，可以指定接口IP (self.my_ip)
            cmd = f"arp -s {ip} {mac_for_cmd}"
            if self.my_ip:  # 如果当前选定接口有IP，则指定接口
                # 在某些Windows版本，arp -s 的接口参数是通过 iface index，而不是IP
                # 但通常直接 arp -s IP MAC 也能工作，并绑定到合适的接口
                # 为简单起见，暂时不加接口参数，依赖系统判断
                # cmd = f"arp -s {ip} {mac_for_cmd} {self.my_ip}"
                pass

            logging.info(f"执行ARP命令: {cmd}")
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)

            self.log_defense(f"系统静态ARP设置成功: {ip} -> {mac}")
            logging.info(f"系统静态ARP设置成功: {ip} -> {mac}. Output: {result.stdout}")
            self.update_arp_table_from_system()  # 更新内部ARP表缓存
            return True
        except subprocess.CalledProcessError as e:
            error_msg = f"设置静态ARP绑定 {ip} -> {mac} 失败: {e.stderr or e.stdout or str(e)}"
            logging.error(error_msg)
            self.log_defense(f"错误: {error_msg}")
            messagebox.showerror("ARP绑定失败", error_msg)
            return False
        except Exception as e_gen:
            error_msg_gen = f"设置静态ARP绑定时发生未知错误: {str(e_gen)}"
            logging.error(error_msg_gen)
            self.log_defense(f"错误: {error_msg_gen}")
            messagebox.showerror("ARP绑定失败", error_msg_gen)
            return False

    def delete_arp_static_entry(self, ip):
        """从系统中删除静态/动态ARP条目 (arp -d)"""
        if not ip:
            return False
        try:
            cmd = f"arp -d {ip}"
            logging.info(f"执行ARP命令: {cmd}")
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
            self.log_defense(f"系统ARP条目删除成功: {ip}")
            logging.info(f"系统ARP条目删除成功: {ip}. Output: {result.stdout}")
            self.update_arp_table_from_system()  # 更新内部ARP表缓存
            return True
        except subprocess.CalledProcessError as e:
            error_msg = f"删除ARP条目 {ip} 失败: {e.stderr or e.stdout or str(e)}"
            # 如果条目不存在，arp -d 也会报错，这不一定是严重错误
            if "the arp entry deletion failed: element not found" in str(e).lower() or \
                    "arp 条目删除失败: 找不到元素" in str(e).lower():
                self.log_defense(f"尝试删除ARP条目 {ip}，但系统中未找到该条目。")
                logging.info(f"尝试删除ARP条目 {ip}，但系统中未找到该条目。")
                return True  # 从应用角度看，条目确实不在了

            logging.error(error_msg)
            self.log_defense(f"错误: {error_msg}")
            messagebox.showerror("ARP删除失败", error_msg)
            return False
        except Exception as e_gen:
            error_msg_gen = f"删除ARP条目时发生未知错误: {str(e_gen)}"
            logging.error(error_msg_gen)
            self.log_defense(f"错误: {error_msg_gen}")
            messagebox.showerror("ARP删除失败", error_msg_gen)
            return False

    def show_bind_tree_menu(self, event):
        """显示绑定列表的右键菜单"""
        selected_item = self.bind_tree.identify_row(event.y)
        if selected_item:
            self.bind_tree.selection_set(selected_item)  # 选中右键点击的行
            self.bind_tree_menu.post(event.x_root, event.y_root)

    def delete_selected_binding(self):
        """删除选中的静态绑定 (从系统和UI)"""
        selected_items = self.bind_tree.selection()
        if not selected_items:
            messagebox.showinfo("提示", "请先在绑定列表中选择一个条目。")
            return

        item_id = selected_items[0]
        values = self.bind_tree.item(item_id, 'values')
        ip_to_delete = values[0]
        mac_to_delete = values[1]

        confirm = messagebox.askyesno("确认删除",
                                      f"确定要从系统和列表中删除IP {ip_to_delete} (MAC: {mac_to_delete}) 的静态ARP绑定吗？")
        if confirm:
            if self.delete_arp_static_entry(ip_to_delete):  # 从系统中删除
                self.bind_tree.delete(item_id)  # 从UI中删除
                self.log_defense(f"已删除静态ARP绑定: {ip_to_delete} -> {mac_to_delete}")
                self.status_var.set(f"静态ARP绑定 {ip_to_delete} 已删除。")
            else:
                self.log_defense(f"尝试删除静态ARP绑定 {ip_to_delete} 失败。")
                self.status_var.set(f"删除静态ARP绑定 {ip_to_delete} 失败。")
                # 即使系统删除失败，也可能需要从UI移除，或者提示用户手动检查

    def bind_gateway_static(self):
        """静态绑定网关ARP"""
        if self.gateway_ip and self.gateway_mac:
            if self.set_arp_static_entry(self.gateway_ip, self.gateway_mac):
                # 更新UI中的绑定列表
                updated = False
                for item_id in self.bind_tree.get_children():
                    if self.bind_tree.item(item_id, 'values')[0] == self.gateway_ip:
                        self.bind_tree.item(item_id, values=(self.gateway_ip, self.gateway_mac))
                        updated = True
                        break
                if not updated:
                    self.bind_tree.insert("", "end", values=(self.gateway_ip, self.gateway_mac))
                self.log_defense(f"已静态绑定网关: {self.gateway_ip} -> {self.gateway_mac}")
                self.status_var.set("网关ARP已成功静态绑定。")
            else:
                self.log_defense(f"静态绑定网关 {self.gateway_ip} -> {self.gateway_mac} 失败。")
                self.status_var.set("静态绑定网关失败。")
        else:
            self.log_defense("无法绑定网关: 网关IP或MAC信息不完整。请先确保接口已正确选择且网关信息已获取。")
            messagebox.showwarning("绑定失败", "无法绑定网关，因为网关IP或MAC信息不完整。\n请检查网络接口选择和网络连接。")

    # def bind_local_static(self): ... (绑定本机通常意义不大，可以省略或按需实现)

    def clear_displayed_bindings(self):
        """清除UI中显示的所有ARP绑定 (不影响系统中的)"""
        if not self.bind_tree.get_children():
            messagebox.showinfo("提示", "当前没有显示的绑定条目可清除。")
            return

        confirm = messagebox.askyesno("确认清除",
                                      "确定要清除列表中显示的所有ARP绑定吗？\n(这不会影响系统中实际的静态ARP条目)")
        if confirm:
            for item in self.bind_tree.get_children():
                self.bind_tree.delete(item)
            self.log_defense("已清除UI中显示的ARP绑定列表。")
            self.status_var.set("显示的ARP绑定已清除。")

    def log_defense(self, message):
        """记录防御及操作日志到UI"""
        if hasattr(self, 'defense_log') and self.defense_log:
            self.defense_log.config(state=tk.NORMAL)
            self.defense_log.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
            self.defense_log.config(state=tk.DISABLED)
            self.defense_log.see(tk.END)
        logging.info(f"[防御日志] {message}")  # 也记录到文件

    def log_alert(self, alert_type, source_ip, details):
        """记录安全警报到UI和日志文件"""
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # 更完整的时间戳

        # 避免过于频繁的相同警报 (例如，持续的欺骗攻击)
        # 可以基于 (alert_type, source_ip, details的某个摘要) 做一个简单的去重计时器
        # 此处简化，直接添加

        # 添加到UI的警报树
        self.alert_tree.insert("", 0, values=(timestamp_str, alert_type, source_ip, details))  # 插入到顶部

        # 添加到内部列表 (如果需要)
        self.alerts.append((timestamp_str, alert_type, source_ip, details))

        # 自动滚动到顶部 (如果插入到顶部)
        # self.alert_tree.yview_moveto(0.0)

        # 在状态栏显示最新警报 (可以考虑只显示一段时间)
        self.status_var.set(f"新警报: {alert_type} - {source_ip}")

        # 记录到日志文件
        logging.warning(f"安全警报: 类型='{alert_type}', 源IP='{source_ip}', 详情='{details}'")

        # 弹出消息提示 (可选，可能会很烦人)
        # messagebox.showwarning("安全警报", f"类型: {alert_type}\n来源IP: {source_ip}\n详情: {details[:100]}...")

    def show_alert_details(self, event):
        selected = self.alert_tree.selection()
        if not selected:
            return

        item = self.alert_tree.item(selected[0])
        values = item['values']  # (time, type, source, details)

        self.alert_detail.config(state=tk.NORMAL)
        self.alert_detail.delete(1.0, tk.END)
        if len(values) == 4:
            self.alert_detail.insert(tk.END, f"时间: {values[0]}\n")
            self.alert_detail.insert(tk.END, f"类型: {values[1]}\n")
            self.alert_detail.insert(tk.END, f"来源IP: {values[2]}\n")
            self.alert_detail.insert(tk.END, f"详细信息:\n{values[3]}")
        self.alert_detail.config(state=tk.DISABLED)

    def clear_alerts(self):
        if not self.alert_tree.get_children():
            messagebox.showinfo("提示", "当前没有警报可清除。")
            return
        confirm = messagebox.askyesno("确认清除", "确定要清除所有安全警报吗？")
        if confirm:
            for item in self.alert_tree.get_children():
                self.alert_tree.delete(item)
            self.alerts = []
            self.alert_detail.config(state=tk.NORMAL)
            self.alert_detail.delete(1.0, tk.END)
            self.alert_detail.config(state=tk.DISABLED)
            self.status_var.set("所有安全警报已清除。")
            self.log_defense("所有安全警报已清除。")  # 也记录到操作日志

    def determine_scapy_interface_name(self):
        """根据WMI获取的接口信息 (主要是MAC和IP) 来确定Scapy使用的接口名"""
        if not SCAPY_AVAILABLE or not self.interface:
            return None

        # 优先使用MAC地址匹配，因为IP可能变动或未分配
        if self.my_mac:
            my_mac_norm = normalize_mac_address(self.my_mac)
            try:
                for iface_obj in get_if_list(resolve_mac=True):  # get_if_list可以返回对象列表
                    # scapy.arch.windows.NetworkInterface
                    if hasattr(iface_obj, 'mac') and hasattr(iface_obj, 'name'):
                        scapy_mac_norm = normalize_mac_address(iface_obj.mac)
                        if scapy_mac_norm == my_mac_norm:
                            logging.info(
                                f"Scapy接口匹配 (MAC): WMI '{self.interface}' -> Scapy '{iface_obj.name}' (MAC: {my_mac_norm})")
                            return iface_obj.name  # 返回Scapy接口名，如 'eth0', '{GUID}'
            except Exception as e_mac_match:
                logging.warning(f"通过MAC匹配Scapy接口时出错: {e_mac_match}")

        # 其次尝试IP地址匹配
        if self.my_ip:
            try:
                for iface_name_str in get_if_list():  # get_if_list() 返回字符串列表
                    try:
                        scapy_iface_ip = get_if_addr(iface_name_str)
                        if scapy_iface_ip == self.my_ip:
                            logging.info(
                                f"Scapy接口匹配 (IP): WMI '{self.interface}' -> Scapy '{iface_name_str}' (IP: {self.my_ip})")
                            return iface_name_str
                    except Exception:  # get_if_addr 可能对某些接口失败
                        continue
            except Exception as e_ip_match:
                logging.warning(f"通过IP匹配Scapy接口时出错: {e_ip_match}")

        # 如果直接匹配失败，尝试更宽松的名称匹配 (作为最后的手段)
        # Scapy在Windows上可能使用GUID作为接口名，WMI使用描述性名称
        # 这部分匹配可能不可靠
        try:
            all_scapy_ifs = get_if_list()
            wmi_desc_lower = self.interface.lower()
            for scapy_if_name in all_scapy_ifs:
                if wmi_desc_lower in scapy_if_name.lower():  # 简单包含匹配
                    logging.warning(
                        f"Scapy接口匹配 (名称包含 - 可能不准确): WMI '{self.interface}' -> Scapy '{scapy_if_name}'")
                    return scapy_if_name
        except Exception as e_name_match:
            logging.warning(f"通过名称匹配Scapy接口时出错: {e_name_match}")

        logging.error(f"无法为WMI接口 '{self.interface}' (IP: {self.my_ip}, MAC: {self.my_mac}) 找到匹配的Scapy接口。")
        return None

    def sniff_network_packets(self):
        """Scapy嗅探网络ARP包的线程函数"""
        if not SCAPY_AVAILABLE or not self.monitoring or not conf.iface:
            if not SCAPY_AVAILABLE: self.log_defense("错误: Scapy不可用，无法启动嗅探。")
            if not self.monitoring: self.log_defense("错误: 监控标志未设置，无法启动嗅探。")
            if not conf.iface: self.log_defense(
                f"错误: Scapy接口 (conf.iface) 未设置，无法启动嗅探。当前 WMI 接口: {self.interface}")
            self.stop_monitoring()  # 确保状态一致
            return

        self.log_defense(f"开始在Scapy接口 '{conf.iface}' 上嗅探ARP包...")

        try:
            # stop_filter 用于在 self.monitoring 变为 False 时停止嗅探
            # filter="arp" 只捕获ARP包
            # store=0 表示不将包存储在内存中
            # prn 指定每个包的回调函数
            sniff(iface=conf.iface, prn=self.process_arp_packet_from_sniff, filter="arp", store=0,
                  stop_filter=lambda x: not self.monitoring)
        except RuntimeError as e_rt:  # 例如 "cannot find winpcap"
            logging.error(f"Scapy嗅探运行时错误 (接口: {conf.iface}): {str(e_rt)}")
            self.log_defense(f"Scapy嗅探错误: {str(e_rt)}。请确保WinPcap/Npcap已正确安装并正在运行。")
            messagebox.showerror("Scapy嗅探错误",
                                 f"启动网络嗅探失败:\n{str(e_rt)}\n\n请确保WinPcap或Npcap已正确安装并正在运行。")
            self.root.after(0, self.stop_monitoring)  # 在主线程中停止监控
        except Exception as e:
            logging.error(f"Scapy网络嗅探发生意外错误 (接口: {conf.iface}): {str(e)}")
            self.log_defense(f"Scapy网络嗅探意外错误: {str(e)}")
            self.root.after(0, self.stop_monitoring)  # 在主线程中停止监控

        if self.monitoring:  # 如果循环结束但监控标志仍为true，说明是非正常停止
            self.log_defense("嗅探意外终止。")
            logging.warning("Scapy sniff函数意外终止，但监控标志仍为True。")
            self.root.after(0, self.stop_monitoring)

    def get_normalized_static_bindings(self):
        """获取UI中当前显示的、规范化后的静态绑定 IP -> MAC"""
        bindings = {}
        for item_id in self.bind_tree.get_children():
            values = self.bind_tree.item(item_id, 'values')
            if len(values) == 2:
                # bind_tree 中的 MAC 应该已经是规范化的
                bindings[values[0]] = values[1]  # MAC已经是 normalize_mac_address 处理过的
        return bindings

    def process_arp_packet_from_sniff(self, packet):
        """处理Scapy嗅探到的ARP包 (在嗅探线程中运行)"""
        if not packet.haslayer(ARP):
            return

        self.packet_count += 1
        # 更新UI的操作需要放到主线程中执行，使用 self.root.after
        self.root.after(0, lambda: self.packet_count_var.set(f"已处理ARP包: {self.packet_count}"))

        arp_layer = packet[ARP]
        src_ip = arp_layer.psrc
        src_mac_raw = arp_layer.hwsrc
        src_mac = normalize_mac_address(src_mac_raw)

        dst_ip = arp_layer.pdst  # ARP包的目标IP (ARP请求的查询对象，ARP回复的接收者)
        # dst_mac_raw = arp_layer.hwdst # ARP包的目标MAC (ARP请求通常是00:00.., ARP回复是查询者的MAC)

        op_code = arp_layer.op  # 1 for request ('who-has'), 2 for reply ('is-at')

        # 忽略本机发出的包 和 一些无效/广播IP/MAC
        if src_ip == self.my_ip or src_ip in ["0.0.0.0", "255.255.255.255"] or \
                src_mac in ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "incomplete"]:
            return

        logging.debug(f"ARP嗅探: OP={op_code}, SRC_IP={src_ip}, SRC_MAC={src_mac}, DST_IP={dst_ip}")

        # --- ARP欺骗检测核心逻辑 ---
        is_spoof = False
        alert_details = ""
        trusted_mac_source = "未知"  # 用于记录警报

        # 1. 检查是否与静态绑定冲突 (最高优先级)
        static_bindings = self.get_normalized_static_bindings()  # 从UI获取
        if src_ip in static_bindings:
            trusted_mac = static_bindings[src_ip]
            trusted_mac_source = "静态绑定"
            if src_mac != trusted_mac:
                is_spoof = True
                alert_details = f"IP {src_ip} 的MAC地址 ({src_mac}) 与静态绑定的MAC ({trusted_mac}) 不符。"

        # 2. 如果没有静态绑定冲突，检查是否与系统ARP缓存冲突 (次高优先级)
        # self.arp_table 是通过 'arp -a' 定期更新的
        if not is_spoof and src_ip in self.arp_table:
            trusted_mac = self.arp_table[src_ip]  # arp_table中的MAC已规范化
            trusted_mac_source = "系统ARP缓存"
            if src_mac != trusted_mac:
                # 进一步确认：如果这个IP是网关，且声明的MAC与我们已知的网关MAC不符
                if src_ip == self.gateway_ip and self.gateway_mac and src_mac != self.gateway_mac:
                    is_spoof = True
                    alert_details = f"网关IP {src_ip} 的MAC地址 ({src_mac}) 与系统ARP缓存/已知网关MAC ({trusted_mac}/{self.gateway_mac}) 不符。"
                elif src_ip != self.gateway_ip:  # 非网关IP冲突
                    is_spoof = True
                    alert_details = f"IP {src_ip} 的MAC地址 ({src_mac}) 与系统ARP缓存中的MAC ({trusted_mac}) 不符。"

        # 3. 如果也不是系统ARP缓存冲突，检查 self.devices 中记录的MAC是否变化 (最低优先级)
        # 这可以检测一个已知设备突然改变MAC地址的情况
        if not is_spoof and src_ip in self.devices:
            previous_mac = self.devices[src_ip].get("mac")
            if previous_mac and src_mac != previous_mac:
                # 可能是合法换网卡，也可能是更隐蔽的欺骗。这里需要谨慎。
                # 如果这个IP是网关，且变化后的MAC和我们已知的网关MAC不符，则更可疑
                if src_ip == self.gateway_ip and self.gateway_mac and src_mac != self.gateway_mac:
                    is_spoof = True
                    alert_details = f"网关IP {src_ip} 的MAC地址从 {previous_mac} 变为 {src_mac} (与已知网关MAC {self.gateway_mac} 不符)。"
                    trusted_mac_source = "之前观察到的网关MAC"
                else:  # 非网关IP的MAC变化
                    is_spoof = True  # 标记为潜在欺骗，但可能需要人工确认
                    alert_details = f"IP {src_ip} 的MAC地址从之前观察到的 {previous_mac} 变为 {src_mac}。"
                    trusted_mac_source = "之前观察值"

        if is_spoof:
            log_msg = f"ARP欺骗警报! {alert_details} (信任来源: {trusted_mac_source})"
            # 使用 root.after 在主线程中调用 log_alert
            self.root.after(0, lambda lm=log_msg, sip=src_ip, ad=alert_details: self.log_alert("ARP欺骗", sip, lm))

            if self.defense_active:
                # 确定正确的MAC地址用于发送纠正包
                correct_mac_to_send = None
                if src_ip in static_bindings:
                    correct_mac_to_send = static_bindings[src_ip]
                elif src_ip in self.arp_table:
                    correct_mac_to_send = self.arp_table[src_ip]
                elif src_ip == self.gateway_ip and self.gateway_mac:  # 优先使用已知的网关MAC
                    correct_mac_to_send = self.gateway_mac
                # 如果都没有，可以考虑使用 self.devices 中上一次的MAC，但这风险较高

                if correct_mac_to_send:
                    # 确定欺骗包的受害者IP，通常是arp_layer.pdst
                    # 如果欺骗者伪装成网关，那么受害者可能是本地网络上的其他主机，包括本机
                    # 如果欺骗者伪装成其他主机，受害者可能是网关或本机
                    victim_ip_in_arp = dst_ip
                    self.root.after(0, lambda sip=src_ip, cmac=correct_mac_to_send, vip=victim_ip_in_arp: \
                        self.send_corrective_arp(sip, cmac, vip))
                else:
                    logging.warning(f"检测到ARP欺骗来自 {src_ip} ({src_mac})，但未能确定其正确的MAC地址，无法发送纠正包。")

        # --- 更新 self.devices 列表 (无论是否欺骗，都记录最新观察) ---
        device_entry = self.devices.get(src_ip)
        current_time = time.time()
        if device_entry:
            if device_entry["mac"] != src_mac and not is_spoof:  # MAC变了但未被标记为欺骗 (例如，新设备或合法更换)
                logging.info(f"IP {src_ip} 的MAC地址从 {device_entry['mac']} 更新为 {src_mac} (未标记为欺骗)。")
            device_entry["mac"] = src_mac  # 更新为最新观察到的MAC
            device_entry["last_seen"] = current_time
            device_entry["status"] = "在线"
        else:
            self.devices[src_ip] = {
                "mac": src_mac,
                "last_seen": current_time,
                "status": "在线"
            }
            logging.info(f"网络中发现新设备 (或首次通过ARP观察到): {src_ip} - {src_mac}")
            # 新设备发现时，可能需要更新一次ARP表，或触发一次对该设备的主动查询（如果需要更强验证）
            self.root.after(100, self.update_arp_table_from_system)  # 延迟更新，避免过于频繁

        # 定期更新UI中的设备列表 (例如每处理N个包或每隔几秒)
        # 这个逻辑移到 periodic_updates 中，以固定频率执行

    def send_corrective_arp(self, spoofed_ip, correct_mac, original_arp_dst_ip):
        """发送纠正性的ARP包 (在主线程中调用，因为它可能更新UI日志)"""
        if not SCAPY_AVAILABLE or not conf.iface:
            self.log_defense("错误: Scapy不可用或接口未设置，无法发送纠正ARP。")
            return

        correct_mac_norm = normalize_mac_address(correct_mac)
        if not correct_mac_norm or correct_mac_norm in ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "incomplete"]:
            self.log_defense(f"错误: 提供的正确MAC地址 '{correct_mac}' 无效，无法为IP {spoofed_ip} 发送纠正ARP。")
            logging.warning(f"尝试为IP {spoofed_ip} 发送纠正ARP，但提供的正确MAC '{correct_mac}' 无效。")
            return

        try:
            logging.info(
                f"准备为IP {spoofed_ip} 发送ARP纠正，正确MAC: {correct_mac_norm}。原始ARP目标IP: {original_arp_dst_ip}")

            # 方案1: 发送免费ARP (Gratuitous ARP) 给广播地址，声明 spoofed_ip 的正确MAC
            # 这会通知网络上所有监听的主机
            gratuitous_arp_reply = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                                   ARP(op=2,  # "is-at" (ARP Reply)
                                       hwsrc=correct_mac_norm,  # 正确的源MAC
                                       psrc=spoofed_ip,  # 被欺骗的源IP
                                       hwdst="ff:ff:ff:ff:ff:ff",  # 对于免费ARP，目标MAC通常是广播或00s
                                       pdst=spoofed_ip)  # 对于免费ARP，目标IP通常也是源IP

            sendp(gratuitous_arp_reply, iface=conf.iface, verbose=0)
            log_msg_g = f"已发送广播ARP纠正: IP {spoofed_ip} 的MAC应为 {correct_mac_norm}。"
            self.log_defense(log_msg_g)
            logging.info(log_msg_g)

            # 方案2: 如果知道原始欺骗ARP包的目标IP (original_arp_dst_ip)，可以向其发送定向ARP纠正
            # 这有助于直接通知受害者。
            # original_arp_dst_ip 就是欺骗者想要欺骗的那个IP (例如本机IP，或网关IP)
            if original_arp_dst_ip and original_arp_dst_ip != "0.0.0.0" and original_arp_dst_ip != spoofed_ip:
                # 获取 original_arp_dst_ip (受害者) 的MAC地址
                # 注意：这里获取受害者MAC也可能被欺骗，但这是尽力而为的尝试
                victim_mac_raw = self.get_mac_address_for_ip(original_arp_dst_ip)
                victim_mac_norm = normalize_mac_address(victim_mac_raw)

                if victim_mac_norm and victim_mac_norm not in ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "incomplete"]:
                    targeted_arp_reply = Ether(dst=victim_mac_norm) / \
                                         ARP(op=2,  # "is-at"
                                             hwsrc=correct_mac_norm,  # 正确的源MAC (对应spoofed_ip)
                                             psrc=spoofed_ip,  # 被欺骗的源IP
                                             hwdst=victim_mac_norm,  # 受害者的MAC
                                             pdst=original_arp_dst_ip)  # 受害者的IP

                    sendp(targeted_arp_reply, iface=conf.iface, verbose=0)
                    log_msg_t = f"已向 {original_arp_dst_ip}({victim_mac_norm}) 发送定向ARP纠正: IP {spoofed_ip} 的MAC应为 {correct_mac_norm}。"
                    self.log_defense(log_msg_t)
                    logging.info(log_msg_t)
                else:
                    logging.warning(f"无法获取受害者 {original_arp_dst_ip} 的MAC地址，未能发送定向ARP纠正。")

        except Exception as e:
            error_msg = f"发送ARP纠正包 (针对IP {spoofed_ip}) 失败: {str(e)}"
            logging.error(error_msg)
            self.log_defense(f"错误: {error_msg}")

    def update_device_list_ui(self):
        """更新UI中的设备列表 (在主线程中调用)"""
        # 清空现有列表
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)

        # 检查设备状态 (标记离线)
        current_time = time.time()
        offline_threshold = 60  # 秒, 例如超过60秒未见ARP包则认为离线

        # devices_copy = list(self.devices.items()) # 复制以避免迭代时修改
        # for ip, info in devices_copy: # 使用副本迭代
        ips_to_remove = []
        for ip, info in self.devices.items():
            if current_time - info.get("last_seen", 0) > offline_threshold:
                if info["status"] == "在线":  # 仅当状态从在线变为离线时记录日志
                    logging.info(f"设备 {ip} ({info.get('mac')}) 长时间未活跃，标记为离线。")
                info["status"] = "离线"
                # 可以考虑在非常久未见后从 self.devices 中移除，或者保留但标记为“非常不活跃”
                # if current_time - info.get("last_seen", 0) > offline_threshold * 10: # 例如10倍时间
                #     ips_to_remove.append(ip)

            # 重新填充列表
            last_seen_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(info.get("last_seen", 0))) if info.get(
                "last_seen") else "N/A"
            self.device_tree.insert("", "end",
                                    values=(ip, info.get("mac", "N/A"), info.get("status", "未知"), last_seen_str))

        # for ip_remove in ips_to_remove:
        #     del self.devices[ip_remove]
        #     logging.info(f"设备 {ip_remove} 因长时间不活跃已从监控列表移除。")

    def update_traffic_stats_ui(self):
        """更新UI中的流量统计 (当前为模拟数据)"""
        if not hasattr(self, 'traffic_text') or not self.traffic_text:
            return

        # 实际应用中需要从pcap或其他方式获取真实流量
        import random
        for ip in list(self.devices.keys()):  # 使用keys的副本，因为devices可能在其他线程修改
            if self.devices.get(ip, {}).get("status") == "在线":  # 只更新在线设备的模拟流量
                self.traffic_stats[ip]["sent"] += random.randint(10, 100)  # KB
                self.traffic_stats[ip]["received"] += random.randint(5, 50)  # KB

        self.traffic_text.config(state=tk.NORMAL)
        self.traffic_text.delete(1.0, tk.END)

        header = f"{'IP地址':<18}{'发送(KB)':>12}{'接收(KB)':>12}{'总计(KB)':>12}\n"
        self.traffic_text.insert(tk.END, header)
        self.traffic_text.insert(tk.END, "-" * len(header) + "\n")

        sorted_traffic = sorted(self.traffic_stats.items(), key=lambda item: item[1]['sent'] + item[1]['received'],
                                reverse=True)

        for ip, stats in sorted_traffic:
            if ip in self.devices:  # 只显示当前设备列表中的IP
                sent_kb = stats["sent"]
                recv_kb = stats["received"]
                total_kb = sent_kb + recv_kb
                self.traffic_text.insert(tk.END, f"{ip:<18}{sent_kb:>12}{recv_kb:>12}{total_kb:>12}\n")

        self.traffic_text.config(state=tk.DISABLED)

    def periodic_updates(self):
        """定期执行的UI更新和其他周期性任务 (在主线程中)"""
        if self.monitoring:  # 只有在监控时才更新这些
            self.update_device_list_ui()
            self.update_traffic_stats_ui()  # 如果有真实流量统计的话

        # 每隔一段时间自动更新系统ARP表缓存
        # (例如，如果最后更新时间超过N秒)
        # self.update_arp_table_from_system() # 这个可能比较耗时，频率不宜过高

        self.root.after(5000, self.periodic_updates)  # 5秒后再次调用


if __name__ == "__main__":
    # 顶部的管理员权限检查已经处理了提权。
    # 此处的检查更多是作为后备或提示。
    if platform.system() == "Windows":
        try:
            is_admin_final_check = ctypes.windll.shell32.IsUserAnAdmin()
        except:
            is_admin_final_check = False

        if not is_admin_final_check:
            # 如果到这里还没有管理员权限，说明提权失败或被跳过
            messagebox.showwarning("权限警告",
                                   "程序未能获取管理员权限。\n"
                                   "ARP静态绑定、网络嗅探等核心功能可能无法正常工作。\n"
                                   "请尝试以管理员身份手动重新运行此程序。")

    root = tk.Tk()
    app = WindowsARPSecurityMonitor(root)


    def on_closing():
        if app.monitoring:
            if messagebox.askokcancel("退出确认", "监控仍在运行中。确定要停止监控并退出吗？"):
                app.stop_monitoring()  # 确保监控线程被妥善停止
                root.destroy()
            else:
                return  # 用户取消退出
        else:
            root.destroy()


    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
