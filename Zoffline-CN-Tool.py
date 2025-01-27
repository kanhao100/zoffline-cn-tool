import socket
import FreeSimpleGUI as sg
import ctypes
import sys
import os
import shutil
import subprocess
import tkinter as tk
from tkinter import filedialog
import time
import platform
import math
import signal
import threading

import xml.etree.ElementTree as ET
from urllib3 import PoolManager
from binascii import crc32
import requests
import warnings
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed

def is_admin():
    """检查是否具有管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """以管理员权限重新启动程序"""
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

def create_main_window():
    """创建主窗口"""
    sg.theme('LightGrey1')
    
    # 添加菜单栏
    menu_def = [
        ['文件(&F)', ['保存配置', '重新加载配置', '---', '退出']],
        ['工具(&T)', ['检查系统代理', '检查端口占用', '强行终止端口占用', '---', '清理网络配置', '终止所有进程']],
        ['版本(&V)', ['查询官服版本', '查询社区服版本', '查询内置版本库']],
        ['测试(&D)', ['远程端口测试', '本地host和caddy测试', 'HTTPS测试', '一键测试连通性']],
        ['帮助(&H)', ['使用说明', '关于']]
    ]
    
    # 状态面板布局
    status_layout = [
        [sg.Text("进程状态:", font=("Helvetica", 12))],
        [sg.Text("ZwiftLauncher:", size=(12,1)), 
        sg.Text("●", text_color='red', key='-LAUNCHER-STATUS-')],
        [sg.Text("ZwiftApp:", size=(12,1)), 
        sg.Text("●", text_color='red', key='-APP-STATUS-')],
        [sg.Text("Caddy:", size=(12,1)), 
        sg.Text("●", text_color='red', key='-CADDY-STATUS-')],
        [sg.Text("Zoffline_local:", size=(12,1)), 
        sg.Text("●", text_color='red', key='-ZOFFLINE-STATUS-')]
    ]
    
    # 服务器设置布局
    server_layout = [
        [sg.Text("服务器设置:", font=("Helvetica", 12))],
        [sg.Text("IP:", size=(2,1)), 
        sg.Input(key='-SERVER-IP-', size=(15,1)), 
        sg.Button("保存IP")]
    ]
    
    # 主要按钮布局
    main_layout = [
        [sg.Frame('主要功能', [
            [sg.Button("一键启动社区服Zwift", size=(24, 5), button_color=('white', '#FF6347'))],
            [sg.Button("一键启动官服Zwift", size=(24, 2))],
            [sg.Button("更新下载资源文件(手动)", size=(24, 2))]
        ], pad=(10, 5))]
    ]
    
    # 高级选项布局
    advanced_layout = [
        [sg.Frame('高级选项', [
            [sg.Button("手动选择证书", size=(15, 1)),
            sg.Button("导入Host设置", size=(15, 1))],
            [sg.Button("自动导入系统证书", size=(15, 1)),
            sg.Button("自动导入客户端证书", size=(15, 1))],
            [sg.Button("启动Caddy后台", size=(15, 1)),
            sg.Button("查询官服版本", size=(15, 1))],
            [sg.Button("查询社区服版本", size=(15, 1)),
            sg.Button("查询内置版本库", size=(15, 1))],
            [sg.Button("强制\"更新\"版本", size=(15, 1)),
            sg.Button("检查系统代理", size=(15, 1))],
            [sg.Button("检查端口占用", size=(15, 1)),
            sg.Button("强行终止端口占用", size=(15, 1))],
            [sg.Button("远程端口测试", size=(15, 1)),
            sg.Button("本地host和caddy测试", size=(15, 1))],
            [sg.Button("社区服HTTPS测试", size=(15, 1)),
            sg.Button("一键测试连通性", size=(15, 1))]
        ], pad=(10, 5))]
    ]
    
    # 完整布局，添加菜单栏
    layout = [
        [sg.Menu(menu_def)],  # 添加菜单栏
        [sg.Text("Zoffline-CN Tool", font=("Helvetica", 20), justification='center', pad=(0, 10))],
        [sg.Column(status_layout, vertical_alignment='top'),
         sg.VerticalSeparator(pad=(10,0)),
         sg.Column(server_layout + main_layout, vertical_alignment='top'),
         sg.VerticalSeparator(pad=(10,0)),
         sg.Column(advanced_layout, vertical_alignment='top')],
        [sg.Output(size=(80, 10), pad=(10, 5), key='-OUTPUT-')],
        [
            sg.Button("退出", size=(15, 1)),
            sg.Button("终止所有进程", size=(15, 1)),
            sg.Button("清除网络配置", size=(15, 1))
        ],
    ]
    
    return sg.Window("Zoffline-CN Tool", layout, finalize=True)

def find_zwift_location():
    """查找Zwift安装位置"""
    try:
        # 首先检查zwift_location.txt
        location_file = "zwift_location.txt"
        if os.path.exists(location_file):
            with open(location_file, 'r', encoding='utf-8') as f:
                saved_path = f.read().strip().strip('"')
                if os.path.exists(os.path.join(saved_path, "ZwiftApp.exe")):
                    print(f"从配置文件找到Zwift安装位置: {saved_path}")
                    return saved_path

        # 常见安装位置
        common_locations = [
            os.path.join(os.environ['ProgramFiles(x86)'], 'Zwift'),
            os.path.join(os.environ['ProgramFiles'], 'Zwift'),
            os.path.join(os.environ['SystemDrive'] + '\\', 'Program Files (x86)', 'Zwift'),
            os.path.join(os.environ['SystemDrive'] + '\\', 'Program Files', 'Zwift')
        ]

        # 添加所有本地磁盘驱动器
        import string
        from ctypes import windll
        drives = []
        bitmask = windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drives.append(letter)
            bitmask >>= 1
        
        # 添加其他可能的安装位置
        for drive in drives:
            common_locations.extend([
                f"{drive}:\\Program Files (x86)\\Zwift",
                f"{drive}:\\Program Files\\Zwift",
                f"{drive}:\\Zwift"
            ])

        # 检查所有可能的位置
        for location in common_locations:
            zwift_exe = os.path.join(location, "ZwiftApp.exe")
            if os.path.exists(zwift_exe):
                print(f"自动找到Zwift安装位置: {location}")
                # 保存找到的位置
                with open(location_file, 'w', encoding='utf-8') as f:
                    f.write(f'"{location}"')
                return location

        print("未找到Zwift安装位置，请手动选择...")
        
        root = tk.Tk()
        root.withdraw()  # 隐藏主窗口
        
        folder_path = filedialog.askdirectory(
            title="请选择Zwift安装目录",
            initialdir=os.environ['ProgramFiles(x86)']
        )
        
        if folder_path:
            # 检查选择的文件夹是否包含ZwiftApp.exe
            if os.path.exists(os.path.join(folder_path, "ZwiftApp.exe")):
                print(f"已选择Zwift安装位置: {folder_path}")
                # 保存用户选择的位置
                with open(location_file, 'w', encoding='utf-8') as f:
                    f.write(f'"{folder_path}"')
                return folder_path
            else:
                print("[错误] 选择的文件夹不包含ZwiftApp.exe")
                return None
        else:
            print("[错误] 未选择Zwift安装位置")
            return None

    except Exception as e:
        print(f"[错误] 查找Zwift安装位置时出现异常: {str(e)}")
        return None

def modify_hosts_file():
    """修改hosts文件，添加Zwift相关的域名解析"""
    try:
        # hosts文件路径
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        
        # 检测文件编码
        encodings = ['ascii', 'gbk', 'gb2312', 'utf-8', 'utf-16', ]
        file_encoding = None
        
        for encoding in encodings:
            try:
                with open(hosts_path, 'r', encoding=encoding) as file:
                    file.read()
                file_encoding = encoding
                print(f"检测到hosts文件编码: {encoding}")
                break
            except UnicodeDecodeError:
                continue
                
        if not file_encoding:
            print("[错误] 无法检测hosts文件编码")
            return False
        
        # 备份hosts文件
        backup_path = hosts_path + '.bak'
        shutil.copy2(hosts_path, backup_path)
        print("已备份hosts文件")

        # 需要添加的域名
        domains = [
            "127.0.0.1 us-or-rly101.zwift.com",
            "127.0.0.1 secure.zwift.com",
            "127.0.0.1 cdn.zwift.com",
            "127.0.0.1 launcher.zwift.com"
        ]

        # 读取当前hosts文件内容
        with open(hosts_path, 'r', encoding=file_encoding) as file:
            lines = file.readlines()

        # 移除已存在的Zwift相关条目
        filtered_lines = [line for line in lines if 'zwift.com' not in line.lower()]

        # 添加新的域名解析
        filtered_lines.extend([domain + '\n' for domain in domains])

        # 写入更新后的内容
        with open(hosts_path, 'w', encoding=file_encoding) as file:
            file.writelines(filtered_lines)

        print("成功添加Zwift服务器解析到hosts文件")
        return True

    except PermissionError:
        print("[错误] 没有足够的权限修改hosts文件")
        return False
    except Exception as e:
        print(f"[错误] 修改hosts文件失败: {str(e)}")
        return False

def import_certificates():
    """导入系统证书"""
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # 检查证书文件是否存在
        # mixed_cert = os.path.join(current_dir, "mixed-key-zwift-com.p12")
        domain_cert = os.path.join(current_dir, "cert-zwift-com.p12")
        
        # if not os.path.exists(mixed_cert):
        #     print("[错误] 找不到证书文件 mixed-key-zwift-com.p12")
        #     return False
            
        if not os.path.exists(domain_cert):
            print("[错误] 找不到证书文件 cert-zwift-com.p12")
            return False
        
        process = subprocess.run(
            ['certutil.exe', '-store', 'Root'],
            capture_output=True,
            text=True
        )
        
        # # 检查并导入Mixed证书
        # if "73e89c29c209595132ef0d402687a87be5137756" not in process.stdout:
        #     print("正在导入Mixed证书...")
        #     result = subprocess.run(
        #         ['certutil.exe', '-importpfx', 'Root', mixed_cert],
        #         input='\n',  # 自动确认导入
        #         capture_output=True,
        #         text=True
        #     )
        #     if result.returncode != 0:
        #         print(f"[错误] Mixed证书导入失败: {result.stderr}")
        #         return False
        # else:
        #     print("Mixed证书已存在，无需导入")

        # 检查并导入Domain证书
        if "54f7f293407370a07679885767e5bd599458e471" not in process.stdout:
            print("正在导入Domain证书...")
            result = subprocess.run(
                ['certutil.exe', '-importpfx', 'Root', domain_cert],
                input='\n',  # 自动确认导入
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                print(f"[错误] Domain证书导入失败: {result.stderr}")
                return False
        else:
            print("Domain证书已存在，无需导入")

        return True

    except Exception as e:
        print(f"[错误] 证书导入过程出现异常: {str(e)}")
        return False

def import_client_certificates(zwift_folder):
    """导入Zwift客户端证书"""
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # 检查cacert.pem文件
        cacert_path = os.path.join(zwift_folder, "data", "cacert.pem")
        if not os.path.exists(cacert_path):
            print(f"[错误] 未找到cacert.pem文件: {cacert_path}")
            return False
            
        # 检查证书文件
        # mixed_cert_pem = os.path.join(current_dir, "mixed-cert-zwift-com.pem")
        domain_cert_pem = os.path.join(current_dir, "cert-zwift-com.pem")
        
        # if not os.path.exists(mixed_cert_pem):
        #     print("[错误] 未找到mixed-cert-zwift-com.pem文件")
        #     return False
            
        if not os.path.exists(domain_cert_pem):
            print("[错误] 未找到cert-zwift-com.pem文件")
            return False

        # 读取现有的cacert.pem内容
        with open(cacert_path, 'r', encoding='utf-8') as f:
            current_content = f.read()

        # # 检查并添加Mixed证书
        # mixed_cert_signature = "MIID8TCCAtmgAwIBAgIUc+icKcIJWVEy7w1AJoeoe+UTd1YwDQYJKoZIhvcNAQEL"
        # if mixed_cert_signature not in current_content:
        #     print("正在添加Mixed证书到cacert.pem...")
        #     with open(mixed_cert_pem, 'r') as f:
        #         mixed_cert_content = f.read()
        #     with open(cacert_path, 'a') as f:
        #         f.write('\n' + mixed_cert_content)
        # else:
        #     print("Mixed证书已存在于cacert.pem中")

        # 检查并添加Domain证书
        domain_cert_signature = "MIIEQTCCAymgAwIBAgIUVPfyk0BzcKB2eYhXZ+W9WZRY5HEwDQYJKoZIhvcNAQEL"
        if domain_cert_signature not in current_content:
            print("正在添加Domain证书到cacert.pem...")
            with open(domain_cert_pem, 'r', encoding='utf-8') as f:
                domain_cert_content = f.read()
            with open(cacert_path, 'a', encoding='utf-8') as f:
                f.write('\n' + domain_cert_content)
        else:
            print("Domain证书已存在于cacert.pem中")

        # 保存Zwift安装位置
        with open("zwift_location.txt", 'w', encoding='utf-8') as f:
            f.write(f'"{zwift_folder}"')

        print("客户端证书导入完成")
        return True

    except Exception as e:
        print(f"[错误] 导入客户端证书时出现异常: {str(e)}")
        return False

def check_processes():
    """检查Zwift相关进程的运行状态"""
    try:
        processes = {
            'ZwiftLauncher': False, 
            'ZwiftApp': False, 
            'caddy': False,
            'zoffline_local': False
        }
        
        # 使用subprocess运行PowerShell命令获取进程信息
        cmd = """
        Get-Process | Where-Object {
            $_.ProcessName -like 'ZwiftLauncher' -or 
            $_.ProcessName -like 'ZwiftApp' -or 
            $_.ProcessName -like 'caddy' -or
            $_.ProcessName -like 'zoffline_*'
        } | Select-Object ProcessName
        """
        result = subprocess.run(['powershell', '-Command', cmd], 
                                capture_output=True, 
                                text=True)
        
        # 检查每个进程是否在运行
        output = result.stdout.lower()
        processes['ZwiftLauncher'] = 'zwiftlauncher' in output
        processes['ZwiftApp'] = 'zwiftapp' in output
        processes['caddy'] = 'caddy' in output
        processes['zoffline_local'] = 'zoffline' in output
        
        return processes
    except Exception as e:
        print(f"检查进程状态时出错: {str(e)}")
        return None

def kill_processes():
    """终止所有Zwift相关进程"""
    try:
        cmd = """
        Get-Process | Where-Object {
            $_.ProcessName -like 'ZwiftLauncher' -or 
            $_.ProcessName -like 'ZwiftApp' -or 
            $_.ProcessName -like 'caddy' -or
            $_.ProcessName -like 'zoffline_*'
        } | ForEach-Object { 
            $processName = $_.ProcessName
            Stop-Process -Id $_.Id -Force
            Write-Output "已终止进程: $processName"
        }
        """
        result = subprocess.run(['powershell', '-Command', cmd], 
                            capture_output=True, 
                            text=True)
        return True
    except Exception as e:
        print(f"终止进程时出错: {str(e)}")
        return False

def select_certificates():
    """手动选择证书文件"""
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        root = tk.Tk()
        root.withdraw()  # 隐藏主窗口
        
        # 定义需要的证书文件
        cert_files = {
            "mixed-cert-zwift-com.pem": "由服务器提供的证书",
            "mixed-key-zwift-com.pem": "由服务器提供的密钥"
        }
        
        # 保存选择的文件路径
        config = {}
        
        print("请依次选择以下证书文件（Cert和Key）:")
        for file_name, desc in cert_files.items():
            print(f"\n正在选择{desc} ({file_name})")
            file_path = filedialog.askopenfilename(
                title=f"选择{desc}文件",
                filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")],
                initialdir=os.path.expanduser("~")
            )
            
            if not file_path:
                print(f"[错误] 未选择{desc}文件")
                return False
            
            # 简单验证文件
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # 检查是否包含PEM文件的基本特征
                    if "BEGIN" not in content or "END" not in content:
                        print(f"[错误] {file_path}文件格式不正确")
                        return False
                    # 根据文件类型进行特定验证
                    if "CERTIFICATE" in file_name.upper():
                        if "BEGIN CERTIFICATE" not in content:
                            print(f"[错误] {file_path}不是有效的证书文件")
                            return False
                    elif "KEY" in file_name.upper():
                        if "BEGIN PRIVATE KEY" not in content:
                            print(f"[错误] {file_path}不是有效的密钥文件")
                            return False
                
                # 保存文件路径到配置
                config[file_name] = file_path
                print(f"[成功] {file_path}文件基本格式验证通过")
                
            except Exception as e:
                print(f"[错误] 验证{file_path}文件失败: {str(e)}")
                return False
        
        # 保存配置到文件
        try:
            with open("certificates.conf", 'w', encoding='utf-8') as f:
                for name, path in config.items():
                    f.write(f"{name}={path}\n")
            print("\n证书配置已保存!")
        except Exception as e:
            print(f"[错误] 保存证书配置失败: {str(e)}")
            return False
            
        return True
        
    except Exception as e:
        print(f"[错误] 选择证书时出现异常: {str(e)}")
        return False

def run_caddy_server():
    """启动Caddy服务器"""
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # 定义需要的证书文件
        cert_files = {
            "mixed-cert-zwift-com.pem": "由服务器提供的证书",
            "mixed-key-zwift-com.pem": "由服务器提供的密钥"
        }
        
        # 检查证书配置文件
        config_file = "certificates.conf"
        if os.path.exists(config_file):
            # 从配置文件读取证书路径
            cert_paths = {}
            with open(config_file, 'r', encoding='utf-8') as f:
                for line in f:
                    name, path = line.strip().split('=', 1)
                    cert_paths[name] = path
            
            # 验证配置文件中的路径
            for file_name, desc in cert_files.items():
                if file_name not in cert_paths or not os.path.exists(cert_paths[file_name]):
                    print(f"[错误] 未找到{desc}文件: {cert_paths.get(file_name, '路径未配置')}")
                    return False
                else:
                    # 复制证书文件到当前工作目录
                    destination_path = os.path.join(current_dir, file_name)
                    if not os.path.exists(destination_path):
                        shutil.copy(cert_paths[file_name], destination_path)
                        print(f"[成功] 复制 {desc} 文件到当前工作目录: {destination_path}")

        else:
            # 检查本地证书文件
            for file_name, desc in cert_files.items():
                if not os.path.exists(os.path.join(current_dir, file_name)):
                    print(f"[错误] 未找到{desc}文件: {file_name}")
                    return False
        
        
        
        # 检查Caddy进程是否已在运行
        processes = check_processes()
        if processes and processes['caddy']:
            print("Caddy服务器已在运行")
            return True
            
        # 检查或获取服务器IP
        ip_file = "remote_server_ip.txt"
        if os.path.exists(ip_file):
            with open(ip_file, 'r', encoding='utf-8') as f:
                server_ip = f.read().strip()
        else:
            print("[错误] 未设置服务器IP地址")
            return False
            
        print(f"使用服务器IP: {server_ip}")
        
        # 检查caddy可执行文件
        caddy_exe = os.path.join(current_dir, "caddy.exe")
        if not os.path.exists(caddy_exe):
            print(f"[错误] 未找到Caddy可执行文件: {caddy_exe}\n如果你是从源码运行的，请手动下载 Caddy (https://caddyserver.com/download) 并重命名为 Caddy.exe，放置在项目根目录")
            return False

        # 设置环境变量
        my_env = os.environ.copy()
        my_env["ZWIFT_SERVER"] = server_ip

        # 启动Caddy服务器
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE

        process = subprocess.Popen(
            [caddy_exe, "run"],
            cwd=current_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW,
            env=my_env  # 使用修改后的环境变量
        )
        
        # 等待一小段时间确保进程启动
        time.sleep(1)
        
        # 检查是否成功启动
        if process.poll() is None:
            print("Caddy服务器已在后台启动")
            return True
        else:
            error_output = process.stderr.read().decode('utf-8')
            print(f"[错误] Caddy服务器启动失败: {error_output}")
            return False
            
    except Exception as e:
        print(f"[错误] 启动Caddy服务器时出现异常: {str(e)}")
        return False

def check_ports():
    """检查关键端口是否被占用"""
    try:
        ports = {
            80: "HTTP",
            443: "HTTPS",
            3024: "Zwift Game",
            3025: "Zwift Launcher"
        }
        
        # PowerShell命令检查端口占用
        cmd = """
        $ports = @(80, 443, 3024, 3025)
        foreach ($port in $ports) {
            $result = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
            if ($result) {
                $process = Get-Process -Id $result.OwningProcess -ErrorAction SilentlyContinue
                if ($process) {
                    Write-Output "$port|$($process.ProcessName)|$($process.Id)"
                }
            }
        }
        """
        
        result = subprocess.run(['powershell', '-Command', cmd],
                              capture_output=True,
                              text=True)
        
        occupied_ports = {}
        for line in result.stdout.strip().split('\n'):
            if line:
                port, process_name, pid = line.strip().split('|')
                occupied_ports[int(port)] = {
                    'process': process_name,
                    'pid': pid,
                    'description': ports[int(port)]
                }
        
        if occupied_ports:
            print("发现以下端口被占用:")
            for port, info in occupied_ports.items():
                print(f"端口 {port} ({info['description']}) 被进程 {info['process']} (PID: {info['pid']}) 占用")
            return occupied_ports
        else:
            print("所有必需端口都可用")
            return None
            
    except Exception as e:
        print(f"[错误] 检查端口时出现异常: {str(e)}")
        return None

def kill_port_processes():
    """终止占用关键端口的进程"""
    try:
        # 先检查端口占用情况
        occupied_ports = check_ports()
        if not occupied_ports:
            print("没有发现端口占用")
            return True

        pids = set(info['pid'] for info in occupied_ports.values())
        pid_list = ','.join(pids)
        
        cmd = f"""
        $processIds = @({pid_list})
        foreach ($processId in $processIds) {{
            $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
            if ($process) {{
                $processName = $process.ProcessName
                Stop-Process -Id $processId -Force
                Write-Output "已终止进程: $processName (PID: $processId)"
            }}
        }}
        """
        
        result = subprocess.run(['powershell', '-Command', cmd],
                              capture_output=True,
                              text=True)
        
        if result.returncode == 0:
            print("\n所有占用端口的进程已终止")
            # 再次检查确认端口已释放
            remaining = check_ports()
            if remaining:
                print("[警告] 某些端口仍然被占用，可能需要手动处理")
                return False
            return True
        else:
            print(f"[错误] 终止进程时出现问题: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"[错误] 终止端口占用进程时出现异常: {str(e)}")
        return False

def check_system_proxy():
    """检查系统代理设置"""
    try:
        # PowerShell命令获取代理设置
        cmd = """
        $proxy = Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'
        $enabled = $proxy.ProxyEnable
        $server = $proxy.ProxyServer
        Write-Output "$enabled|$server"
        """
        
        result = subprocess.run(['powershell', '-Command', cmd],
                              capture_output=True,
                              text=True)
        
        if result.returncode == 0:
            proxy_enabled, proxy_server = result.stdout.strip().split('|')
            proxy_enabled = proxy_enabled.strip() == '1'
            proxy_server = proxy_server.strip()
            
            if proxy_enabled:
                print(f"系统代理已启用，请关闭系统代理\n代理服务器: {proxy_server}")
                if (proxy_server == "127.0.0.1:7890"):
                    print("猜测你正在使用Clash小猫，请手动关闭Clash的系统代理")
                else:
                    print("[错误] 请手动关闭系统代码否则无法启动！")
                
                # 检查是否是本地代理
                if "127.0.0.1" in proxy_server:
                    print("当前使用本地代理")
                    return False
                else:
                    print("当前使用的不是本地代理")
                    return True
                
                return False
            else:
                print("系统代理未启用")
                return True
                
        else:
            print(f"[错误] 获取代理设置失败: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"[错误] 检查系统代理时出现异常: {str(e)}")
        return False

def cleanup_system():
    """清理系统设置，包括hosts文件和进程"""
    try:
        # 1. 清理hosts文件
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        try:
            # 读取当前hosts文件内容
            with open(hosts_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()

            # 过滤掉所有zwift.com相关的条目
            filtered_lines = [line for line in lines if 'zwift.com' not in line.lower()]

            # 写入更新后的内容
            with open(hosts_path, 'w', encoding='utf-8') as file:
                file.writelines(filtered_lines)
            print("已清理hosts文件中的Zwift相关条目")
        except Exception as e:
            print(f"[错误] 清理hosts文件失败: {str(e)}")
            return False

        # 2. 终止Caddy进程
        cmd = """
        Get-Process | Where-Object {$_.ProcessName -like 'caddy'} | 
        ForEach-Object { 
            $processName = $_.ProcessName
            Stop-Process -Id $_.Id -Force
            Write-Output "已终止进程: $processName"
        }
        """
        result = subprocess.run(['powershell', '-Command', cmd], 
                              capture_output=True, 
                              text=True)
        
        if result.returncode == 0:
            print("已终止Caddy进程")
        else:
            print("[警告] 终止Caddy进程时出现问题")

        # 3. 检查端口是否已释放
        occupied_ports = check_ports()
        if occupied_ports:
            print("[警告] 某些端口仍被占用，建议重启系统")
            return False

        print("系统清理完成")
        return True

    except Exception as e:
        print(f"[错误] 系统清理时出现异常: {str(e)}")
        return False

def check_zwift_version():
    """检查Zwift客户端和服务器版本"""
    try:
        # 检查zwift_location.txt文件
        if not os.path.exists("zwift_location.txt"):
            print("[错误] 未找到zwift_location.txt文件，请先运行初始化设置")
            return False
            
        # 读取Zwift安装路径
        with open("zwift_location.txt", 'r', encoding='utf-8') as f:
            zwift_path = f.read().strip().strip('"')
        
        with open(os.path.join(zwift_path, "Zwift_ver_cur_filename.txt"), 'r', encoding='utf-8') as f:
            local_version_file_name = f.read().strip().strip('"').rstrip('\x00')
            
        # 检查本地版本文件
        local_version_file = os.path.join(zwift_path, local_version_file_name)
        if not os.path.exists(local_version_file):
            print("[错误] 未找到本地版本文件")
            return False
            
        # 读取本地版本
        try:
            tree = ET.parse(local_version_file)
            root = tree.getroot()
            local_version = root.get('version')
            local_sversion = root.get('sversion')
            local_branch = root.get('gbranch')
        except Exception as e:
            print(f"[错误] 读取本地版本文件失败: {str(e)}")
            return False
            
        # 获取服务器版本
        try:
            response = requests.get(
                'https://cdn.zwift.com/gameassets/Zwift_Updates_Root/Zwift_ver_cur.xml',
                verify=False  # 忽略SSL证书验证
            )
            # 禁用 SSL 警告
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
            
            if response.status_code != 200:
                print("[错误] 连接服务器失败，请检查网络连接")
                return False
                
            server_root = ET.fromstring(response.text)
            server_version = server_root.get('version')
            server_sversion = server_root.get('sversion')
            server_branch = server_root.get('gbranch')
        except Exception as e:
            print(f"[错误] 获取服务器版本失败: {str(e)}")
            return False
            
        print("\n版本信息:")
        print("-" * 20)
        print(f"本地版本:")
        print(f"  - 版本号: {local_version}")
        print(f"  - 显示版本: {local_sversion}")
        print("服务器版本:")
        print(f"  - 版本号: {server_version}")
        print(f"  - 显示版本: {server_sversion}")
        print("-" * 20)
        
        if local_version < server_version:
            print("[警告] 本地版本低于服务器版本, 请点击从资源文件更新")
            return False
        elif local_version > server_version:
            print("[错误] 本地版本高于服务器版本，请联系服务器管理员更新，或记下服务器版本号，然后点击更新下载资源文件，将下载匹配的版本")
            return False
        else:
            print("[成功] 版本匹配！一切正常")
            return True
        
        
    except Exception as e:
        print(f"[错误] 检查版本时出现异常: {str(e)}")
        return False

def check_official_version():
    """清理网络配置"""
    cleanup_system()
    if check_zwift_version():
        pass
    else:
        print("[提示] 版本错误")
        return False

def check_community_version():
    """清理网络配置"""
    # 查找Zwift安装路径
    zwift_path = find_zwift_location()
    if zwift_path:
        if modify_hosts_file() and import_certificates() and import_client_certificates(zwift_path):
            print("所有设置都已完成")
        else:
            print("\n部分设置失败，请检查错误信息")
    else:
        print("Zwift安装位置未找到")
        
    # 终止现有进程
    if kill_processes():
        print("已终止所有相关进程")
    else:
        print("终止进程时出现错误")
    
    occupied_ports = check_ports()
    if not occupied_ports:
        pass
    else:
        print("端口检查失败，尝试手动关闭占用端口的程序")
        return False
        
    if check_system_proxy():
        pass
    else:
        print("系统代理检查失败，尝试手动关闭系统代理")
        return False
    
    # 启动Caddy服务器
    if not run_caddy_server():
        print("[错误] Caddy服务器启动失败")
        return False
        
    # 等待Caddy启动
    time.sleep(2)
    
    if test_community_connectivity():
        pass
    else:
        print("[错误] 社区服连通性测试失败")
        return False
    
    if check_zwift_version():
        pass
    else:
        print("[错误] 版本错误")
        return False
    
    return True

def get_application_path():
    """获取应用程序路径"""
    if getattr(sys, 'frozen', False):
        # 如果是打包后的exe运行
        return os.path.dirname(sys.executable)
    else:
        # 如果是脚本运行
        return os.path.dirname(os.path.abspath(__file__))
    
def check_local_versions():
    """查询本地版本库文件"""
    try:
        # current_dir = os.path.dirname(os.path.abspath(__file__))
        # versions_dir = os.path.join(current_dir, "zwift_ver_cur")
        app_path = get_application_path()
        versions_dir = os.path.join(app_path, "zwift_ver_cur")
        
        if not os.path.exists(versions_dir):
            print(f"[提示] 未找到版本库目录: {versions_dir}")
            return False
            
        # 获取所有版本文件夹
        version_folders = [d for d in os.listdir(versions_dir) 
                        if os.path.isdir(os.path.join(versions_dir, d))]
        
        if not version_folders:
            print("未找到任何版本文件")
            return False
            
        print("\n本地版本库文件列表:")
        print("-" * 30)
        for folder in sorted(version_folders):
            with open(os.path.join(versions_dir, folder, "Zwift_ver_cur_filename.txt"), 'r', encoding='utf-8') as f:
                local_version_file_name = f.read().strip().strip('"').rstrip('\x00')
                
            ver_file = os.path.join(versions_dir, folder, local_version_file_name)
            if os.path.exists(ver_file):
                try:
                    tree = ET.parse(ver_file)
                    root = tree.getroot()
                    version = root.get('version', 'Unknown')
                    sversion = root.get('sversion', 'Unknown')
                    print(f"文件夹: {folder}")
                    print(f"  - 版本号: {version}")
                    print(f"  - 显示版本: {sversion}")
                    print("-" * 40)
                except Exception as e:
                    print(f"[错误] 读取版本文件 {folder} 失败: {str(e)}")
            else:
                print(f"[警告] 文件夹 {folder} 中未找到 Zwift_ver_cur.xml")
                
        return True
        
    except Exception as e:
        print(f"[错误] 查询本地版本库时出现异常: {str(e)}")
        return False

def check_remote_server_status():
    """检查远程服务器状态"""
    try:
        # 读取服务器IP
        try:
            with open("remote_server_ip.txt", 'r', encoding='utf-8') as f:
                server_ip = f.read().strip()
        except FileNotFoundError:
            return False
            
        # 测试3025端口
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((server_ip, 3025))
        sock.close()
        
        return result == 0
        
    except Exception:
        return False

def test_direct_remote():
    """测试远程服务器的直接连接性"""
    try:
        # 读取服务器IP
        try:
            with open("remote_server_ip.txt", 'r', encoding='utf-8') as f:
                server_ip = f.read().strip()
        except FileNotFoundError:
            print("[错误] 未找到remote_server_ip.txt文件，请先设置服务器IP")
            return False

        print(f"正在测试与服务器 {server_ip} 的直接连接...")
        print("=" * 20)

        # 测试ping
        print(f"正在ping服务器 {server_ip}...")
        ping_result = subprocess.run(['ping', '-n', '2', server_ip], 
                                capture_output=True, 
                                text=True)
        
        if ping_result.returncode != 0:
            print(f"[错误] 无法ping通服务器 {server_ip}!")
            print("请检查网络连接和服务器可用性。")
            return False
            
        print("[成功] Ping测试通过")
        
        # 测试端口
        ports = [80, 443, 3025]
        test_failed = False
        
        print(f"正在测试服务器 {server_ip} 的端口:")
        for port in ports:
            # print(f"测试端口 {port}...")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((server_ip, port))
                sock.close()
                
                if result == 0:
                    print(f"端口 {port}: 连接成功")
                else:
                    print(f"端口 {port}: 连接失败")
                    test_failed = True
            except Exception as e:
                print(f"端口 {port}: 连接错误 - {str(e)}")
                test_failed = True
                
        if test_failed:
            print("[错误] 直接连接服务器测试失败!")
            print("请检查服务器是否正在运行且可访问。")
            return False
        else:
            print("[成功] 所有端口都可以访问!")
            # print("你现在可以进行最终测试了")
            return True
            
    except Exception as e:
        print(f"[错误] 测试远程连接时出现异常: {str(e)}")
        return False

def test_local_connectivity():
    """测试本地连通性和hosts文件配置"""
    try:
        # 检查hosts文件中的域名解析
        domains = [
            "us-or-rly101.zwift.com",
            "secure.zwift.com",
            "cdn.zwift.com",
            "launcher.zwift.com"
        ]
        
        print("正在测试本地连通性...")
        print("=" * 20)
        
        # 1. 检查hosts文件配置
        print("1. 检查hosts文件解析:")
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        with open(hosts_path, 'r', encoding='utf-8') as f:
            hosts_content = f.read().lower()
            
        hosts_ok = True
        for domain in domains:
            if f"127.0.0.1 {domain}" not in hosts_content.lower():
                print(f"[错误] {domain} 未在hosts文件中配置为127.0.0.1")
                hosts_ok = False
            else:
                print(f"[成功] {domain} 已正确配置")
                
        if not hosts_ok:
            print("[错误] hosts文件配置不完整，请运行初始化设置")
            
        # 2. 测试域名解析
        print("2. 测试域名解析:")
        import socket
        dns_ok = True
        for domain in domains:
            try:
                ip = socket.gethostbyname(domain)
                if ip == "127.0.0.1":
                    print(f"[成功] {domain} 解析到 127.0.0.1")
                else:
                    print(f"[错误] {domain} 解析到 {ip}，应为 127.0.0.1")
                    dns_ok = False
            except socket.gaierror:
                print(f"[错误] {domain} 解析失败")
                dns_ok = False
                
        # 3. 测试本地端口
        print("3. 测试本地端口:")
        ports = [80, 443, 3025]
        ports_ok = True
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            
            if result == 0:
                print(f"[成功] 端口 {port} 可访问")
            else:
                print(f"[错误] 端口 {port} 无法访问 请检查Caddy是否正常运行")
                ports_ok = False
                
        if hosts_ok and dns_ok and ports_ok:
            print("[成功] 所有测试通过！本地配置正常")
            return True
        else:
            print("[错误] 存在配置问题，请检查上述错误信息")
            return False
            
    except Exception as e:
        print(f"[错误] 测试过程中出现异常: {str(e)}")
        return False

def test_https_connectivity():
    """测试远程服务器的HTTP和HTTPS连接"""
    try:
        warnings.filterwarnings('ignore', category=InsecureRequestWarning)
        
        try:
            with open("remote_server_ip.txt", 'r', encoding='utf-8') as f:
                server_ip = f.read().strip()
        except FileNotFoundError:
            print("[错误] 未找到remote_server_ip.txt文件，请先设置服务器IP")
            return False

        print("测试远程Zwift服务器连接...")
        print("=" * 20)
        
        print("测试IP直连:")
        
        print("1. 测试HTTP via IP...")
        cmd = f"""powershell -Command "try {{ $response = Invoke-WebRequest -Uri ('http://{server_ip}/static/web/launcher/settings.html') -UseBasicParsing -TimeoutSec 2; Write-Host '[Success] HTTP via IP: Connected (Status: ' $response.StatusCode ')' }} catch {{ Write-Host '[Warning] HTTP via IP: ' $_.Exception.Message }}" """
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print(result.stdout.strip())

        print("2. 测试HTTPS via IP (忽略证书)...")
        try:
            response = requests.get(
                f'https://{server_ip}/static/web/launcher/settings.html',
                verify=False,
                timeout=2
            )
            print(f"[成功] HTTPS via IP (忽略证书): 已连接 (状态码: {response.status_code})")
        except Exception as e:
            print(f"[警告] HTTPS via IP (忽略证书): {str(e)}")

        print("3. 测试HTTPS via IP (验证证书)...")
        cmd = f"""powershell -Command "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null; try {{ $response = Invoke-WebRequest -Uri ('https://{server_ip}/static/web/launcher/settings.html') -UseBasicParsing -TimeoutSec 2; Write-Host '[Success] HTTPS via IP (verify cert): Connected (Status: ' $response.StatusCode ')' }} catch {{ Write-Host '[Notice] HTTPS via IP (verify cert): Certificate verification failed (Expected)' }}" """
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print(result.stdout.strip())

        print("测试域名连接:")
        
        print("4. 测试HTTP via domain...")
        cmd = """powershell -Command "try { $response = Invoke-WebRequest -Uri 'http://cdn.zwift.com/static/web/launcher/settings.html' -UseBasicParsing -TimeoutSec 2; Write-Host '[Success] HTTP via domain: Connected (Status: ' $response.StatusCode ')' } catch { Write-Host '[Warning] HTTP via domain: ' $_.Exception.Message }" """
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print(result.stdout.strip())

        print("5. 测试HTTPS via domain (忽略证书)...")
        try:
            response = requests.get(
                'https://cdn.zwift.com/static/web/launcher/settings.html',
                verify=False,
                timeout=2
            )
            print(f"[成功] HTTPS via domain (忽略证书): 已连接 (状态码: {response.status_code})")
        except Exception as e:
            print(f"[警告] HTTPS via domain (忽略证书): {str(e)}")

        print("6. 测试HTTPS via domain (验证证书)...")
        cmd = """powershell -Command "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null; try { $response = Invoke-WebRequest -Uri 'https://cdn.zwift.com/static/web/launcher/settings.html' -UseBasicParsing -TimeoutSec 2; Write-Host '[Success] HTTPS via domain (verify cert): Connected (Status: ' $response.StatusCode ')' } catch { Write-Host '[Notice] HTTPS via domain (verify cert): ' $_.Exception.Message }" """
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print(result.stdout.strip())

        return True

    except Exception as e:
        print(f"[错误] 测试远程连接时出现异常: {str(e)}")
        return False

def test_community_connectivity():
    """一键测试社区服连接"""
    print("开始全面连通性测试...")
    
    print("1. 测试远程服务器直连...")
    if not test_direct_remote():
        print("[错误] 远程服务器直连测试失败，停止后续测试")
        return False
    print("远程服务器直连测试通过")
    
    print("2. 测试本地配置...")
    if not test_local_connectivity():
        print("[错误] 本地配置测试失败，停止后续测试")
        return False
    print("本地配置测试通过")
    
    print("3. 测试HTTPS连接...")
    if not test_https_connectivity():
        print("[错误] HTTPS连接测试失败")
        return False
    print("HTTPS连接测试通过")
    
    print("[成功] 所有连通性测试通过！")
    return True

def force_update_version():
    """强制更新版本文件"""
    try:
        # 查找Zwift安装路径
        zwift_path = find_zwift_location()
        if not zwift_path:
            print("[错误] 未找到Zwift安装位置")
            return False
            
        # 检查本地版本库目录
        app_path = get_application_path()
        versions_dir = os.path.join(app_path, "zwift_ver_cur")
        
        if not os.path.exists(versions_dir):
            print(f"[错误] 未找到版本库目录: {versions_dir}")
            return False
            
        # 获取所有版本文件夹
        version_folders = [d for d in os.listdir(versions_dir) 
                        if os.path.isdir(os.path.join(versions_dir, d))]
        
        if not version_folders:
            print("[错误] 版本库为空")
            return False
            
        # 准备版本列表数据
        version_list = []
        for folder in sorted(version_folders):
            
            with open(os.path.join(versions_dir, folder, "Zwift_ver_cur_filename.txt"), 'r', encoding='utf-8') as f:
                local_version_file_name = f.read().strip().strip('"').rstrip('\x00')
                
            ver_file = os.path.join(versions_dir, folder, local_version_file_name)
            
            if os.path.exists(ver_file):
                try:
                    tree = ET.parse(ver_file)
                    root = tree.getroot()
                    version = root.get('version', 'Unknown')
                    sversion = root.get('sversion', 'Unknown')
                    version_list.append(f"{folder} (版本号: {version}, 显示版本: {sversion})")
                except Exception as e:
                    print(f"[警告] 读取版本文件 {folder} 失败: {str(e)}")
                    
        # 创建版本选择窗口
        layout = [
            [sg.Text("请选择要更新的版本:")],
            [sg.Listbox(values=version_list, size=(50, 10), key='-VERSION-')],
            [sg.Button('确定'), sg.Button('取消')]
        ]
        
        window = sg.Window('选择版本', layout)
        
        while True:
            event, values = window.read()
            
            if event in (sg.WIN_CLOSED, '取消'):
                window.close()
                return False
                
            if event == '确定':
                if not values['-VERSION-']:
                    sg.popup_error('请选择一个版本')
                    continue
                    
                selected_version = values['-VERSION-'][0]
                selected_folder = selected_version.split(' ')[0]
                break
                
        window.close()
        
        # 创建备份时间戳
        current_time = time.strftime("%Y%m%d_%H%M%S")
        
        # 需要复制的文件列表
        files_to_copy = [
            "Zwift_ver_cur.xml",
            "Zwift_ver_cur.*.xml",
            "Zwift_ver_cur_filename.txt",
            "Zwift_1.0.*_manifest.xml",
            "Zwift_0.0.0_manifest.xml"
        ]
        
        # 备份并复制每个文件
        for file_pattern in files_to_copy:
            # 在源文件夹中查找匹配的文件
            source_dir = os.path.join(versions_dir, selected_folder)
            matching_files = []
            for file in os.listdir(source_dir):
                if file_pattern == file or (file_pattern.endswith('*_manifest.xml') and '_manifest.xml' in file) or (file_pattern.endswith('*.xml') and 'Zwift_ver_cur' in file):
                    matching_files.append(file)
            
            # 复制找到的每个文件
            for file in matching_files:
                source_file = os.path.join(source_dir, file)
                target_file = os.path.join(zwift_path, file)
                backup_file = os.path.join(zwift_path, f"{file}.BACKUP_{current_time}")
                
                # 如果目标文件存在，创建备份
                if os.path.exists(target_file):
                    shutil.copy2(target_file, backup_file)
                    print(f"已创建备份: {backup_file}")
                
                # 复制新文件
                shutil.copy2(source_file, target_file)
                print(f"已更新文件: {file}")
        
        print(f"\n已完成版本 {selected_folder} 的所有文件更新")
        print("[提示] 请重启Zwift以应用更改")
        
        return True
        
    except Exception as e:
        print(f"[错误] 强制更新版本时出现异常: {str(e)}")
        return False

def check_server_type():
    """检测当前连接的是官方服务器还是社区服务器"""
    try:
        # 尝试不验证证书的请求
        response_no_verify = requests.get(
            'https://cdn.zwift.com/gameassets/Zwift_Updates_Root/Zwift_ver_cur.xml',
            verify=False
        )
        
        # 尝试验证证书的请求
        try:
            response_verify = requests.get(
                'https://cdn.zwift.com/gameassets/Zwift_Updates_Root/Zwift_ver_cur.xml',
                verify=True
            )
            # 如果验证证书的请求成功，说明是官服
            if response_verify.status_code == 200:
                print("[检测结果] 当前连接的是 Zwift 官方服务器")
                return "official"
        except requests.exceptions.SSLError:
            # 如果出现SSL错误，并且不验证证书的请求成功，说明是社区服
            if response_no_verify.status_code == 200:
                print("[检测结果] 当前连接的是社区服务器（自签名证书）")
                return "community"
        
        print("[错误] 无法确定服务器类型，请检查网络连接")
        return None

    except Exception as e:
        print(f"[错误] 检测服务器类型时出现异常: {str(e)}")
        return None

def launch_official_zwift():
    """一键启动官服"""
    try:
        # 查找Zwift安装路径
        zwift_path = find_zwift_location()
        if zwift_path:
            check_official_version()
        else:
            print("Zwift安装位置未找到")
            
        launcher_path = os.path.join(zwift_path, "ZwiftLauncher.exe")
        if not os.path.exists(launcher_path):
            print("[错误] 未找到ZwiftLauncher.exe")
            return False
            
        # 终止现有进程
        kill_processes()
        
        # 启动ZwiftLauncher
        print("正在启动ZwiftLauncher...")
        subprocess.Popen(launcher_path)
        print("[成功] ZwiftLauncher已启动")
        
        return True
        
    except Exception as e:
        print(f"[错误] 启动Zwift时出现异常: {str(e)}")
        return False

def update_download_files():
    """更新下载资源文件(手动)"""
    try:
        # 查找Zwift安装路径
        zwift_path = find_zwift_location()
        if zwift_path:
            check_community_version()
        else:
            print("Zwift安装位置未找到")
            return False
        
        cleanup_system()

        # 弹出输入窗口
        version_layout = [
            [sg.Text("请输入版本号 (例如: 138816):")],
            [sg.Input(key='-VERSION-')],
            [sg.Button('确定'), sg.Button('取消')]
        ]
        version_window = sg.Window('输入版本号', version_layout)
        
        while True:
            event, values = version_window.read()
            if event in (None, '取消'):
                version_window.close()
                return False
            if event == '确定':
                version = values['-VERSION-'].strip()
                if version:
                    version_window.close()
                    # 创建下载进度窗口
                    progress_layout = [
                        [sg.Text('正在下载资源文件...(99%请耐心等待)')],
                        [sg.ProgressBar(100, orientation='h', size=(20, 20), key='-PROGRESS-')],
                        [sg.Text('', key='-STATUS-')],
                        [sg.Button('取消下载')]
                    ]
                    progress_window = sg.Window('下载进度', progress_layout, finalize=True)
                    
                    # 创建一个事件来控制下载线程
                    cancel_event = threading.Event()
                    
                    # 创建下载线程
                    download_thread = threading.Thread(
                        target=download_zwift_version,
                        args=(zwift_path, version, progress_window, cancel_event)
                    )
                    download_thread.start()
                    
                    # 监听进度窗口事件
                    while True:
                        event, _ = progress_window.read(timeout=100)
                        if event in (None, '取消下载'):
                            cancel_event.set()  # 通知下载线程取消
                            print("正在取消下载...")
                            download_thread.join()  # 等待下载线程结束
                            break
                        
                        # 如果下载线程已结束，关闭窗口
                        if not download_thread.is_alive():
                            break
                    
                    progress_window.close()
                    break
                else:
                    sg.popup_error('请输入有效的版本号')

        return True
        
    except Exception as e:
        print(f"[错误] 更新资源文件时出现异常: {str(e)}")
        return False

def download_zwift_version(local_path, version, progress_window=None, cancel_event=None):
    """下载指定版本的Zwift资源文件"""
    try:
        system = platform.system()
        if system == 'Windows':
            file = f'Zwift_ver_cur.{version}.xml'
        elif system == 'Darwin':
            file = f'ZwiftMac_ver_cur.{version}.xml'
        else:
            print("Unsupported platform: %s" % system)
            return

        base_url = 'http://cdn.zwift.com/gameassets/Zwift_Updates_Root/'

        # 下载版本文件
        response = PoolManager().request('GET', base_url + file)
        with open(os.path.join(local_path, file), 'wb') as f:
            f.write(response.data)

        # 解析版本文件获取manifest
        tree = ET.parse(os.path.join(local_path, file))
        root = tree.getroot()
        manifest = root.get('manifest')
        manifest_checksum = int(root.get('manifest_checksum')) % (1 << 32)
        manifest_file = os.path.join(local_path, manifest)

        # 下载manifest文件
        while not os.path.isfile(manifest_file) or crc32(open(manifest_file, 'rb').read()) != manifest_checksum:
            response = PoolManager().request('GET', base_url + manifest)
            with open(manifest_file, 'wb') as f:
                f.write(response.data)

        # 解析manifest获取文件列表
        tree = ET.parse(manifest_file)
        root = tree.getroot()
        folder = root.get('folder')
        all_files = list(root.iter('file'))
        total = len(all_files)
        downloaded = 0

        print(f"开始下载 {manifest} 中的文件")
        
        # 创建下载线程池
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            
            # 提交所有下载任务
            for file_info in all_files:
                if cancel_event and cancel_event.is_set():
                    print("\n下载已取消")
                    return
                    
                path = file_info.find('path').text
                length = int(file_info.find('length').text)
                checksum = int(file_info.find('checksum').text) % (1 << 32)
                
                future = executor.submit(
                    download_single_file,
                    base_url, folder, path, length, checksum, local_path
                )
                futures.append(future)
            
            # 更新进度
            for future in as_completed(futures):
                if cancel_event and cancel_event.is_set():
                    executor.shutdown(wait=False)
                    print("\n下载已取消")
                    return
                    
                downloaded += 1
                progress = (downloaded * 100) // total
                
                if progress_window:
                    progress_window['-PROGRESS-'].update(progress)
                    progress_window['-STATUS-'].update(f'进度: {progress}% ({downloaded}/{total})')
                else:
                    print(f'\r进度: {progress}% ({downloaded}/{total})', end='', flush=True)
        
        # 更新版本文件名
        with open(os.path.join(local_path, 'Zwift_ver_cur_filename.txt'), 'w') as f:
            f.write(file)

        print("\n下载完成!")

    except Exception as e:
        print(f"\n[错误] 下载过程中出现异常: {str(e)}")

def download_single_file(base_url, folder, path, length, checksum, local_path):
    """下载单个文件"""
    file_name = os.path.join(local_path, path.replace('\\', os.sep))
    dir_name = os.path.dirname(file_name)
    
    # 创建目录
    if not os.path.isdir(dir_name):
        os.makedirs(dir_name, exist_ok=True)
    
    # 下载文件直到校验和匹配
    while not os.path.isfile(file_name) or os.path.getsize(file_name) != length or (crc32(open(file_name, 'rb').read()) != checksum and checksum != 4294967295):
        response = PoolManager().request('GET', f'{base_url}{folder}/{path.replace("\\", "/")}')
        with open(file_name, 'wb') as f:
            f.write(response.data)

def launch_community_zwift():
    """一键启动社区服"""
    try:
        if not check_community_version():
            return False
        
        zwift_path = find_zwift_location()
    
        # # 新增逻辑: 查找所有 Zwift_ver_cur.xxxxxx.xml 文件
        # version_files = []
        # for file in os.listdir(zwift_path):
        #     if file.startswith("Zwift_ver_cur.") and file.endswith(".xml"):
        #         parts = file.split(".")
        #         print(parts)
        #         if len(parts) == 3 and parts[1].isdigit():
        #             version_number = int(parts[1])
        #             print(version_number)
        #             version_files.append((file, version_number))
        
        # if not version_files:
        #     print("[错误] 未找到任何 Zwift_ver_cur.xxxxxx.xml 文件，如果你的版本是1.80.0，请先更新，换用新的逻辑")
        #     return False
        
        # # 选择最高版本号的文件
        # version_files.sort(key=lambda x: x[1], reverse=True)
        # selected_file, selected_version = version_files[0]
        # print(f"选择的版本文件: {selected_file} (版本号: {selected_version})")
        
        # # 复制选择的文件为 Zwift_ver_cur.xml
        # source_xml = os.path.join(zwift_path, selected_file)
        # target_xml = os.path.join(zwift_path, "Zwift_ver_cur.xml")
        # shutil.copy2(source_xml, target_xml)
        # print(f"已复制 {selected_file} 为 Zwift_ver_cur.xml")
        
        # # 更新 Zwift_ver_cur_filename.txt
        # version_file_path = os.path.join(zwift_path, "Zwift_ver_cur_filename.txt")
        # with open(version_file_path, 'w', encoding='utf-8') as f:
        #     # f.write(f'{selected_file}')
        #     f.write('Zwift_ver_cur.xml')
        # print(f"已更新 Zwift_ver_cur_filename.txt 为: {selected_file}")
        
        # 启动ZwiftLauncher
        launcher_path = os.path.join(zwift_path, "ZwiftLauncher.exe")
        if not os.path.exists(launcher_path):
            print("[错误] 未找到ZwiftLauncher.exe")
            return False
        print("正在启动ZwiftLauncher...")
        subprocess.Popen(launcher_path)
        print("[成功] ZwiftLauncher已启动")

        return True
        
    except Exception as e:
        print(f"[错误] 启动Zwift时出现异常: {str(e)}")
        return False

def main():
    # 检查管理员权限
    if not is_admin():
        print("请求管理员权限...")
        run_as_admin()
        sys.exit()

    window = create_main_window()
    last_check_time = 0
    
    # 事件循环
    while True:
        try:
            event, values = window.read(timeout=2000)  # 设置超时为2秒
            
            # 处理窗口关闭事件
            if event in ('退出', '文件(&F)退出'):
                kill_processes()
                break
                
            # 更新进程状态
            processes = check_processes()
            if processes and window:  # 确保窗口仍然存在
                window['-LAUNCHER-STATUS-'].update("●", text_color='green' if processes['ZwiftLauncher'] else 'red')
                window['-APP-STATUS-'].update("●", text_color='green' if processes['ZwiftApp'] else 'red')
                window['-CADDY-STATUS-'].update("●", text_color='green' if processes['caddy'] else 'red')
                window['-ZOFFLINE-STATUS-'].update("●", text_color='green' if processes['zoffline_local'] else 'red')
            
            if event is None:  # 超时事件
                continue
                
            # 处理按钮事件时才清空输出
            if event != sg.TIMEOUT_EVENT:
                window['-OUTPUT-'].update('')  # 只在有实际事件发生时清空输出
            
            # 处理按钮事件
            if event == "重置网络属性":
                print("执行重置网络属性操作...")

            elif event == "返回官服":
                check_official_version()
                print("现在你可以自行启动官方了")
                
            elif event == "查询客户版本":
                check_zwift_version()
                print("执行查询客户版本操作...")
                
            elif event == "初始化设置":
                print("执行初始化设置操作...")
                zwift_path = find_zwift_location()
                if zwift_path:
                    if modify_hosts_file() and import_certificates() and import_client_certificates(zwift_path):
                        print("\n所有设置都已完成")
                    else:
                        print("\n部分设置失败，请检查错误信息")
                else:
                    print("Zwift安装位置未找到")

            
            elif event == "一键启动社区服Zwift":
                launch_community_zwift()
            
            # elif event == "更新下载资源文件(自动)":
            #     # update_download_files_auto()
            #     print("自动更新下载资源文件暂时失效，请不要使用")

            elif event == "更新下载资源文件(手动)":
                update_download_files()
                
            elif event == "一键启动官服Zwift":
                launch_official_zwift()
                

            elif event == "一键测试连通性":
                test_community_connectivity()

            
            elif event == "终止所有进程":
                if kill_processes():
                    if cleanup_system():
                        print("已终止所有相关进程并清理网络配置")
                    else:
                        print("网络配置清理失败")
                else:
                    print("终止进程时出现错误")
                    
            elif event == "清理网络配置":
                cleanup_system()
                
            elif event == "保存IP":
                ip = values['-SERVER-IP-'].strip()
                if ip:
                    with open("remote_server_ip.txt", 'w', encoding='utf-8') as f:
                        f.write(ip)
                    print(f"已保存服务器IP: {ip}")
                else:
                    print("请输入有效的IP地址")
            
            elif event == "导入Host设置":
                modify_hosts_file()
            
            elif event == "自动导入系统证书":
                import_certificates()
            
            elif event == "自动导入客户端证书":
                zwift_path = find_zwift_location()
                if zwift_path:
                    import_client_certificates(zwift_path)
                else:
                    print("Zwift安装位置未找到")
            
            elif event == "启动Caddy后台":
                if run_caddy_server():
                    print("Caddy服务器启动成功")
                else:
                    print("Caddy服务器启动失败")
                    
            elif event == "查询内置版本库":
                check_local_versions()
                
            elif event == "强制\"更新\"版本":
                force_update_version()
                
            elif event == "检查系统代理":
                check_system_proxy()

            
            elif event == "检查端口占用":
                check_ports()
                
            elif event == "强行终止端口占用":
                if sg.popup_yes_no("警告", 
                                "这是一个危险操作，请先用检查端口仔细检查目前占用端口的进程有无重要进程。\n确定要继续吗？",
                                title="确认操作",
                                button_color=("white", "red")) == "Yes":
                    kill_port_processes()
                else:
                    print("操作已取消")
                    
            elif event == "查询官服版本":
                check_official_version()
                print("查询官方版本有概率失效，主要是官服的接口有可能忘记更新，请查阅")
                # print("查询官服版本暂时失效，请不要使用")

            
            elif event == "查询社区服版本":
                check_community_version()

            elif event == "远程端口测试":
                test_direct_remote()
                
            elif event == "本地host和caddy测试":
                test_local_connectivity()
                
            elif event == "社区服HTTPS测试":
                test_https_connectivity()
                
            elif event == "手动选择证书":
                select_certificates()
                
            elif event == "使用说明":
                sg.popup('使用说明', 
                         '1. 设置服务器IP\n' + 
                         '2. 导入证书和配置\n' + 
                         '3. 选择启动模式\n' + 
                         '4. 根据需要使用高级功能',
                         title='使用说明')
            elif event == "关于":
                about_layout = [
                    [sg.Text('Zoffline-CN Tool', font=('Helvetica', 16))],
                    [sg.Text('版本: 1.0.0')],
                    [sg.Text('作者: kanhao100')],
                    [sg.Text('GitHub: '), sg.Text('https://github.com/kanhao100/zoffline-cn-tool', 
                            text_color='blue', enable_events=True, key='-GITHUB-LINK-')],
                    [sg.Text('如果这个功能帮助你，请给个star鼓励一下作者')],
                    [sg.Button('确定')]
                ]
                
                about_window = sg.Window('关于', about_layout, modal=True, finalize=True)
                
                while True:
                    about_event, about_values = about_window.read()
                    if about_event in (None, '确定'):
                        break
                    elif about_event == '-GITHUB-LINK-':
                        import webbrowser
                        webbrowser.open('https://github.com/kanhao100/zoffline-cn-tool')
                
                about_window.close()
                
        except Exception as e:
            break  # 发生异常时直接退出循环
    
    if window:
        window.close()

if __name__ == "__main__":
    main()