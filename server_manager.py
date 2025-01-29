import json
import time
import socket
import tkinter as tk
from tkinter import filedialog
import os
import FreeSimpleGUI as sg

from language_manager import LanguageManager
# 创建语言管理器实例
lang_mgr = LanguageManager()

def create_server_list_window():
    """创建服务器列表窗口"""
    layout = [
        [sg.Text(lang_mgr.get_text('server_settings'), font=("Helvetica", 12))],
        [sg.Table(values=[['127.0.0.1', '0ms', '0', 'Local Server']],
                 headings=['IP', 'Latency', 'Players', 'Note'],
                 auto_size_columns=False,
                 col_widths=[15, 8, 8, 20],
                 justification='left',
                 num_rows=10,
                 key='-SERVER-TABLE-',
                 enable_events=True,
                 enable_click_events=True,
                 right_click_menu=['&Right', ['Edit Note', 'Delete']])],
        [sg.Input(key='-NEW-SERVER-IP-', size=(15,1)), 
         sg.Button(lang_mgr.get_text('add_server'), size=(10,1)),
         sg.Button(lang_mgr.get_text('test_servers'), size=(15,1))],
        [sg.Button(lang_mgr.get_text('close'), size=(10,1))]
    ]
    
    window = sg.Window(lang_mgr.get_text('server_settings'), layout, modal=True, finalize=True)
    
    # 加载服务器列表
    servers = load_servers()
    table_data = [[s['ip'], s['latency'], s['players'], s['note']] for s in servers]
    window['-SERVER-TABLE-'].update(values=table_data)
    
    return window



def handle_server_list_window(main_window):
    """处理服务器列表窗口"""
    server_window = create_server_list_window()
    
    while True:
        event, values = server_window.read()
        
        if event in (None, lang_mgr.get_text('close')):
            break
            
        # 处理服务器表格事件
        if isinstance(event, tuple):
            if event[0] == '-SERVER-TABLE-':
                # 检查是否是有效的点击事件
                try:
                    row_clicked = event[2][0]
                    col_clicked = event[2][1]
                    # 确保点击了有效行且不是表头
                    if row_clicked >= 0 and col_clicked >= 0:
                        servers = load_servers()
                        if row_clicked < len(servers):  # 确保点击的行在有效范围内
                            if col_clicked == 3:  # 点击备注列
                                edit_server_note(server_window, row_clicked)
                            else:  # 选择服务器
                                selected_server = servers[row_clicked]
                                # 更新主窗口显示的当前服务器
                                main_window['-CURRENT-SERVER-'].update(selected_server['ip'])
                                # 保存到remote_server_ip.txt
                                with open("remote_server_ip.txt", 'w', encoding='utf-8') as f:
                                    f.write(selected_server['ip'])
                                    
                                # 创建证书文件
                                if 'cert' in selected_server and 'key' in selected_server:
                                    try:
                                        with open("mixed-cert-zwift-com.pem", 'w', encoding='utf-8') as f:
                                            f.write(selected_server['cert'])
                                        with open("mixed-key-zwift-com.pem", 'w', encoding='utf-8') as f:
                                            f.write(selected_server['key'])
                                        print("已更新证书文件")
                                    except Exception as e:
                                        print(f"更新证书文件失败: {str(e)}")
                                        
                                print(lang_mgr.get_text('server_selected').format(selected_server['ip']))
                except (IndexError, TypeError):
                    # 忽略无效的点击事件
                    pass
        
        # 处理右键菜单事件
        if event == 'Edit Note':
            if len(values['-SERVER-TABLE-']) > 0:
                row_index = values['-SERVER-TABLE-'][0]
                edit_server_note(server_window, row_index)
        elif event == 'Delete':
            if len(values['-SERVER-TABLE-']) > 0:
                row_index = values['-SERVER-TABLE-'][0]
                delete_server(server_window, row_index)
        
        # 处理服务器管理按钮
        elif event == lang_mgr.get_text('add_server'):
            add_server(server_window, values['-NEW-SERVER-IP-'])
        
        elif event == lang_mgr.get_text('test_servers'):
            update_server_status(server_window)
    
    server_window.close()

def load_servers():
    """加载服务器列表"""
    try:
        if os.path.exists('servers.json'):
            with open('servers.json', 'r', encoding='utf-8') as f:
                servers = json.load(f)
        else:
            # 读取默认证书和密钥
            try:
                with open("cert-zwift-com.pem", 'r', encoding='utf-8') as f:
                    default_cert = f.read()
                with open("key-zwift-com.pem", 'r', encoding='utf-8') as f:
                    default_key = f.read()
            except Exception:
                default_cert = ""
                default_key = ""
                
            servers = [{
                'ip': '127.0.0.1',
                'latency': '0ms',
                'players': '0',
                'note': 'Local Server',
                'cert': default_cert,
                'key': default_key
            }]
        return servers
    except Exception as e:
        print(f"加载服务器列表失败: {str(e)}")
        # 读取默认证书和密钥
        try:
            with open("mixed-cert-zwift-com.pem", 'r', encoding='utf-8') as f:
                default_cert = f.read()
            with open("mixed-key-zwift-com.pem", 'r', encoding='utf-8') as f:
                default_key = f.read()
        except Exception:
            default_cert = ""
            default_key = ""
            
        return [{
            'ip': '127.0.0.1',
            'latency': '0ms',
            'players': '0',
            'note': 'Local Server',
            'cert': default_cert,
            'key': default_key
        }]

def save_servers(servers):
    """保存服务器列表"""
    try:
        with open('servers.json', 'w', encoding='utf-8') as f:
            json.dump(servers, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"保存服务器列表失败: {str(e)}")
        return False

def test_server_latency(ip):
    """测试服务器延迟"""
    try:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, 3025))
        sock.close()
        if result == 0:
            latency = int((time.time() - start_time) * 1000)
            return f"{latency}ms"
        return "Timeout"
    except Exception:
        return "Error"

def check_server_players(ip):
    """检查服务器在线人数"""
    try:
        # 这里需要实现实际的在线人数检查逻辑
        # 暂时返回模拟数据
        return "0"
    except Exception:
        return "Error"

def update_server_status(window):
    """更新所有服务器状态"""
    try:
        servers = load_servers()
        updated_servers = []
        for server in servers:
            latency = test_server_latency(server['ip'])
            players = check_server_players(server['ip'])
            updated_servers.append({
                'ip': server['ip'],
                'latency': latency,
                'players': players,
                'note': server['note']
            })
        
        # 更新表格
        table_data = [[s['ip'], s['latency'], s['players'], s['note']] for s in updated_servers]
        window['-SERVER-TABLE-'].update(values=table_data)
        save_servers(updated_servers)
        return True
    except Exception as e:
        print(f"更新服务器状态失败: {str(e)}")
        return False

def edit_server_note(window, row_index):
    """编辑服务器备注"""
    try:
        servers = load_servers()
        if 0 <= row_index < len(servers):
            current_note = servers[row_index]['note']
            new_note = sg.popup_get_text('编辑备注', default_text=current_note)
            if new_note is not None:
                servers[row_index]['note'] = new_note
                save_servers(servers)
                # 更新表格
                table_data = [[s['ip'], s['latency'], s['players'], s['note']] for s in servers]
                window['-SERVER-TABLE-'].update(values=table_data)
    except Exception as e:
        print(f"编辑备注失败: {str(e)}")

def add_server(window, ip):
    """添加新服务器"""
    try:
        if not ip:
            print("请输入服务器IP")
            return False
            
        servers = load_servers()
        if any(s['ip'] == ip for s in servers):
            print("服务器已存在")
            return False
            
        # 选择证书文件
        root = tk.Tk()
        root.withdraw()
        
        print("\n请选择证书文件 (mixed-cert-zwift-com.pem):")
        cert_path = filedialog.askopenfilename(
            title="选择证书文件",
            filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")],
            initialdir=os.path.expanduser("~")
        )
        
        if not cert_path:
            print("未选择证书文件")
            return False
            
        print("\n请选择密钥文件 (mixed-key-zwift-com.pem):")
        key_path = filedialog.askopenfilename(
            title="选择密钥文件",
            filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")],
            initialdir=os.path.dirname(cert_path)
        )
        
        if not key_path:
            print("未选择密钥文件")
            return False
            
        # 读取证书和密钥文件内容
        try:
            with open(cert_path, 'r', encoding='utf-8') as f:
                cert_content = f.read()
            with open(key_path, 'r', encoding='utf-8') as f:
                key_content = f.read()
        except Exception as e:
            print(f"读取证书文件失败: {str(e)}")
            return False
            
        latency = test_server_latency(ip)
        players = check_server_players(ip)
        
        servers.append({
            'ip': ip,
            'latency': latency,
            'players': players,
            'note': 'New Server',
            'cert': cert_content,
            'key': key_content
        })
        
        save_servers(servers)
        table_data = [[s['ip'], s['latency'], s['players'], s['note']] for s in servers]
        window['-SERVER-TABLE-'].update(values=table_data)
        window['-NEW-SERVER-IP-'].update('')
        print("服务器添加成功")
        return True
    except Exception as e:
        print(f"添加服务器失败: {str(e)}")
        return False

def delete_server(window, row_index):
    """删除服务器"""
    try:
        servers = load_servers()
        if 0 <= row_index < len(servers):
            if servers[row_index]['ip'] == '127.0.0.1':
                print("无法删除本地服务器")
                return False
            del servers[row_index]
            save_servers(servers)
            table_data = [[s['ip'], s['latency'], s['players'], s['note']] for s in servers]
            window['-SERVER-TABLE-'].update(values=table_data)
            return True
    except Exception as e:
        print(f"删除服务器失败: {str(e)}")
        return False
