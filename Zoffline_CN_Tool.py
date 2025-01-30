from language_manager import LanguageManager
from Zoffline_CN_Tool_Lib import *
from server_manager import *

# 创建语言管理器实例
lang_mgr = LanguageManager()

def create_main_window():
    """创建主窗口"""
    sg.theme('LightGrey1')
    
    # 添加菜单栏
    menu_def = [
        [lang_mgr.get_text('menu_file'), [lang_mgr.get_text('menu_save_config'), 
                                         lang_mgr.get_text('menu_reload_config'), 
                                         '---', 
                                         lang_mgr.get_text('menu_exit')]],
        [lang_mgr.get_text('menu_tools'), [lang_mgr.get_text('select_cert'),
                                          lang_mgr.get_text('import_host'),
                                          lang_mgr.get_text('import_sys_cert'),
                                          lang_mgr.get_text('import_client_cert'),
                                          lang_mgr.get_text('start_caddy'),
                                          '---',
                                          lang_mgr.get_text('download_local_server'),
                                          lang_mgr.get_text('start_local_server'),
                                          '---',
                                          lang_mgr.get_text('check_proxy'),
                                          lang_mgr.get_text('check_ports'),
                                          lang_mgr.get_text('kill_ports'),
                                          lang_mgr.get_text('clean_network'),
                                          lang_mgr.get_text('kill_all')]],
        [lang_mgr.get_text('menu_version'), [lang_mgr.get_text('check_official_ver'), 
                                            lang_mgr.get_text('check_community_ver'), 
                                            lang_mgr.get_text('check_local_ver'),
                                            lang_mgr.get_text('force_update')]],
        [lang_mgr.get_text('menu_test'), [lang_mgr.get_text('test_remote'), 
                                         lang_mgr.get_text('test_local'), 
                                         lang_mgr.get_text('test_https'), 
                                         lang_mgr.get_text('test_connectivity')]],
        ['Language/语言', lang_mgr.get_available_languages()],
        [lang_mgr.get_text('menu_help'), [lang_mgr.get_text('menu_usage'), 
                                         lang_mgr.get_text('menu_about')]]
    ]
    
    # 状态面板布局
    status_layout = [
        [sg.Text(lang_mgr.get_text('process_status'), font=("Helvetica", 12))],
        [sg.Text(lang_mgr.get_text('launcher_status'), size=(12,1)), 
        sg.Text("●", text_color='red', key='-LAUNCHER-STATUS-')],
        [sg.Text(lang_mgr.get_text('app_status'), size=(12,1)), 
        sg.Text("●", text_color='red', key='-APP-STATUS-')],
        [sg.Text(lang_mgr.get_text('caddy_status'), size=(12,1)), 
        sg.Text("●", text_color='red', key='-CADDY-STATUS-')],
        [sg.Text(lang_mgr.get_text('zoffline_status'), size=(12,1)), 
        sg.Text("●", text_color='red', key='-ZOFFLINE-STATUS-')]
    ]
    
    # 服务器设置布局
    server_layout = [
        [sg.Text(lang_mgr.get_text('current_server'), size=(12,1)),
         sg.Text("127.0.0.1", key='-CURRENT-SERVER-')],
        [sg.Button(lang_mgr.get_text('manage_servers'), size=(15,1))]
    ]
    
    # 主要按钮布局
    main_layout = [
        [sg.Frame(lang_mgr.get_text('main_functions'), [
            [sg.Button(lang_mgr.get_text('launch_community'), size=(24, 5), button_color=('white', '#FF6347'))],
            [sg.Button(lang_mgr.get_text('launch_official'), size=(24, 2))],
            [sg.Button(lang_mgr.get_text('update_resources'), size=(24, 2))]
        ], pad=(10, 5))]
    ]
    
    # 完整布局，添加菜单栏
    layout = [
        [sg.Menu(menu_def)],  # 添加菜单栏
        [sg.Text(lang_mgr.get_text('window_title'), font=("Helvetica", 20), justification='center', pad=(0, 10))],
        [sg.Column(status_layout, vertical_alignment='top'),
         sg.VerticalSeparator(pad=(10,0)),
         sg.Column(server_layout + main_layout, vertical_alignment='top')],
        [sg.Output(size=(80, 10), pad=(10, 5), key='-OUTPUT-')],
        [
            sg.Button(lang_mgr.get_text('exit'), size=(15, 1)),
            sg.Button(lang_mgr.get_text('kill_all'), size=(15, 1)),
            sg.Button(lang_mgr.get_text('clean_network'), size=(15, 1))
        ],
        [
            sg.Text('https://github.com/kanhao100/zoffline-cn-tool', text_color='blue', enable_events=True, key='-GITHUB-LINK-'),
            sg.Push(),
            sg.Text('东南大学猎风车队|南京高校联队', pad=(10, 5))
        ]
    ]
    
    return sg.Window(lang_mgr.get_text('window_title'), layout, finalize=True)

def main():
    # 检查管理员权限
    if not is_admin():
        print("请求管理员权限...")
        run_as_admin()
        sys.exit()

    # 显示版权声明
    show_copyright_notice()

    window = create_main_window()
    last_check_time = 0
    window_active = True  # 添加一个标志来跟踪窗口状态
    
    # 加载当前服务器
    try:
        with open("remote_server_ip.txt", 'r', encoding='utf-8') as f:
            current_server = f.read().strip()
            window['-CURRENT-SERVER-'].update(current_server)
    except:
        pass
    
    # 事件循环
    while True:
        try:
            event, values = window.read(timeout=2000)  # 设置超时为2秒
            
            # 处理窗口关闭事件
            if event in (None, lang_mgr.get_text('exit'), f"{lang_mgr.get_text('menu_file')}退出"):
                window_active = False  # 设置标志表示窗口即将关闭
                kill_processes()
                break
                
            # 处理语言切换
            if event in lang_mgr.get_available_languages():
                if event != lang_mgr.current_language:
                    lang_mgr.set_language(event)
                    window.close()
                    window = create_main_window()
                    # 重新加载当前服务器
                    try:
                        with open("remote_server_ip.txt", 'r', encoding='utf-8') as f:
                            current_server = f.read().strip()
                            window['-CURRENT-SERVER-'].update(current_server)
                    except:
                        pass
                    continue
            
            # 处理服务器管理按钮
            elif event == lang_mgr.get_text('manage_servers'):
                handle_server_list_window(window)
                
            # 处理服务器表格事件
            if isinstance(event, tuple):
                if event[0] == '-SERVER-TABLE-':
                    if event[2][1] != -1:  # 确保点击了有效行
                        row_clicked = event[2][0]
                        if event[2][1] == 3:  # 点击备注列
                            edit_server_note(window, row_clicked)
            
            # 处理右键菜单事件
            if event == 'Edit Note':
                if len(values['-SERVER-TABLE-']) > 0:
                    row_index = values['-SERVER-TABLE-'][0]
                    edit_server_note(window, row_index)
            elif event == 'Delete':
                if len(values['-SERVER-TABLE-']) > 0:
                    row_index = values['-SERVER-TABLE-'][0]
                    delete_server(window, row_index)
            
            # 处理服务器管理按钮
            elif event == lang_mgr.get_text('add_server'):
                add_server(window, values['-NEW-SERVER-IP-'])
            
            elif event == lang_mgr.get_text('test_servers'):
                update_server_status(window)
                
            # 只在窗口活动时更新进程状态
            if window_active:
                processes = check_processes()
                if processes and window:  # 确保窗口仍然存在
                    try:
                        window['-LAUNCHER-STATUS-'].update("●", text_color='green' if processes['ZwiftLauncher'] else 'red')
                        window['-APP-STATUS-'].update("●", text_color='green' if processes['ZwiftApp'] else 'red')
                        window['-CADDY-STATUS-'].update("●", text_color='green' if processes['caddy'] else 'red')
                        window['-ZOFFLINE-STATUS-'].update("●", text_color='green' if processes['zoffline_local'] else 'red')
                    except Exception:
                        # 忽略更新状态时的错误
                        pass
            
            if event is None:  # 超时事件
                continue
                
            # 处理按钮事件时才清空输出
            if event != sg.TIMEOUT_EVENT:
                window['-OUTPUT-'].update('')  # 只在有实际事件发生时清空输出
            
            # 处理按钮事件
            if event == lang_mgr.get_text('launch_community'):
                launch_community_zwift()
            
            elif event == lang_mgr.get_text('launch_official'):
                launch_official_zwift()

            elif event == lang_mgr.get_text('update_resources'):
                update_download_files()
                
            elif event == lang_mgr.get_text('select_cert'):
                select_certificates()
            
            elif event == lang_mgr.get_text('import_host'):
                modify_hosts_file()
            
            elif event == lang_mgr.get_text('import_sys_cert'):
                import_certificates()
            
            elif event == lang_mgr.get_text('import_client_cert'):
                zwift_path = find_zwift_location()
                if zwift_path:
                    import_client_certificates(zwift_path)
                else:
                    print("Zwift安装位置未找到")
            
            elif event == lang_mgr.get_text('start_caddy'):
                if run_caddy_server():
                    print("Caddy服务器启动成功")
                else:
                    print("Caddy服务器启动失败")
                    
            elif event == lang_mgr.get_text('download_local_server'):
                download_local_server()
                    
            elif event == lang_mgr.get_text('start_local_server'):
                start_local_server()
                    
            elif event == lang_mgr.get_text('check_local_ver'):
                check_local_versions()
                
            elif event == lang_mgr.get_text('force_update'):
                force_update_version()
                
            elif event == lang_mgr.get_text('check_proxy'):
                check_system_proxy()

            elif event == lang_mgr.get_text('check_ports'):
                check_ports()
                
            elif event == lang_mgr.get_text('kill_ports'):
                if sg.popup_yes_no("警告", 
                                "这是一个危险操作，请先用检查端口仔细检查目前占用端口的进程有无重要进程。\n确定要继续吗？",
                                title="确认操作",
                                button_color=("white", "red")) == "Yes":
                    kill_port_processes()
                else:
                    print("操作已取消")
                    
            elif event == lang_mgr.get_text('check_official_ver'):
                check_official_version()
                print("查询官方版本有概率失效，主要是官服的接口有可能忘记更新，请查阅")

            elif event == lang_mgr.get_text('check_community_ver'):
                check_community_version()

            elif event == lang_mgr.get_text('test_remote'):
                test_direct_remote()
                
            elif event == lang_mgr.get_text('test_local'):
                test_local_connectivity()
                
            elif event == lang_mgr.get_text('test_https'):
                test_https_connectivity()
                
            elif event == lang_mgr.get_text('test_connectivity'):
                test_community_connectivity()
                
            elif event == lang_mgr.get_text('kill_all'):
                if kill_processes():
                    if cleanup_system():
                        print("已终止所有相关进程并清理网络配置")
                    else:
                        print("网络配置清理失败")
                else:
                    print("终止进程时出现错误")
                    
            elif event == lang_mgr.get_text('clean_network'):
                cleanup_system()
                
            elif event == lang_mgr.get_text('save_ip'):
                ip = values['-SERVER-IP-'].strip()
                if ip:
                    with open("remote_server_ip.txt", 'w', encoding='utf-8') as f:
                        f.write(ip)
                    print(f"已保存服务器IP: {ip}")
                else:
                    print("请输入有效的IP地址")
            
            elif event == '-GITHUB-LINK-':
                import webbrowser
                webbrowser.open('https://github.com/kanhao100/zoffline-cn-tool')
                
            elif event == lang_mgr.get_text('menu_usage'):
                sg.popup(lang_mgr.get_text('menu_usage'), 
                         '1. 设置服务器IP\n' + 
                         '2. 导入证书和配置\n' + 
                         '3. 选择启动模式\n' + 
                         '4. 根据需要使用高级功能',
                         title=lang_mgr.get_text('menu_usage'))
                         
            elif event == lang_mgr.get_text('menu_about'):
                about_layout = [
                    [sg.Text('Zoffline-CN-Tool', font=('Helvetica', 16), justification='center')],
                    [sg.Text('版本: 1.4.0', justification='center')],
                    [sg.Text('开源地址: '), sg.Text('https://github.com/kanhao100/zoffline-cn-tool', 
                            text_color='blue', enable_events=True, key='-GITHUB-LINK-', justification='center')],
                    [sg.Text('请给Star鼓励一下作者', justification='center')],
                    [sg.Column([[sg.Image(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'SEU.ico'), size=(128,128)), 
                               sg.Image(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'NUCU.ico'), size=(128,128))]], 
                              justification='center')],
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
            if window_active:  # 只在窗口仍然活动时显示错误
                print(f"发生错误: {str(e)}")
            break  # 发生异常时直接退出循环
    
    if window:
        window.close()

if __name__ == "__main__":
    main()