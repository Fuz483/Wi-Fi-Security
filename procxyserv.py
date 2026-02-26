import socket
import winreg
import subprocess
import time
import os
import threading

class ProxyManager:
    def __init__(self):
        self.proxy_host = '127.0.0.1'
        self.proxy_port = 8080
        self.server_socket = None
        self.is_running = False
        self.proxy_thread = None

    def set_system_proxy(self, enable=True):
        try:
            internet_settings = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                            r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
                                            0, winreg.KEY_ALL_ACCESS)
            if enable:
                winreg.SetValueEx(internet_settings, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(internet_settings, 'ProxyServer', 0, winreg.REG_SZ, f"{self.proxy_host}:{self.proxy_port}")
            else:
                winreg.SetValueEx(internet_settings, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
            
            subprocess.run(['ie4uinit.exe', '-show'], capture_output=True)
            winreg.CloseKey(internet_settings)
            return True
        except Exception as e:
            print(f"Proxy Registry Error: {e}")
            return False

    def connect_wifi(self, ssid, password):
        profile_xml = f"""<?xml version="1.0"?>
        <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
            <name>{ssid}</name>
            <SSIDConfig><SSID><name>{ssid}</name></SSID></SSIDConfig>
            <connectionType>ESS</connectionType>
            <connectionMode>manual</connectionMode>
            <MSM><security><authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption><sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey></security></MSM>
        </WLANProfile>"""

        try:
            filename = f"temp_{int(time.time())}.xml"
            with open(filename, "w") as f:
                f.write(profile_xml)
            
            subprocess.run(f'netsh wlan add profile filename="{filename}"', shell=True, capture_output=True)
            time.sleep(1)
            result = subprocess.run(f'netsh wlan connect name="{ssid}"', shell=True, capture_output=True)
            
            if os.path.exists(filename):
                os.remove(filename)
                
            time.sleep(5) 
            return result.returncode == 0
        except Exception as e:
            print(f"Wifi Connect Error: {e}")
            return False

    def disconnect_wifi(self, ssid):
        try:
            subprocess.run('netsh wlan disconnect', shell=True, capture_output=True)
            time.sleep(1)
            if ssid:
                subprocess.run(f'netsh wlan delete profile name="{ssid}"', shell=True, capture_output=True)
            return True
        except Exception as e:
            print(f"Wifi Disconnect Error: {e}")
            return False

    def handle_client(self, conn):
        try:
            conn.settimeout(5)
            data = conn.recv(4096)
            if not data: return
            
            first_line = data.decode('utf-8', errors='ignore').split('\n')[0]
            if len(first_line.split(' ')) < 2: return
            
            url = first_line.split(' ')[1]
            http_pos = url.find("://")
            temp = url[(http_pos+3):] if http_pos != -1 else url
            port_pos = temp.find(":")
            webserver_pos = temp.find("/")
            if webserver_pos == -1: webserver_pos = len(temp)

            if port_pos == -1 or webserver_pos < port_pos:
                target_port = 80
                target_host = temp[:webserver_pos]
            else:
                target_port = int((temp[(port_pos+1):])[:webserver_pos-port_pos-1])
                target_host = temp[:port_pos]

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((target_host, target_port))
                s.sendall(data)
                while True:
                    reply = s.recv(4096)
                    if len(reply) > 0:
                        conn.sendall(reply)
                    else:
                        break
        except Exception:
            pass
        finally:
            conn.close()

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.proxy_host, self.proxy_port))
        self.server_socket.listen(10)
        self.is_running = True
        
        while self.is_running:
            try:
                self.server_socket.settimeout(1)
                conn, addr = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def start_proxy_background(self):
        self.proxy_thread = threading.Thread(target=self.start_server, daemon=True)
        self.proxy_thread.start()
        self.set_system_proxy(True)

    def stop_proxy(self):
        self.is_running = False
        self.set_system_proxy(False)
        if self.server_socket:
            try:
                self.server_socket.close()
            except: pass