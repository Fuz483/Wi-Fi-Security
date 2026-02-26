import os
import threading
import time
import json
import numpy as np 
import pandas as pd
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from scapy.all import sniff
import socket
import winreg
import subprocess

from mainpyth import Analyzer
from procxyserv import ProxyManager
from url_checking import URLSecurityAnalyzer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

analyzer = Analyzer()
url_analyzer = URLSecurityAnalyzer()
is_scanning = False
stop_event = threading.Event()
scan_thread = None

proxy_manager = ProxyManager()

def reset_analyzer_state():
    global analyzer
    
    analyzer.threats = []
    analyzer.risk_scores.clear()
    analyzer.network_risk_score = 0
    analyzer.packets = []
    analyzer.df = None
    analyzer.statistics = {}
    
    if hasattr(analyzer, 'dataset_loaded'):
        analyzer.dataset_loaded = False
        analyzer.dataset_filename = None

def clean_for_json(obj):
    if isinstance(obj, (pd.Timestamp, datetime)):
        return str(obj)
    if isinstance(obj, (np.integer, np.int64)):
        return int(obj)
    if isinstance(obj, (np.floating, np.float64)):
        return float(obj)
    if isinstance(obj, dict):
        return {k: clean_for_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [clean_for_json(i) for i in obj]
    return obj

def calculate_safety_score():
    base_score = 100
    total_risk = analyzer.network_risk_score + sum(analyzer.risk_scores.values())
    if total_risk == 0: return 100
    deduction = total_risk * 0.5
    safety = max(0, base_score - deduction)
    return int(safety)

def emit_results():
    threats = analyzer.threats
    stats = analyzer.statistics
    score = calculate_safety_score()

    raw_data = {
        'threats': threats,
        'stats': stats,
        'safety_score': score,
        'is_dataset': hasattr(analyzer, 'dataset_loaded') and analyzer.dataset_loaded
    }
    
    safe_data = clean_for_json(raw_data)
    socketio.emit('scan_complete', safe_data)
    for threat in threats:
        socketio.emit('threat_detected', clean_for_json(threat))

def background_scan(interface="wlan0", timeout=60):
    global is_scanning
    
    def stop_filter(x):
        return stop_event.is_set()

    try:
        captured = sniff(timeout=timeout, count=40, stop_filter=stop_filter)
        if captured:
            analyzer.packets = list(captured)
            analyzer._create_dataframe()
            analyzer._collect_statistics()
            analyzer.analyze_security()
        else:
            print("Пакетов не захвачено")
        emit_results()
    except Exception as e:
        print(f"Ошибка сканирования: {e}")
        socketio.emit('error', {'message': str(e)})
    finally:
        is_scanning = False
        socketio.emit('status_update', {'status': 'IDLE'})

@app.route('/')
def index():
    return render_template('front.html')

@app.route('/api/status')
def get_status():
    return jsonify({
        'status': 'ACTIVE' if is_scanning else 'IDLE',
        'stats': {
            'threats_detected': len(analyzer.threats),
            'safety_score': calculate_safety_score(),
            'total_packets': len(analyzer.df) if analyzer.df is not None else 0
        },
        'dataset_info': {
            'loaded': hasattr(analyzer, 'dataset_loaded') and analyzer.dataset_loaded,
            'filename': getattr(analyzer, 'dataset_filename', 'Нет')
        },
        'threats': analyzer.threats
    })

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    global is_scanning, stop_event, scan_thread
    if is_scanning:
        return jsonify({'success': False, 'message': 'Сканирование уже идет'})
    reset_analyzer_state()
    stop_event.clear()
    is_scanning = True
    socketio.emit('scan_complete', {'threats': [], 'stats': {}, 'safety_score': 100, 'is_dataset': False})
    
    scan_thread = threading.Thread(target=background_scan)
    scan_thread.daemon = True
    scan_thread.start()
    
    socketio.emit('scan_started')
    return jsonify({'success': True, 'message': 'Сканирование запущено'})

def proxy_scan_workflow(ssid, password):
    global is_scanning
    try:
        socketio.emit('status_custom', {'msg': 'Подключение к Wi-Fi...'})
        print(f"Connecting to {ssid}...")
        
        if ssid and password:
            connected = proxy_manager.connect_wifi(ssid, password)
            if not connected:
                socketio.emit('error', {'message': 'Не удалось подключиться к Wi-Fi'})
                return
        
        socketio.emit('status_custom', {'msg': 'Запуск Proxy сервера...'})
        proxy_manager.start_proxy_background()
        
        socketio.emit('status_custom', {'msg': 'Анализ трафика через Proxy...'})
        time.sleep(2)
        
        captured = sniff(timeout=30, count=50)
        if captured:
            analyzer.packets = list(captured)
            analyzer._create_dataframe()
            analyzer._collect_statistics()
            analyzer.analyze_security()
        
        emit_results()
        
    except Exception as e:
        print(f"Proxy Scan Error: {e}")
        socketio.emit('error', {'message': str(e)})
    finally:
        socketio.emit('status_custom', {'msg': 'Отключение Proxy и удаление сети...'})
        proxy_manager.stop_proxy()
        if ssid:
            proxy_manager.disconnect_wifi(ssid)
            
        is_scanning = False
        socketio.emit('status_update', {'status': 'IDLE'})

@app.route('/api/scan/proxy', methods=['POST'])
def start_proxy_scan():
    global is_scanning, stop_event, scan_thread
    if is_scanning:
        return jsonify({'success': False, 'message': 'Сканирование уже идет'})

    data = request.json
    ssid = data.get('ssid')
    password = data.get('password')
    
    if not ssid or not password:
        return jsonify({'success': False, 'message': 'Нужны SSID и пароль'})

    reset_analyzer_state()
    stop_event.clear()
    is_scanning = True
    
    socketio.emit('scan_complete', {'threats': [], 'stats': {}, 'safety_score': 100, 'is_dataset': False})
    socketio.emit('scan_started')
    
    scan_thread = threading.Thread(target=proxy_scan_workflow, args=(ssid, password))
    scan_thread.daemon = True
    scan_thread.start()
    
    return jsonify({'success': True, 'message': 'Безопасное сканирование запущено'})

@app.route('/api/scan/stop', methods=['POST'])
def stop_scan():
    global is_scanning, stop_event
    if proxy_manager.is_running:
        proxy_manager.stop_proxy()
    
    if is_scanning:
        stop_event.set()
        is_scanning = False
        return jsonify({'success': True, 'message': 'Остановка...'})
    return jsonify({'success': False, 'message': 'Нечего останавливать'})

@app.route('/api/logs/clear', methods=['POST'])
def clear_logs():
    analyzer.threats = []
    analyzer.risk_scores.clear()
    analyzer.network_risk_score = 0
    analyzer.packets = []
    if analyzer.df is not None:
        analyzer.df = pd.DataFrame()
    emit_results()
    return jsonify({'success': True, 'message': 'Журнал и данные очищены'})

@app.route('/api/dataset/load', methods=['POST'])
def load_dataset():
    files = [f for f in os.listdir('.') if f.endswith(('.csv', '.pcap', '.pcapng'))]
    if not files:
        return jsonify({'success': False, 'message': 'Файлы не найдены'})
    target_file = files[0]
    try:
        reset_analyzer_state()
        if target_file.endswith('.csv'):
            analyzer.df = pd.read_csv(target_file)
            analyzer._collect_statistics()
            msg = f"CSV {target_file} загружен"
        else:
            success = analyzer.load_pcap(target_file)
            if not success: raise Exception("Ошибка PCAP")
            msg = f"PCAP {target_file} проанализирован"
        analyzer.analyze_security()
        analyzer.dataset_loaded = True
        analyzer.dataset_filename = target_file
        emit_results() 
        return jsonify({'success': True, 'message': msg})
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'success': False, 'message': f'Ошибка: {str(e)}'})

@app.route('/api/scan/url_check', methods=['POST'])
def check_url_api():
    data = request.json
    url = data.get('url')
    
    result = url_analyzer.analyze_url(url)
    msg = f"Энтропия: {result['entropy']}. Риск: {result['risk_score']}%. " + " ".join(result['details'])
    
    return jsonify({
        "success": True, 
        "result": result['status'], 
        "message": msg
    })

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000, allow_unsafe_werkzeug=True)