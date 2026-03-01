from flask_socketio import emit

# Service references (set by app.py)
attack_service = None
detection_service = None
traffic_service = None


def init_services(attack, detection, traffic):
    """Initialize service references"""
    global attack_service, detection_service, traffic_service
    attack_service = attack
    detection_service = detection
    traffic_service = traffic


def register_socketio_handlers(socketio):
    """Register WebSocket event handlers"""
    
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection"""
        print("[WebSocket] Client connected")
        emit('connection_response', {'status': 'connected'})
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection"""
        print("[WebSocket] Client disconnected")
    
    @socketio.on('start_attack')
    def handle_start_attack(data):
        """Handle attack start request"""
        target_ip = data.get('target_ip', '127.0.0.1')
        target_port = data.get('target_port', 80)
        threads = data.get('threads', 8)
        
        print(f"[WebSocket] Start attack: {target_ip}:{target_port} ({threads} threads)")
        
        result = attack_service.start_syn_flood(target_ip, target_port, threads)
        emit('attack_response', result)
        
        # Also start detection if not already running
        if not detection_service.active:
            detection_service.start_monitoring()
    
    @socketio.on('stop_attack')
    def handle_stop_attack():
        """Handle attack stop request"""
        print("[WebSocket] Stop attack")
        result = attack_service.stop()
        emit('attack_response', result)
    
    @socketio.on('start_detection')
    def handle_start_detection():
        """Handle detection start request"""
        print("[WebSocket] Start detection")
        result = detection_service.start_monitoring()
        emit('detection_response', result)
    
    @socketio.on('stop_detection')
    def handle_stop_detection():
        """Handle detection stop request"""
        print("[WebSocket] Stop detection")
        result = detection_service.stop()
        emit('detection_response', result)
    
    @socketio.on('toggle_edge_mode')
    def handle_toggle_edge_mode(data):
        """Handle edge device simulation toggle"""
        enabled = data.get('enabled', False)
        print(f"[WebSocket] Toggle edge mode: {'ON' if enabled else 'OFF'}")
        result = detection_service.toggle_edge_mode(enabled)
        emit('edge_mode_response', result)
    
    @socketio.on('get_edge_info')
    def handle_get_edge_info():
        """Return edge device simulation info"""
        info = detection_service.get_edge_info()
        emit('edge_info_response', info)
    
    @socketio.on('start_traffic')
    def handle_start_traffic(data):
        """Handle normal traffic start request"""
        target_url = data.get('target_url', 'http://127.0.0.1:8000')
        rate = data.get('rate', 10)
        
        print(f"[WebSocket] Start traffic: {target_url} at {rate} req/s")
        
        result = traffic_service.start_normal_traffic(target_url, rate)
        emit('traffic_response', result)
    
    @socketio.on('stop_traffic')
    def handle_stop_traffic():
        """Handle normal traffic stop request"""
        print("[WebSocket] Stop traffic")
        result = traffic_service.stop()
        emit('traffic_response', result)
    
    @socketio.on('get_status')
    def handle_get_status():
        """Handle status request"""
        status = {
            'attack': attack_service.get_status(),
            'detection': detection_service.get_status(),
            'traffic': traffic_service.get_status()
        }
        emit('status_response', status)
