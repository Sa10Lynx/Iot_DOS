from flask import Blueprint, jsonify, request

api_bp = Blueprint('api', __name__, url_prefix='/api')

# These will be set by app.py
attack_service = None
detection_service = None
traffic_service = None


def init_services(attack, detection, traffic):
    """Initialize service references"""
    global attack_service, detection_service, traffic_service
    attack_service = attack
    detection_service = detection
    traffic_service = traffic


@api_bp.route('/status', methods=['GET'])
def get_status():
    """Get overall system status"""
    return jsonify({
        'attack': attack_service.get_status() if attack_service else {},
        'detection': detection_service.get_status() if detection_service else {},
        'traffic': traffic_service.get_status() if traffic_service else {}
    })


@api_bp.route('/attack/start', methods=['POST'])
def start_attack():
    """Start DoS attack via REST API"""
    data = request.json or {}
    
    target_ip = data.get('target_ip', '127.0.0.1')
    target_port = data.get('target_port', 80)
    threads = data.get('threads', 8)
    
    result = attack_service.start_syn_flood(target_ip, target_port, threads)
    return jsonify(result)


@api_bp.route('/attack/stop', methods=['POST'])
def stop_attack():
    """Stop DoS attack via REST API"""
    result = attack_service.stop()
    return jsonify(result)


@api_bp.route('/detection/start', methods=['POST'])
def start_detection():
    """Start detection monitoring via REST API"""
    result = detection_service.start_monitoring()
    return jsonify(result)


@api_bp.route('/detection/stop', methods=['POST'])
def stop_detection():
    """Stop detection monitoring via REST API"""
    result = detection_service.stop()
    return jsonify(result)


@api_bp.route('/traffic/start', methods=['POST'])
def start_traffic():
    """Start normal traffic generation via REST API"""
    data = request.json or {}
    
    target_url = data.get('target_url', 'http://127.0.0.1:8000')
    rate = data.get('rate', 10)
    
    result = traffic_service.start_normal_traffic(target_url, rate)
    return jsonify(result)


@api_bp.route('/traffic/stop', methods=['POST'])
def stop_traffic():
    """Stop normal traffic generation via REST API"""
    result = traffic_service.stop()
    return jsonify(result)
