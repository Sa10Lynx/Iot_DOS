from flask import Flask, render_template
from flask_socketio import SocketIO
from flask_cors import CORS
import os

from config import Config
from services import AttackService, DetectionService, TrafficService
from routes import api_bp, register_socketio_handlers
import routes.api as api_routes
import routes.websocket as ws_routes

# Create Flask app
app = Flask(__name__)
app.config.from_object(Config)
Config.init_app(app)

# Enable CORS
CORS(app)

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialize services
attack_service = AttackService(socketio)
detection_service = DetectionService(
    socketio, 
    Config.MODEL_PATH, 
    Config.DOS_FEATURES
)
traffic_service = TrafficService(socketio, detection_service)

# Link services to detection service
attack_service.detection_service = detection_service

# Initialize service references in routes
api_routes.init_services(attack_service, detection_service, traffic_service)
ws_routes.init_services(attack_service, detection_service, traffic_service)

# Register blueprints
app.register_blueprint(api_bp)

# Register WebSocket handlers
register_socketio_handlers(socketio)


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


@app.route('/health')
def health():
    """Health check endpoint"""
    return {
        'status': 'healthy',
        'model_loaded': detection_service.model is not None
    }


def main():
    """Run the application"""
    print("=" * 60)
    print("IoT DoS Detection System - Web Interface")
    print("=" * 60)
    print(f"Server: http://{Config.HOST}:{Config.PORT}")
    print(f"Model: {Config.MODEL_PATH}")
    print(f"Model loaded: {detection_service.model is not None}")
    print("=" * 60)
    print("\nPress Ctrl+C to stop the server")
    print()
    
    # Start detection monitoring by default
    detection_service.start_monitoring()
    
    # Run Flask app with SocketIO
    socketio.run(
        app,
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG,
        allow_unsafe_werkzeug=True  # For development only
    )


if __name__ == '__main__':
    main()
