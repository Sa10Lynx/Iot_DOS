import os

class Config:
    """Application configuration"""
    
    # Flask settings
    SECRET_KEY = 'dos-detection-secret-key-change-in-production'
    DEBUG = True
    
    # Server settings
    HOST = '127.0.0.1'
    PORT = 5000
    
    # Paths
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.dirname(BASE_DIR)
    MODEL_PATH = os.path.join(PROJECT_ROOT, 'dos_lightgbm_model.pkl')
    CAPTURES_DIR = os.path.join(BASE_DIR, 'captures')
    
    # Attack settings
    DEFAULT_TARGET_IP = '127.0.0.1'
    DEFAULT_TARGET_PORT = 80
    MAX_THREADS = 16
    
    # Detection settings
    DETECTION_THRESHOLD = 0.5  # DoS probability threshold
    WINDOW_SIZE = 1.0  # seconds for packet aggregation
    
    # DoS features (must match training)
    DOS_FEATURES = [
        'ct_srv_src', 'ct_dst_ltm', 'ct_srv_dst',
        'synack', 'ackdat', 'tcprtt',
        'dmean', 'dpkts',
        'rate', 'sload', 'sbytes'
    ]
    
    @staticmethod
    def init_app(app):
        """Initialize application with config"""
        # Create captures directory if not exists
        os.makedirs(Config.CAPTURES_DIR, exist_ok=True)
