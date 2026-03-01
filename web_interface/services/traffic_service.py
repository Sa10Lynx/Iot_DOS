import threading
import time
import requests
from requests.exceptions import RequestException


class TrafficService:
    """Service for generating normal HTTP traffic"""
    
    def __init__(self, socketio, detection_service=None):
        self.socketio = socketio
        self.detection_service = detection_service  # Link to detection service
        self.active = False
        self.request_count = 0
        self.threads = []
        self.monitor_thread = None
        
    def start_normal_traffic(self, target_url='http://127.0.0.1:8000', rate=10):
        """Start generating normal HTTP requests"""
        if self.active:
            return {'success': False, 'message': 'Traffic generation already running'}
        
        self.active = True
        self.request_count = 0
        self.threads = []
        
        print(f"[TrafficService] Starting normal traffic: {target_url} at {rate} req/s")
        
        # Calculate delay between requests
        delay = 1.0 / rate if rate > 0 else 0.1
        
        # Start traffic generator thread
        t = threading.Thread(
            target=self._traffic_worker,
            args=(target_url, delay)
        )
        t.daemon = True
        t.start()
        self.threads.append(t)
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._broadcast_stats)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        return {'success': True, 'message': f'Normal traffic started at {rate} req/s'}
    
    def _traffic_worker(self, target_url, delay):
        """Generate HTTP requests"""
        success_count = 0
        error_count = 0
        
        while self.active:
            try:
                # Make GET request
                response = requests.get(target_url, timeout=2)
                
                if response.status_code == 200:
                    success_count += 1
                else:
                    error_count += 1
                
                self.request_count += 1
                
                # Record packet to detection service (each HTTP request = packet)
                if self.detection_service:
                    self.detection_service.record_packet({
                        'timestamp': time.time(),
                        'proto': 'tcp',
                        'type': 'normal_http',
                        'status_code': response.status_code
                    })
                
                # Wait before next request
                time.sleep(delay)
                
            except RequestException:
                # Target not reachable, continue anyway
                error_count += 1
                self.request_count += 1

                # Even failed requests generate outbound traffic attempts
                if self.detection_service:
                    self.detection_service.record_packet({
                        'timestamp': time.time(),
                        'proto': 'tcp',
                        'type': 'normal_http',
                        'status_code': 0
                    })

                time.sleep(delay)
                
            except Exception as e:
                print(f"[TrafficService] Error in traffic worker: {e}")
                time.sleep(1)
    
    def _broadcast_stats(self):
        """Broadcast traffic statistics via WebSocket"""
        last_count = 0
        start_time = time.time()
        
        while self.active:
            try:
                current_count = self.request_count
                rate = current_count - last_count  # Requests in last second
                elapsed = time.time() - start_time
                
                # Emit stats to all connected clients
                self.socketio.emit('traffic_stats', {
                    'total': current_count,
                    'rate': rate,
                    'elapsed': round(elapsed, 1),
                    'status': 'running'
                })
                
                last_count = current_count
                time.sleep(1)
                
            except Exception as e:
                print(f"[TrafficService] Error broadcasting stats: {e}")
    
    def stop(self):
        """Stop traffic generation"""
        if not self.active:
            return {'success': False, 'message': 'No active traffic generation'}
        
        print("[TrafficService] Stopping traffic generation...")
        self.active = False
        
        # Wait for threads to finish
        for t in self.threads:
            t.join(timeout=2)
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        
        final_count = self.request_count
        
        # Emit final stats
        self.socketio.emit('traffic_stats', {
            'total': final_count,
            'rate': 0,
            'status': 'stopped'
        })
        
        print(f"[TrafficService] Traffic stopped. Total requests: {final_count}")
        
        return {'success': True, 'message': f'Traffic stopped. Total requests: {final_count}'}
    
    def get_status(self):
        """Get current traffic status"""
        return {
            'active': self.active,
            'request_count': self.request_count
        }
