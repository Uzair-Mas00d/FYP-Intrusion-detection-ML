from scapy.all import *
import numpy as np
from collections import defaultdict
import time
import tensorflow as tf

class FlowFeatureExtractor:
    def __init__(self, flow_timeout=120):
        """
        Initialize the flow feature extractor
        
        Args:
            flow_timeout: Flow timeout in seconds (default: 120s)
        """
        self.flows = defaultdict(lambda: self._create_new_flow())
        self.flow_timeout = flow_timeout
        self.feature_list = []  # Store features for all flows here

    def _create_new_flow(self):
        """Create a new flow with initial values"""
        return {
            'start_time': time.time(),
            'last_seen': time.time(),
            
            # Forward packets (source → destination)
            'fwd_packets': [],
            'fwd_packet_lengths': [],
            'fwd_packet_times': [],
            'fwd_header_lengths': [],
            'fwd_data_packets': 0,
            
            # Backward packets (destination → source)
            'bwd_packets': [],
            'bwd_packet_lengths': [],
            'bwd_packet_times': [],
            
            # Flags
            'fin_count': 0,
            
            # Flow state
            'active_start': time.time(),
            'active_times': [],
            'idle_times': [],
        }

    def _get_flow_key(self, packet):
        """Generate flow key from packet"""
        if IP in packet and (TCP in packet or UDP in packet):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                proto = 'TCP'
            else:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                proto = 'UDP'
            
            return (src_ip, dst_ip, src_port, dst_port, proto)
        return None

    def _is_forward_flow(self, packet, flow_key):
        """Determine if packet belongs to forward flow"""
        return packet[IP].src == flow_key[0]

    def process_packet(self, packet):
        """Process a packet and update flow statistics"""
        flow_key = self._get_flow_key(packet)
        if not flow_key:
            return
        
        current_time = time.time()
        flow = self.flows[flow_key]
        
        # Check if flow has expired
        if current_time - flow['last_seen'] > self.flow_timeout:
            self.flows[flow_key] = self._create_new_flow()
            flow = self.flows[flow_key]
        
        # Update flow timestamps
        flow['last_seen'] = current_time
        
        # Process packet
        packet_length = len(packet)
        if self._is_forward_flow(packet, flow_key):
            # Forward flow features
            flow['fwd_packets'].append(packet)
            flow['fwd_packet_lengths'].append(packet_length)
            flow['fwd_packet_times'].append(current_time)
            
            if IP in packet:
                flow['fwd_header_lengths'].append(packet[IP].ihl * 4)
            
            if TCP in packet:
                if packet[TCP].flags.F:
                    flow['fin_count'] += 1
                
                # Check if packet contains actual data
                if Raw in packet or len(packet[TCP].payload) > 0:
                    flow['fwd_data_packets'] += 1
        else:
            # Backward flow features
            flow['bwd_packets'].append(packet)
            flow['bwd_packet_lengths'].append(packet_length)
            flow['bwd_packet_times'].append(current_time)
        
        # Update active/idle times
        if current_time - flow['last_seen'] > 1:  # 1 second threshold
            if flow['active_times']:
                flow['idle_times'].append(current_time - flow['last_seen'])
            flow['active_times'].append(current_time - flow['active_start'])
            flow['active_start'] = current_time

    def calculate_flow_features(self, flow_key):
        """Calculate all features for a given flow"""
        flow = self.flows[flow_key]
        
        features = {}
        
        # Calculate time-based features
        flow_duration = flow['last_seen'] - flow['start_time']
        features['Flow Duration'] = flow_duration
        
        # Forward packet features
        fwd_packet_lengths = flow['fwd_packet_lengths']
        features['Total Fwd Packets'] = len(fwd_packet_lengths)
        
        if fwd_packet_lengths:
            features['Fwd Packet Length Min'] = min(fwd_packet_lengths)
            features['Fwd Packet Length Max'] = max(fwd_packet_lengths)
            features['Fwd Packet Length Std'] = np.std(fwd_packet_lengths) if len(fwd_packet_lengths) > 1 else 0
        
        # Forward IAT (Inter Arrival Time) features
        fwd_times = flow['fwd_packet_times']
        if len(fwd_times) > 1:
            fwd_iats = np.diff(fwd_times)
            features['Fwd IAT Total'] = sum(fwd_iats)
            features['Fwd IAT Mean'] = np.mean(fwd_iats)
            features['Fwd IAT Std'] = np.std(fwd_iats)
            features['Fwd IAT Max'] = max(fwd_iats)
        
        # Backward packet features
        bwd_packet_lengths = flow['bwd_packet_lengths']
        if bwd_packet_lengths:
            features['Bwd Packet Length Mean'] = np.mean(bwd_packet_lengths)
            features['Bwd Packet Length Std'] = np.std(bwd_packet_lengths) if len(bwd_packet_lengths) > 1 else 0
            features['Bwd Packet Length Min'] = min(bwd_packet_lengths)
            
            if flow_duration > 0:
                features['Bwd Packets/s'] = len(bwd_packet_lengths) / flow_duration
        
        # Header and data packet features
        features['Fwd Header Length'] = sum(flow['fwd_header_lengths'])
        features['Fwd Act Data Packets'] = flow['fwd_data_packets']
        
        # Flag features
        features['FIN Flag Count'] = flow['fin_count']
        
        # Size features
        all_packets = fwd_packet_lengths + bwd_packet_lengths
        if all_packets:
            features['Packet Length Std'] = np.std(all_packets) if len(all_packets) > 1 else 0
            features['Avg Packet Size'] = np.mean(all_packets)
        
        if bwd_packet_lengths:
            features['Avg Bwd Segment Size'] = np.mean(bwd_packet_lengths)
        
        # Active time features
        if flow['active_times']:
            features['Active Max'] = max(flow['active_times'])
        
        return features

    def start_capture(self, packet_count=100, interface=None):
        """Start capturing packets and extracting features"""

        def packet_callback(packet):
            self.process_packet(packet)
            
            # Collect features for all flows
            for flow_key in list(self.flows.keys()):
                features = self.calculate_flow_features(flow_key)
                self.feature_list.append(list(features.values()))

        try:
            print(f"Starting capture on interface {interface if interface else 'default'}")
            sniff(iface=interface, 
                  prn=packet_callback, 
                  store=0,
                  count=packet_count)
        except KeyboardInterrupt:
            print("\nCapture stopped by user")
        
        # Convert feature list to numpy array and return
        return self.feature_list

# feature_array = []
# if __name__ == "__main__":
#     extractor = FlowFeatureExtractor()
#     raw_array = extractor.start_capture(packet_count=100)

#     for packets in raw_array:
#         if len(packets) >=14:
#             feature_array.append(packets)

#     feature_array = np.array(feature_array)

#     with open(r'E:\FYP\model_training\normalizer.pkl', 'rb') as file:
#         normalizer = pickle.load(file)
    
#     normalized_feature = normalizer.transform(feature_array)

#     with open(r'E:\FYP\model_training\quantile_transformer.pkl', 'rb') as file:
#         quantile_transformer = pickle.load(file)
    
#     quantile_normalized_feature = quantile_transformer.transform(normalized_feature)


#     model = tf.keras.models.load_model(r'E:\FYP\model_training\security_expert.keras')

#     pred = model.predict(quantile_normalized_feature)

#     for i in range(len(pred)):
#         if pred[i][0] > 0.6:
#             print("Attack")
#         else:
#             print("Normal")


