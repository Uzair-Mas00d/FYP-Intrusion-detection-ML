from scapy.all import *
import numpy as np
from collections import defaultdict
import tensorflow as tf

class FlowFeatureExtractor:
    def __init__(self):
        self.flows = defaultdict(lambda: {
            'start_time': None,
            'packets': [],
            'fwd_packets': [],
            'fwd_header_lengths': [],
            'fwd_data_packets': 0,
            'fin_count': 0
        })
        
    def get_flow_key(self, packet):
        try:
            if IP in packet and TCP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        except:
            pass
        return None

    def process_packet(self, packet):
        try:
            if not (IP in packet and TCP in packet):
                return
            
            flow_key = self.get_flow_key(packet)
            if not flow_key:
                return
                
            flow = self.flows[flow_key]
            
            if flow['start_time'] is None:
                flow['start_time'] = float(packet.time)
            
            flow['packets'].append(packet)
            
            if TCP in packet and packet[TCP].flags & 0x02:  # SYN flag
                flow['fwd_packets'].append(packet)
                flow['fwd_header_lengths'].append(len(packet[TCP]))
                
                if len(packet.payload) > 0:
                    flow['fwd_data_packets'] += 1
            
            if TCP in packet and packet[TCP].flags & 0x01:  # FIN flag
                flow['fin_count'] += 1
                
            # Print immediate packet info for debugging
            print(f"Captured packet: {packet.summary()}")
            
        except Exception as e:
            print(f"Error processing packet: {e}")

    def extract_features(self, flow_key):
        try:
            flow = self.flows[flow_key]
            
            if not flow['fwd_packets']:
                return None
                
            flow_duration = float(flow['packets'][-1].time) - flow['start_time']
            total_fwd_packets = len(flow['fwd_packets'])
            
            fwd_packet_lengths = [len(p) for p in flow['fwd_packets']]
            fwd_packet_length_min = min(fwd_packet_lengths) if fwd_packet_lengths else 0
            fwd_packet_length_max = max(fwd_packet_lengths) if fwd_packet_lengths else 0
            fwd_packet_length_std = np.std(fwd_packet_lengths) if fwd_packet_lengths else 0
            
            fwd_times = [float(p.time) for p in flow['fwd_packets']]
            fwd_iats = np.diff(fwd_times)
            fwd_iat_total = np.sum(fwd_iats) if len(fwd_iats) > 0 else 0
            fwd_iat_mean = np.mean(fwd_iats) if len(fwd_iats) > 0 else 0
            fwd_iat_std = np.std(fwd_iats) if len(fwd_iats) > 0 else 0
            fwd_iat_max = np.max(fwd_iats) if len(fwd_iats) > 0 else 0
            
            fwd_header_length = sum(flow['fwd_header_lengths'])
            packet_length_std = np.std([len(p) for p in flow['packets']])
            avg_packet_size = np.mean([len(p) for p in flow['packets']])
            
            return {
                "Flow Duration": flow_duration,
                "Total Fwd Packets": total_fwd_packets,
                "Fwd Packet Length Min": fwd_packet_length_min,
                "Fwd Packet Length Max": fwd_packet_length_max,
                "Fwd Packet Length Std": fwd_packet_length_std,
                "Fwd IAT Total": fwd_iat_total,
                "Fwd IAT Mean": fwd_iat_mean,
                "Fwd IAT Std": fwd_iat_std,
                "Fwd IAT Max": fwd_iat_max,
                "Fwd Header Length": fwd_header_length,
                "Fwd Act Data Packets": flow['fwd_data_packets'],
                "FIN Flag Count": flow['fin_count'],
                "Packet Length Std": packet_length_std,
                "Avg Packet Size": avg_packet_size,
                # "Label": "Normal"
            }
        except Exception as e:
            print(f"Error extracting features: {e}")
            return None

# def packet_callback(packet):
#     global feature_extractor
#     feature_extractor.process_packet(packet)

# def main():
#     data_list = []
#     global feature_extractor
#     feature_extractor = FlowFeatureExtractor()
    
#     print("Starting packet capture on loopback interface...")
#     print("Capturing TCP traffic on port 8000...")
#     print("Press Ctrl+C to stop capture")
    
#     try:
#         # Try different interface names that might work on Windows
#         interfaces_to_try = [
#             'Loopback Pseudo-Interface 1',
#             'lo0',
#             'lo',
#             'loop',
#             'loopback',
#             None  # Let Scapy choose default
#         ]
        
#         for iface in interfaces_to_try:
#             try:
#                 print(f"\nTrying interface: {iface}")
#                 sniff(iface=iface,
#                      filter="tcp port 8000",
#                      prn=packet_callback,
#                      store=0,
#                      timeout=30)  # Set 30 second timeout for testing
#                 break
#             except Exception as e:
#                 print(f"Failed with interface {iface}: {e}")
#                 continue
                
#     except Exception as e:
#         print(f"Error during capture: {e}")
#     finally:
#         for flow_key in feature_extractor.flows:
#             features = feature_extractor.extract_features(flow_key)
#             if features:
#                 data_list.append(features)

#     new_data =  [list(d.values()) for d in data_list if len(d) == 14]

#     feature_array = np.array(new_data)

#     print(feature_array.shape)

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
    

# if __name__ == "__main__":
#     main()