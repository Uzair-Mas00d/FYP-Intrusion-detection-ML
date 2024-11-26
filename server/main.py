from fastapi import FastAPI, BackgroundTasks
from capture_realtime_traffic import FlowFeatureExtractor
import tensorflow as tf
import pickle
import numpy as np
from scapy.all import sniff

with open(r'E:\FYP\model_training\normalizer.pkl', 'rb') as file:
        normalizer = pickle.load(file)

with open(r'E:\FYP\model_training\quantile_transformer.pkl', 'rb') as file:
        quantile_transformer = pickle.load(file)
    
model = tf.keras.models.load_model(r'E:\FYP\model_training\security_expert.keras')

app = FastAPI()

def packet_callback(packet):
    global feature_extractor
    feature_extractor.process_packet(packet)

def capture_traffic_task():
    data_list = []
    global feature_extractor
    feature_extractor = FlowFeatureExtractor()
    
    print("Starting packet capture on loopback interface...")
    print("Capturing TCP traffic on port 8000...")
    print("Press Ctrl+C to stop capture")
    
    try:
        # Try different interface names that might work on Windows
        interfaces_to_try = [
            'Loopback Pseudo-Interface 1',
            'lo0',
            'lo',
            'loop',
            'loopback',
            None  # Let Scapy choose default
        ]
        
        for iface in interfaces_to_try:
            try:
                print(f"\nTrying interface: {iface}")
                sniff(iface=iface,
                     filter="tcp port 8000",
                     prn=packet_callback,
                     store=0,
                     timeout=30)  # Set 30 second timeout for testing
                break
            except Exception as e:
                print(f"Failed with interface {iface}: {e}")
                continue
                
    except Exception as e:
        print(f"Error during capture: {e}")
    finally:
        for flow_key in feature_extractor.flows:
            features = feature_extractor.extract_features(flow_key)
            if features:
                data_list.append(features)

    new_data =  [list(d.values()) for d in data_list if len(d) == 14]

    feature_array = np.array(new_data)

    print(feature_array.shape)
    
    normalized_feature = normalizer.transform(feature_array)
    
    quantile_normalized_feature = quantile_transformer.transform(normalized_feature)

    print(quantile_normalized_feature)

    # pred = model.predict(quantile_normalized_feature)

    # for i in range(len(pred)):
    #     if pred[i][0] > 0.5:
    #         print("Attack")
    #     else:
    #         print("Normal")

@app.get("/")
async def capture_traffic(background_tasks: BackgroundTasks):
    background_tasks.add_task(capture_traffic_task)

    return {"message": "Traffic capture started in the background"}