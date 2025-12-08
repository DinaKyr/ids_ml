from packetCapture import PacketCapture
from trafficAnalyser import TrafficAnalyzer
import time
from packetPred import PacketPred

#classes initialization
capture = PacketCapture()
analyzer = TrafficAnalyzer()

packet_predictor = PacketPred('models/mlp_model.joblib', analyzer)


from scapy.all import get_if_list, get_if_addr
selected_iface = None
for iface in get_if_list():
    try:
        ip = get_if_addr(iface)
        print(iface, ip)
        # Pick the first interface that has an IP
        if selected_iface is None and ip != '0.0.0.0':
            selected_iface = iface
    except:
        pass

print(selected_iface)
if selected_iface:
    capture.start_capture(interface=selected_iface)
else:
    print("No interface found with an active IP address!")
try:
    while True:
        # Check if there are packets in the queue
        if not capture.packet_queue.empty():
            packet = capture.packet_queue.get()
            
            features = analyzer.analyze_packet(packet)
            pred_class, pred_prob = packet_predictor.predict(packet)
            
            # Print the feature dictionary
            if features:
                if pred_class is not None:
                    print("Predicted class:", pred_class)
                    print("Probability:", pred_prob)
                print(features)
                print("-----\n")
        else:
            #busy waiting/sleep when no packets in queue
            time.sleep(1)

except KeyboardInterrupt:
    #ctrl+c 
    capture.stop()
    print("Capture stopped.")
