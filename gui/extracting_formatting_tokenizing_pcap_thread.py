#######################################################################################
#                        Extracting and Formatting Packet Data                        #                 #                       
#######################################################################################
'''
A class to process network traffic data from a pcap file and convert it into a format 
suitable for classification or analysis by a Large Language Model (LLM).

The class extracts network-related statistics (e.g., IP addresses, ports, HTTP requests, etc.) 
from the pcap file and formats the data into descriptive log entries.
'''

from PyQt5.QtCore import QThread, pyqtSignal
import subprocess

class PcapDataProcessor(QThread):
    # Signal to send logs back to the main thread
    processed_data_signal = pyqtSignal(str)  
 

    def __init__(self, pcap_file_location_on_host):
        super().__init__()
        self.pcap_file_location_on_host = pcap_file_location_on_host
        self.packets = []

    def run(self):
        try:
            # Extract pcap data
            self.extract_pcap_data()

            # Convert to text
            logs = self.convert_to_text()

            # Emit the signal with the logs as a string
            logs_str = '\n'.join(logs)  
            self.processed_data_signal.emit(logs_str)
        except Exception as e:
            print([f"Error: {str(e)}"])
            

    
    def extract_pcap_data(self):
        '''
        This method uses TShark to analyze the given .pcap file and extracts key 
        network traffic details such as source and destination IP addresses, source 
        and destination TCP ports, HTTP request URIs, and frame lengths. 
        The extracted data is returned as a list of packet-level details.
        '''
        tshark_command = [
            'tshark', '-r', self.pcap_file_location_on_host, 
            '-T', 'fields', 
            '-e', 'ip.src', 
            '-e', 'ip.dst', 
            '-e', 'tcp.srcport', 
            '-e', 'tcp.dstport', 
            '-e', 'http.request.uri', 
            '-e', 'frame.len'
        ]
        
        # Execute the tshark command
        result = subprocess.run(tshark_command, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise Exception(f"TShark error: {result.stderr}")
        
        # Store the extracted packets
        self.packets = result.stdout.splitlines()


    def convert_to_text(self):
        '''
        Converts raw packet data into human-readable log entries.

        This method processes a list of packets (each as a tab-separated string of fields) 
        and formats them into descriptive log entries. Each log entry provides details 
        about the TCP connection, HTTP request, and packet size.
        '''
        logs = []
        
        for packet in self.packets:
            fields = packet.split('\t')
            if len(fields) < 6:
                continue
            
            src_ip, dst_ip, src_port, dst_port, uri, frame_len = fields
            log_entry = f"TCP connection from {src_ip}:{src_port} to {dst_ip}:{dst_port} | HTTP request: {uri} | Packet length: {frame_len} bytes"
            logs.append(log_entry)
            print(logs)
        
        return logs


