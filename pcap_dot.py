#!/usr/bin/env python3                                                                                                                                                                                                                                       
import sys, pyshark, pickle,csv,time
from pcapkit import IP, extract

def extract_pcap(input_file,in_flows={},debug=True):
    e = extract(fin=input_file,nofile=True)
    flows = in_flows
   
    if debug:
      print (f"Found {e.length} packets")

    for p in range(0,e.length):
        if IP in e.frame[p]:
            ip = e.frame[p][IP]
            (src_ip, dst_ip) =  (str(ip.src),str(ip.dst))
            if src_ip not in flows:
                flows[src_ip] = []                         
                if debug:
                    print ("New src",src_ip)
            if dst_ip not in flows[src_ip]:
                flows[src_ip].append(dst_ip)               
                if debug:
                    print ("New dst",dst_ip)
    return flows                          


def shark_pcap(input_file,in_flows={},debug=False):
    cap = pyshark.FileCapture(input_file)
    flows = in_flows
    for e in cap:                                              
        if 'IP' in e:                          
            if 'TCP' in e or 'UDP' in e:        
                (src_eth,src_ip, dst_eth,dst_ip) =  (e.eth.src,e.ip.src,e.eth.dst,e.ip.dst)                                   
                if src_ip not in flows:
                    flows[src_ip] = []                         
                    if debug:
                        print ("New src",src_ip)
                if dst_ip not in flows[src_ip]:
                    flows[src_ip].append(dst_ip)               
                    if debug:
                        print ("New dst",dst_ip)
    return flows                          

def dump_flow(flows):
    print(flows)
    for src in flows.keys():
        print("=== SRC:",src)
        print("  ",flows[src])

def enrich_dict(data,lookup_file):
    """
        falco-falcosidekick-746c76f858-qgx96,10.42.1.41
        falco-falcosidekick-ui-7bbfd79c5-282tl,10.42.1.42
    """
    lookup_table = {}
    out_dict = {}

    with open(lookup_file, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            name, ip_address = row
            lookup_table[ip_address] = name

    print(lookup_table)

    for k in data.keys():
        print(f"Checking {k} in Lookup") 
        if k in lookup_table:
            # Replace keys
            out_dict[k + "\n("+ lookup_table[k] +")"] = data[k]
            # inefficient AF
            for v in data[k]:
                if v in lookup_table:
                    data[k].remove(v)
                    data[k].append(v + "\n("+ lookup_table[v] +")")

    print (out_dict) 

    return(out_dict)

def dict_to_dot(data,dotfile="cluster-"):
    dot_string = "digraph G {\n"
    for node, connections in data.items():
        for connection in connections:
            dot_string += f'  "{node}" -> "{connection}";\n'
    dot_string += "}"

    with open(dotfile+str(int(time.time()))+".dot", "w") as f:
        f.write(dot_string)

def pickle_dump(flows, output_file):
    with open(output_file, 'wb') as handle:                    
        pickle.dump(flows, handle)
                                                         
def pickle_load(input_file):
    with open(input_file, 'rb') as handle:
        b = pickle.load(handle)
    return b                                 
                                                         
if __name__ == "__main__":        
    if len(sys.argv) < 2:
        print ("Usage:\n shark.py <pcap> [pickle]")
    else:
        # Use a pickle file
        if len (sys.argv) > 3:
            if os.exists(sys.argv[2]):
                loaded_flows = pickle_load(sys.argv[2])
        else:
            f = extract_pcap(sys.argv[1])
            g = enrich_dict(f,"lookup.csv")
            dict_to_dot(g)
