# k3s-pcap

These are network scripts to help visualize networking of homelab K3S clusters

See (Python Packet Libraries)[https://github.com/mdfranz/cheetsheetz/blob/main/python/packet.md]

# Installation

Assuming you have [uv](https://docs.astral.sh/uv/) installed, create a virtual environment 

```
mfranz@cros-acer516ge:~/github/k3s-pcap$ uv venv
Using CPython 3.11.2 interpreter at: /usr/bin/python3
Creating virtual environment at: .venv
Activate with: source .venv/bin/activate
mfranz@cros-acer516ge:~/github/k3s-pcap$ source .venv/bin/activate
(k3s-pcap) mfranz@cros-acer516ge:~/github/k3s-pcap$
``` 

Then install the depedencies
```
$ uv pip install -r requirements.txt
Resolved 25 packages in 861ms
Prepared 25 packages in 2.47s
Installed 25 packages in 83ms
 + aenum==3.1.15
 + appdirs==1.4.4
 + blessed==1.20.0
 + bpython==0.24
 + certifi==2024.8.30
 + chardet==5.2.0
 + charset-normalizer==3.4.0
 + curtsies==0.4.2
 + cwcwidth==0.1.9
 + dictdumper==0.8.4.post6
 + greenlet==3.1.1
 + idna==3.10
 + lxml==5.3.0
 + packaging==24.2
 + pygments==2.18.0
 + pypcapkit==1.3.3.post1
 + pyshark==0.6
 + pyxdg==0.28
 + requests==2.32.3
 + scapy==2.6.1
 + six==1.16.0
 + tbtrim==0.3.1
 + termcolor==2.5.0
 + urllib3==2.2.3
 + wcwidth==0.2.13
 ```

## Traffic Captured

I captured traffic on `cni0` and `flannel.1` across multiple nodes, using `mergecap` to combine into a single PCAP and `tcpdump` to convert back from PCAPNG to PCAP.

# Generating Resolution File

Then generated the lookup table with the following commands

```
kubectl get services -A -o go-template='{{range .items}}{{.metadata.name}},{{.spec.clusterIP}}{{"\n"}}{{end}}'
```

and

```
kubectl get pods -A -o go-template='{{range .items}}{{.metadata.name}},{{.status.podIP}}{{"\n"}}{{end}}'
```


