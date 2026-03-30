# ARPspoof

```
usage: ARPspoof.py [-h] -t TARGET -i INTERFACE [--both]

options:
  -h, --help            show this help message and exit
  -t, --target TARGET   Target IP
  -i, --interface INTERFACE (eth0, wlan0)
  --both                Enable full MITM (victim <-> gateway)
```
```
python3 ARPspoof.py -i eth0 -t 10.0.2.9 --both
```
