# track-host

Rapidly requests logs to your McAfee SIEM and sort results groupped by host to track a user or host.

### Install
```bash
git clone https://github.com/mfesiem/track-host
cd track-host
pip install -r requirements.txt
```

### Configure

Setup [msiempy config file](https://github.com/mfesiem/msiempy#authentication-and-configuration-setup)

### Usage

Search based on a username
```
python3 track.py -t last_24_hours --user tristan
```

Search based on a IP
```
python3 track.py -t last_24_hours --ip 10.0.0.1
```

Search based on a hostname
```
python3 track.py -t last_24_hours --host Tristans-MBP
```

Search based on a Macaddress
```
python3 track.py -t last_24_hours --macaddr BC:EE:7B:00:00:00
```