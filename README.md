# Man-in-the-Middle Attack on Unverified TLS Connections

This is a demonstration project showing the potential damage of unverified TLS connections. The attack is accomplished by ARP spoofing and a simple man-in-the-middle HTTPS server (hereinafter referred to as "middle man"). In this demo, all HTTPS traffic between the victim machine (hereinafter referred to as "victim") and the servers in the IP range 140.113/16 held by NYCU (hereinafter referred to as "servers") is intercepted and redirected to the middle man. The goal is to sniff the inputted ID and password to log into [portal.nycu.edu.tw](https://portal.nycu.edu.tw).

# Prerequisites

- At least one victim machine with Google Chrome installed
- One attack machine with Python 3.8 or later and `dsniff` installed (for `arpspoof`)
- These machines should be able to ping each other within a LAN
- It is recommended to use virtual machines

# Steps

## Attack Machine

### Enable IP forwarding

Enable IP forwarding to allow traffic to go through the attack machine.

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

### Perform ARP spoofing

Perform ARP spoofing on both the victim and the gateway. This is because the traffic between the victim and the servers definitely goes through the gateway. If the attack is successful, the man-in-the-middle scenario holds. All traffic between the victim and the gateway will now go through this machine. The interface name and the gateway IP can be found with `route -n`. The victim IP can be found through IP scanning within the LAN or just by opening a terminal on the victim machine and executing `ifconfig`. Note that at this step, all HTTPS traffic between the victim and the servers is protected via TLS. To be able to get the plaintext HTTP message, the middle man should pretend to be the server to the victim and establish the TLS connection with the victim.

```bash
sudo arpspoof -i <interface name> -c both -t <victim IP> -r <gateway IP>
```

### Set the NAT table

Open a new terminal for the following commands. Clear the NAT table of the `iptables` firewall and add a new rule to redirect incoming HTTPS packets destined for 140.113/16 to this machine on port 8080. The middle man will listen on that port. At this step, the browser on the victim machine will show "This site can't be reached" for all HTTPS connections to the servers.

```bash
sudo iptables -t nat -F && \
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -m iprange \
  --dst-range 140.113.0.0-140.113.255.255 -j REDIRECT --to-port 8080
```

### Generate self-signed certificate

Generate a forged self-signed certificate for \*.nycu.edu.tw. It is used to establish the TLS connection between the victim and the middle man. Since the victim is assumed not to verify the legality of the certificate, using the generated certificate is fine. If the attacker has access to the victim machine, a malicious CA certificate can be installed so that all certificates signed by that CA certificate can pass the TLS verification, which allows the attack to be more covert.

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
  "ocw.nycu.edu.tw"
```

# The Man-in-the-Middle Server

The `attack.py` implements the man-in-the-middle server with pure Python standard library. The main job of the middle man is to establish two TLS connections, one between the victim and the middle man and one between the middle man and the server. Each time the middle man receives a decrypted HTTP message, it checks if the message body carries the desired information and sends the HTTP message to the server. Then it waits for the response from the server. Once it receives a response, it can samely check the message body and should send the message back to victim. It is tested with the listed websites as shown in the command in [Browse the web](#browse-the-web). The code should be self-explaining.

One thing to note is that for [ocw.nycu.edu.tw](https://ocw.nycu.edu.tw), its certificate chain is not complete (check [https://www.ssl.org/report/ocw.nycu.edu.tw](https://www.ssl.org/report/ocw.nycu.edu.tw)) and thus cannot pass the TLS verification on the middle man side. In such a case, the middle man will instead choose not to verify the TLS certificate as the victim. It is fine since the security of the connection is not a consideration for this attack. However, this introduces the opportunity to launch another man-in-the-middle attack between the middle man and the server, which forms the middle man version of The Human Centipede.

# Disclaimer

The content provided in this repository is for educational purposes only. Launching such an attack on another person without consent is against the law. The script `attack.py` is part of a course project in the course Network Security at NYCU CS. Do not plagiarize the script if you are a student doing similar coursework.
