# Tryhackme Dig Dug writeup

## Room information 

* Link https://tryhackme.com/room/digdug
* IP 10.10.225.85

### Prelude
On the room Dig dug there is a small text "hint" for the box as shown below.

*"Oooh, turns out, this MACHINE_IP machine is also a DNS server! If we could dig into it, I am sure we could find some interesting records! But... it seems weird, this only responds to a special type of request for a givemetheflag.com domain?"*


## Get The flag
So using the hint from the room, running the dig tool form the commandling

```
$ dig @10.10.225.85 givemetheflag.com

; <<>> DiG 9.18.1-1-Debian <<>> @10.10.225.85 givemetheflag.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 58226
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;givemetheflag.com.             IN      A

;; ANSWER SECTION:
givemetheflag.com.      0       IN      TXT     "REDACTED-FLAG"

;; Query time: 32 msec
;; SERVER: 10.10.225.85#53(10.10.225.85) (UDP)
;; WHEN: Sun May 29 08:01:54 EDT 2022
;; MSG SIZE  rcvd: 86

```

From the output the flag i visible in a txt record