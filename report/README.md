# Tor Systems Fingerprinting and Availability

This is a small research project for UIC fall 2017 CS 587.

Censorship poses one of the more obvious, but difficult to combat
availability threats of the Tor network.  We survey the literature on
Tor traffic and systems fingerprinting.  We also summarize some
rudimentary Tor network measurement we have performed.  We conclude with
with some thoughts for further exploration in this area.

## Bridges

Tor bridges are entry relay nodes that are not widely published or
disseminated.  Since these relays are essentially otherwise like any
other Tor node, they are susceptible to passive and active
fingerprinting attacks.

## Tools

*nmap* scan was run like this:

```
parse-tor-csv.pl tornodes-YYYYmmdd.csv |
    awk '{print $1}' |
    sudo nmap -iL - -A -T4 -oX tornodes-YYYYmmdd.nmap-A-T4.xml
```

*dnsdb* look ups on list tor nodes:

```
for each in `./parse-tor.csv.pl tornodes-YYYYmmdd.csv | awk '{print $1}'`
do
    dnsdb_query.py -i $each -j > dnsdb/YYYYmmdd/$each.dnsdb 2> dnsdb/YYYYmmdd/$each.err
done
```

## References

* [Tor directory specification](https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt)  
  Details HTTP methods and files relays should support (e.g. hostname:port/tor/keys/all[.z]
* nmap version info /usr/share/nmap/nmap-service-probes
