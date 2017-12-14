#!/bin/sh
URL=https://torstatus.blutmagie.de/query_export.php/Tor_query_EXPORT.csv

wget $URL -O ~/data/cs587/tornodes-`date +%Y%m%d`.csv
