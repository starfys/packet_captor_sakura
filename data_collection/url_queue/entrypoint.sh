#!/bin/bash
touch /pcap_data/report.json
chown 1000 /pcap_data/report.json
chgrp 1000 /pcap_data/report.json

sudo -u $DEFAULT_USER -E ./bin/url_queue config.toml
