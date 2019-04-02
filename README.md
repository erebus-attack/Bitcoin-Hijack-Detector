
# Bitcoin hijacking detector

## Description

This project contains several scripts that altogether analyse the raw BGP update messages to detect large-scale synchronized Bitcoin hijacking attacks.

**Important note: We assume all the data is already available in /data.**

## Analysis of Bitcoin hijacking

* Select BGP update messages for prefix hosting at least one Bitcoin node IP
	````
	python3 select_btc_prefix.py
	````

* Detect Origin-AS (type 1) and Next-AS (type 2) BGP hijacking messages
	````
	python3 detect_hijacking_messages.py
	````

* Group BGP hijacking messages into incidents of 10-minute time window
	````
	python3 group_hijacking_messages.py
	````