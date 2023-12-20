#!/bin/bash

# WDT normal
python3 /home/sj/BA_stuff/BA_transcriber/ipal-transcriber \
	--pcap "/home/sj/BA_stuff/datasets/WDT/raw/Network datatset/pcap/normal.pcap" \
	--log info \
	--logfile "/home/sj/BA_stuff/transcribed_pcaps/WDT/normal.log" \
	--malicious.default "false" \
	--malicious "/home/sj/BA_stuff/datasets/WDT/attacks.json" \
	--protocols tcp modbus \
	--ipal.output "/home/sj/BA_stuff/transcribed_pcaps/WDT/normal.out" \
	--rules "/home/sj/BA_stuff/datasets/WDT/utils/rules.py"

# WDT attack1
python3 /home/sj/BA_stuff/BA_transcriber/ipal-transcriber \
	--pcap "/home/sj/BA_stuff/datasets/WDT/raw/Network dataset/pcap/attack_1.pcap" \
	--log info \
	--logfile "/home/sj/BA_stuff/transcribed_pcaps/WDT/attack_1.log" \
	--malicious.default "false" \
	--malicious "/home/sj/BA_stuff/datasets/WDT/attacks.json" \
	--protocols tcp modbus \
	--ipal.output "/home/sj/BA_stuff/transcribed_pcaps/WDT/attack_1.out" \
	--rules "/home/sj/BA_stuff/datasets/WDT/utils/rules.py"

# WDT attack2
python3 /home/sj/BA_stuff/BA_transcriber/ipal-transcriber \
	--pcap "/home/sj/BA_stuff/datasets/WDT/raw/Network dataset/pcap/attack_2.pcap" \
	--log info \
	--logfile "/home/sj/BA_stuff/transcribed_pcaps/WDT/attack_2.log" \
	--malicious.default "false" \
	--malicious "/home/sj/BA_stuff/datasets/WDT/attacks.json" \
	--protocols tcp modbus \
	--ipal.output "/home/sj/BA_stuff/transcribed_pcaps/WDT/attack_2.out" \
	--rules "/home/sj/BA_stuff/datasets/WDT/utils/rules.py"

# WDT attack3
python3 /home/sj/BA_stuff/BA_transcriber/ipal-transcriber \
	--pcap "/home/sj/BA_stuff/datasets/WDT/raw/Network dataset/pcap/attack_3.pcap" \
	--log info \
	--logfile "/home/sj/BA_stuff/transcribed_pcaps/WDT/attack_3.log" \
	--malicious.default "false" \
	--malicious "/home/sj/BA_stuff/datasets/WDT/attacks.json" \
	--protocols tcp modbus \
	--ipal.output "/home/sj/BA_stuff/transcribed_pcaps/WDT/attack_3.out" \
	--rules  "/home/sj/BA_stuff/datasets/WDT/utils/rules.py"

# WDT attack4
python3 /home/sj/BA_stuff/BA_transcriber/ipal-transcriber \
        --pcap "/home/sj/BA_stuff/datasets/WDT/raw/Network dataset/pcap/attack_4.pcap" \
        --log info \
        --logfile "/home/sj/BA_stuff/transcribed_pcaps/WDT/attack_4.log" \
        --malicious.default "false" \
        --malicious "/home/sj/BA_stuff/datasets/WDT/attacks.json" \
        --protocols tcp modbus \
        --ipal.output "/home/sj/BA_stuff/transcribed_pcaps/WDT/attack_4.out" \
        --rules  "/home/sj/BA_stuff/datasets/WDT/utils/rules.py"
