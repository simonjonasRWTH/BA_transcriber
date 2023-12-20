#!/usr/bin/env bash
TRANSCRIBER="/home/sj/BA_stuff/BA_transcriber/ipal-transcriber --malicious.default false"

DIR=/home/sj/BA_stuff/transcribed_pcaps/Geek
python3 /home/sj/BA_stuff/BA_transcriber/ipal-transcriber \
	--pcap "/home/sj/BA_stuff/datasets/GeekLounge/raw/4SICS-GeekLounge-151022.pcap" \
	--log info \
	--logfile $DIR/Geek.log \
	--protocol s7 tcp \
	--ipal.output $DIR/Geek.out \
