#!/bin/bash
dir=/home/sj/BA_stuff/datasets/Lemay/
transcriber=/home/sj/BA_stuff/BA_transcriber/ipal-transcriber
out_dir=/home/sj/BA_stuff/transcribed_pcaps/Lemay
: '
#normal
for filename in $dir/raw/normal/*.pcap
do
	f=$(basename $filename)
        python3 ${transcriber} \
                --pcap $dir/raw/normal/$f \
                --log INFO \
                --logfile $dir/raw/normal/$f.log \
                --ipal.output $dir/raw/normal/$f.out \
                --protocols modbus tcp
done

#attack
python3 ${transcriber} \
	--pcap $dir/raw/attack/characterization_modbus_6RTU_with_operate.pcap \
        --log INFO \
	--logfile $dir/raw/attack/characterization_modbus_6RTU_with_operate.log \
       	--ipal.output $dir/raw/attack/CnC_uploading_exe_modbus_6RTU_with_operate.out \
        --protocols modbus tcp \
        --malicious $dir/attacks-characterization_modbus_6RTU_with_operate.json

python3 ${transcriber} \
        --pcap $dir/raw/attack/CnC_uploading_exe_modbus_6RTU_with_operate.pcap \
        --log INFO \
        --logfile $dir/raw/attack/CnC_uploading_exe_modbus_6RTU_with_operate.log \
        --ipal.output $dir/raw/attack/CnC_uploading_exe_modbus_6RTU_with_operate.out \
        --protocols modbus tcp \
        --malicious $dir/attacks-CnC_uploading_exe_modbus_6RTU_with_operate.json

python3 ${transcriber} \
        --pcap $dir/raw/attack/exploit_ms08_netapi_modbus_6RTU_with_operate.pcap \
        --log INFO \
        --logfile $dir/raw/attack/exploit_ms08_netapi_modbus_6RTU_with_operate.out\
        --ipal.output $dir/raw/attack/exploit_ms08_netapi_modbus_6RTU_with_operate.log \
        --protocols modbus tcp \
        --malicious $dir/attacks-exploit_ms08_netapi_modbus_6RTU_with_operate.json

python3 ${transcriber} \
        --pcap $dir/raw/attack/moving_two_files_modbus_6RTU.pcap \
        --log INFO \
        --logfile $dir/raw/attack/moving_two_files_modbus_6RTU.log \
        --ipal.output $dir/raw/attack/moving_two_files_modbus_6RTU.out \
        --protocols modbus tcp \
        --malicious $dir/attacks-moving_two_files_modbus_6RTU.json

python3 ${transcriber} \
        --pcap $dir/raw/attack/send_a_fake_command_modbus_6RTU_with_operate.pcap \
        --log INFO \
        --logfile $dir/raw/attack/send_a_fake_command_modbus_6RTU_with_operate.log \
        --ipal.output $dir/raw/attack/send_a_fake_command_modbus_6RTU_with_operate.out \
        --protocols modbus tcp \
        --malicious $dir/attacks-send_a_fake_command_modbus_6RTU_with_operate.json
'
#channel
for filename in $dir/raw/channel/*.pcap
do
        f=$(basename $filename)

	python3 ${transcriber} \
		--pcap $dir/raw/channel/$f \
		--log INFO \
		--logfile $dir/raw/channel/$f.log \
		--ipal.output $dir/raw/channel/$f.out \
		--protocols modbus tcp
done
mv ./normal/*.log $out_dir/normal/
mv ./attack/*.log $out_dir/attack/
mv ./channel/*.log $out_dir/channel/
mv ./normal/*.out $out_dir/normal/
mv ./attack/*.out $out_dir/attack/
mv ./channel/*.log $out_dir/normal/
