#!/bin/bash
# ==========================================================
# Advanced Payload Tester - XSS / SQLi
# Features:
#   * Supports GET or POST requests
#   * Accepts multiple parameter names (comma-separated)
#   * Logs all results to CSV and TXT
#   * Logs successful payloads to separate file
# ==========================================================

# === Color Codes ===
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# === File Paths ===
TARGETS_FILE="logs/targets.txt"
XSS_PAYLOADS="payloads/xss_payloads.txt"
SQLI_PAYLOADS="payloads/sqli_payloads.txt"
OUTPUT_FILE="logs/test_results.txt"
CSV_OUTPUT="logs/test_results.csv"
SUCCESS_FILE="logs/success_payloads.txt"
TMP_RESPONSE="logs/tmp_response.html"

mkdir -p logs

# === Target Selection ===
echo -e "\n${YELLOW}Test edilecek hedef ortamı seçin:${NC}"
echo "1) Manuel hedef (logs/targets.txt kullanılır)"
echo "2) OWASP Juice Shop (http://localhost:3000)"
read -p "Seçiminiz (1-2): " TARGET_CHOICE


case "$TARGET_CHOICE" in
    1)
        echo -e "${YELLOW}Manuel hedefler logs/targets.txt dosyasından okunacak.${NC}"
        ;;
    2)
        echo "http://localhost:3000" > "$TARGETS_FILE"
        echo -e "${GREEN}Juice Shop hedefi eklendi: logs/targets.txt${NC}"
        ;;
    *)
        echo -e "${RED}❌ Geçersiz hedef seçimi.${NC}"
        exit 1
        ;;
esac

# === Interactive Menu ===
echo -e "\n${YELLOW}==== PAYLOAD TEST MENÜSÜ ====${NC}"
echo "1) XSS Payload Testi"
echo "2) SQLi Payload Testi"
read -p "Seçiminiz (1-2): " ATTACK_CHOICE

# === HTTP Method ===
echo -e "\n${YELLOW}HTTP yöntemi seç:${NC}"
echo "1) GET"
echo "2) POST"
read -p "Seçiminiz (1-2): " METHOD_CHOICE

if [[ "$METHOD_CHOICE" == "1" ]]; then
    HTTP_METHOD="GET"
elif [[ "$METHOD_CHOICE" == "2" ]]; then
    HTTP_METHOD="POST"
else
    echo -e "${RED}❌ Geçersiz HTTP yöntemi.${NC}"
    exit 1
fi

# === Parameter Names ===
read -p "Parametre adlarını virgülle ayırarak gir (örn: q,search,input): " PARAM_INPUT
IFS=',' read -ra PARAM_ARRAY <<< "$PARAM_INPUT"
if [[ "${#PARAM_ARRAY[@]}" -eq 0 ]]; then
    echo -e "${RED}❌ En az bir parametre adı gerekli.${NC}"
    exit 1
fi

# === Payload file selection ===
if [[ "$ATTACK_CHOICE" == "1" ]]; then
    PAYLOAD_FILE="$XSS_PAYLOADS"
    MODE="XSS"
elif [[ "$ATTACK_CHOICE" == "2" ]]; then
    PAYLOAD_FILE="$SQLI_PAYLOADS"
    MODE="SQLi"
else
    echo -e "${RED}❌ Geçersiz saldırı seçimi.${NC}"
    exit 1
fi

# === Pre-check files ===
for FILE in "$TARGETS_FILE" "$PAYLOAD_FILE"; do
    if [[ ! -f "$FILE" || ! -s "$FILE" ]]; then
        echo -e "${RED}❌ Gerekli dosya eksik veya boş: $FILE${NC}"
        exit 1
    fi
done

# === Initialize output files ===
> "$OUTPUT_FILE"
> "$SUCCESS_FILE"
echo "Attack_Type,HTTP_Method,Status_Code,Target_URL,Payload,Result" > "$CSV_OUTPUT"

# === Function to send request ===
send_request () {
    local url="$1"
    local data="$2"
    local status
    if [[ "$HTTP_METHOD" == "GET" ]]; then
        status=$(curl -s -o "$TMP_RESPONSE" -w "%{http_code}" "$url")
    else
        status=$(curl -s -o "$TMP_RESPONSE" -w "%{http_code}" -X POST -d "$data" "$url")
    fi
    echo "$status"
}

# === Main loop ===
while IFS= read -r TARGET; do
    echo -e "\n${YELLOW}🎯 Hedef: $TARGET${NC}"
    while IFS= read -r PAYLOAD; do
        ENCODED=$(printf %s "$PAYLOAD" | jq -s -R -r @uri)

        for PARAM in "${PARAM_ARRAY[@]}"; do
            if [[ "$HTTP_METHOD" == "GET" ]]; then
                QUERY_STRING=""
                FIRST=1
                for P in "${PARAM_ARRAY[@]}"; do
                    VAL="test"
                    [[ "$P" == "$PARAM" ]] && VAL="$ENCODED"
                    [[ $FIRST -eq 1 ]] && QUERY_STRING="${P}=${VAL}" || QUERY_STRING="${QUERY_STRING}&${P}=${VAL}"
                    FIRST=0
                done
                REQUEST_URL="${TARGET}?${QUERY_STRING}"
                STATUS=$(send_request "$REQUEST_URL" "")
            else
                POST_DATA=""
                FIRST=1
                for P in "${PARAM_ARRAY[@]}"; do
                    VAL="test"
                    [[ "$P" == "$PARAM" ]] && VAL="$ENCODED"
                    [[ $FIRST -eq 1 ]] && POST_DATA="${P}=${VAL}" || POST_DATA="${POST_DATA}&${P}=${VAL}"
                    FIRST=0
                done
                REQUEST_URL="$TARGET"
                STATUS=$(send_request "$REQUEST_URL" "$POST_DATA")
            fi

            RESULT="BLOCKED"
            if [[ "$MODE" == "XSS" ]]; then
                grep -q "$PAYLOAD" "$TMP_RESPONSE" && RESULT="SUCCESS"
            else
                grep -qi "sql syntax\|mysql_fetch\|ORA-" "$TMP_RESPONSE" && RESULT="VULNERABLE" || RESULT="CLEAN"
            fi

            LOG_LINE="[${MODE}] $STATUS | $HTTP_METHOD | $REQUEST_URL | Param: $PARAM | $RESULT"
            if [[ "$RESULT" == "SUCCESS" || "$RESULT" == "VULNERABLE" ]]; then
                echo -e "${GREEN}$LOG_LINE ✅${NC}" | tee -a "$OUTPUT_FILE" "$SUCCESS_FILE"
            else
                echo -e "${RED}$LOG_LINE ❌${NC}" | tee -a "$OUTPUT_FILE"
            fi
            echo "${MODE},${HTTP_METHOD},${STATUS},${REQUEST_URL},"${PAYLOAD}",${RESULT}" >> "$CSV_OUTPUT"
        done
    done < "$PAYLOAD_FILE"
done < "$TARGETS_FILE"

echo -e "${GREEN}\n✅ Test tamamlandı. Detay: $OUTPUT_FILE"
echo -e "⭐ Başarılı payloadlar: $SUCCESS_FILE"
echo -e "📊 CSV çıktı: $CSV_OUTPUT${NC}"
rm -f "$TMP_RESPONSE"
