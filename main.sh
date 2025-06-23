#!/bin/bash

# === RENKLER ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# === DOSYALAR ===
LOG_DIR="logs"
TARGET_FILE="$LOG_DIR/targets.txt"
mkdir -p "$LOG_DIR"

# === URL REGEX ===
URL_REGEX="^(https?:\/\/)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(:[0-9]+)?(\/.*)?$"

# === ANA MENÜ ===
while true; do
    echo -e "\n${YELLOW}==== CUSTOM WAF BYPASS — HEDEF YÖNETİM MENÜSÜ ====${NC}"
    echo "1) Yeni hedef URL ekle"
    echo "2) Kayıtlı hedefleri görüntüle"
    echo "3) Hedef listesini temizle"
    echo "4) Çıkış"
    read -p "Seçiminiz [1-4]: " choice

    case $choice in

        1)
            read -p "Hedef URL girin (örn: https://example.com): " TARGET_URL

            if [[ -z "$TARGET_URL" ]]; then
                echo -e "${RED}❌ Hata: URL boş olamaz.${NC}"
            elif ! [[ $TARGET_URL =~ $URL_REGEX ]]; then
                echo -e "${RED}❌ Hatalı URL formatı.${NC}"
            elif grep -Fxq "$TARGET_URL" "$TARGET_FILE"; then
                echo -e "${YELLOW}⚠️ Bu URL zaten kayıtlı.${NC}"
            else
                echo "$TARGET_URL" >> "$TARGET_FILE"
                echo -e "${GREEN}✅ URL başarıyla eklendi.${NC}"
            fi
            ;;
        
        2)
            if [[ -s "$TARGET_FILE" ]]; then
                echo -e "${GREEN}📄 Kayıtlı Hedefler:${NC}"
                cat "$TARGET_FILE"
            else
                echo -e "${YELLOW}⚠️ Henüz hedef URL kaydedilmemiş.${NC}"
            fi
            ;;
        
        3)
            read -p "⚠️ Tüm hedefleri silmek istediğinize emin misiniz? (e/h): " confirm
            if [[ "$confirm" == "e" || "$confirm" == "E" ]]; then
                > "$TARGET_FILE"
                echo -e "${RED}🗑️ Hedef listesi temizlendi.${NC}"
            else
                echo -e "${YELLOW}İşlem iptal edildi.${NC}"
            fi
            ;;

        4)
            echo -e "${GREEN}👋 Çıkış yapılıyor... Görüşürüz kuzen!${NC}"
            exit 0
            ;;

        *)
            echo -e "${RED}❌ Geçersiz seçim. Lütfen 1-4 arasında bir değer girin.${NC}"
            ;;
    esac
done
