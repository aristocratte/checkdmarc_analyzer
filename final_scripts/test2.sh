#!/bin/bash

# --- CONFIGURATION ---
DOMAINE="$1"
OUTPUT_DIR="./recon_$DOMAINE"
FINAL_OUTPUT="$OUTPUT_DIR/liens_indirects_final.txt"

# Créer le dossier de sortie
mkdir -p "$OUTPUT_DIR"

echo "[*] Début de la reconnaissance pour $DOMAINE"
echo "[*] Résultats dans $FINAL_OUTPUT"

# --- 1. WHOIS + intel avec Amass ---
echo "[*] Amass intel (WHOIS)..."
amass intel -d "$DOMAINE" -whois -ip -o "$OUTPUT_DIR/amass_whois.txt"

# --- 2. Certificats SSL via crt.sh ---
echo "[*] Recherche CRT.SH..."
curl -s "https://crt.sh/?q=%25$DOMAINE&output=json" | jq -r '.[].name_value' | sort -u > "$OUTPUT_DIR/crtsh_certs.txt"

# --- 3. Wayback Machine urls ---
echo "[*] Waybackurls..."
echo "$DOMAINE" | waybackurls > "$OUTPUT_DIR/waybackurls.txt"

# --- 4. SecurityTrails (si clé API dispo) ---
# Remplace ta clé ici si besoin
SECURITYTRAILS_API_KEY="o6Le3kszIZE1Akzkos1W-j0e8H2OmoMh"
if [ ! -z "$SECURITYTRAILS_API_KEY" ]; then
    echo "[*] SecurityTrails domains..."
    curl -s -H "APIKEY: $SECURITYTRAILS_API_KEY" "https://api.securitytrails.com/v1/domain/$DOMAINE/subdomains" \
    | jq -r '.subdomains[]' | sed "s/^/https:\/\/&.$DOMAINE/" > "$OUTPUT_DIR/securitytrails_domains.txt"
else
    echo "[!] SecurityTrails API non configurée, étape sautée."
fi

# --- Fusion des résultats ---
echo "[*] Fusion des résultats..."
cat "$OUTPUT_DIR"/*.txt | sort -u > "$FINAL_OUTPUT"

echo "[*] Terminé ! Fichier final : $FINAL_OUTPUT"
echo "[*] Nombre total de lignes uniques : $(wc -l < "$FINAL_OUTPUT")"
