#!/bin/bash

# Vérifie si le chemin est déjà présent
if grep -q "/snap/bin" /etc/environment; then
    echo "[✔] /snap/bin est déjà présent dans /etc/environment."
else
    echo "[+] Ajout de /snap/bin au PATH global..."

    # Sauvegarde le fichier avant modification
    sudo cp /etc/environment /etc/environment.bak

    # Lecture et mise à jour
    current_path=$(grep -oP '(?<=PATH=").*(?=")' /etc/environment)
    new_path="${current_path}:/snap/bin"
    sudo sed -i "s|PATH=\".*\"|PATH=\"${new_path}\"|" /etc/environment

    echo "[✔] PATH mis à jour avec succès."
    echo "[i] Ancien fichier sauvegardé dans /etc/environment.bak"
fi

echo "[!] Redémarre ta machine ou ta session pour que les changements soient appliqués."
