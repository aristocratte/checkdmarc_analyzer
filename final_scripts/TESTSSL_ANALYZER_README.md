# 🔒 TESTSSL.SH ANALYZER

## Description

L'analyzeur testssl.sh est un outil puissant qui permet d'analyser les rapports de scan testssl.sh (format CSV) et de générer des rapports Excel complets avec analyse de sécurité, évaluation des vulnérabilités et recommandations.

## Fonctionnalités

✅ **Analyse unique CSV** - Analyse détaillée d'un seul scan testssl.sh  
✅ **Combinaison multiple CSV** - Combine plusieurs scans pour une analyse de domaine complète  
✅ **Rapports Excel** - Génère des rapports Excel avec graphiques et visualisations  
✅ **Scoring de sécurité** - Attribution de notes et grades de sécurité  
✅ **Priorisation des vulnérabilités** - Classement par criticité  
✅ **Vérification de conformité** - Vérification PCI DSS, NIST, etc.

## Installation

```bash
# Les dépendances sont installées avec le script d'installation principal
cd /home/root-02/Desktop/boc-tools/scripts/final_scripts
python3 install-tools-ultra-robust.py
```

## Utilisation

### Analyse d'un seul fichier CSV

```bash
# Rapport console uniquement
python3 testssl-analyzer.py scan.csv --console-only

# Rapport Excel complet
python3 testssl-analyzer.py scan.csv -o rapport_securite.xlsx
```

### Exemple avec le fichier fourni

```bash
# Analyse du scan bonplan.mobilierdefrance.com
python3 testssl-analyzer.py bonplan.mobilierdefrance.com_p443-20250616-0822.csv

# Résultat :
# 📊 Domain: bonplan.mobilierdefrance.com
# 🏆 Overall Grade: A+
# 📈 Security Score: 96/100
# 🔐 TLS 1.3 Support: ✅
# 🔒 TLS 1.2 Support: ✅
```

### Analyse de plusieurs fichiers CSV (combinaison)

```bash
# Combiner plusieurs scans du même domaine
python3 testssl-analyzer.py domain1_scan1.csv domain1_scan2.csv domain1_scan3.csv -o rapport_complet.xlsx

# Analyser plusieurs domaines
python3 testssl-analyzer.py domain1.csv domain2.csv domain3.csv -o multi_domaines.xlsx
```

## Format d'entrée

Le script attend des fichiers CSV générés par testssl.sh avec les colonnes suivantes :

- `id` : Identifiant du test
- `fqdn/ip` : FQDN ou adresse IP testée
- `port` : Port testé
- `severity` : Niveau de sévérité (OK, INFO, LOW, MEDIUM, HIGH, CRITICAL)
- `finding` : Résultat du test
- `cve` : CVE associée (si applicable)
- `cwe` : CWE associée (si applicable)

### Génération du CSV avec testssl.sh

```bash
# Scanner un domaine et générer le CSV
./testssl.sh --csvfile scan_results.csv https://example.com

# Scanner avec options avancées
./testssl.sh --csvfile detailed_scan.csv --full --protocols --ciphers --vulnerabilities https://example.com
```

## Structure du rapport Excel

Le rapport Excel généré contient 5 feuilles :

### 1. **Overview** 📊

- Résumé par domaine
- Grade de sécurité global
- Score de sécurité (/100)
- Nombre d'issues critiques/élevées
- Support TLS 1.2/1.3
- Nombre de vulnérabilités

### 2. **Detailed Analysis** 🔍

- Analyse détaillée de tous les tests
- Catégorisation des tests
- Statuts et résultats complets
- CVE et CWE associées

### 3. **Vulnerabilities** 🚨

- Liste des vulnérabilités détectées
- Priorisation par sévérité
- Descriptions techniques
- Recommandations de correction

### 4. **Recommendations** 💡

- Recommandations priorisées
- Actions à entreprendre
- Catégorisation par domaine
- Impact business

### 5. **Compliance** ✅

- Vérification PCI DSS
- Conformité aux standards
- Statut PASS/FAIL
- Notes de conformité

## Catégories d'analyse

Le script analyse les éléments suivants :

### 🔐 **Protocoles**

- SSLv2, SSLv3 (doivent être désactivés)
- TLS 1.0, 1.1 (déconseillés)
- TLS 1.2, 1.3 (recommandés)

### 🔑 **Chiffrements**

- Chiffrements NULL/faibles
- Chiffrements obsolètes
- Forward Secrecy
- Chiffrements forts

### 📜 **Certificats**

- Validité des certificats
- Chaîne de confiance
- Expiration
- OCSP Stapling

### 🐛 **Vulnérabilités**

- Heartbleed
- BEAST, CRIME, POODLE
- SWEET32, FREAK, DROWN
- LOGJAM, LUCKY13

## Scoring de sécurité

Le score de sécurité est calculé selon les poids suivants :

- **CRITICAL** : 100 points (échec critique)
- **HIGH** : 80 points (problème majeur)
- **MEDIUM** : 60 points (problème modéré)
- **LOW** : 40 points (problème mineur)
- **WARN** : 30 points (avertissement)
- **INFO** : 10 points (information)
- **OK** : 0 points (succès)

### Grades attribués

- **A+** : 95-100 points (Excellent)
- **A** : 90-94 points (Très bon)
- **A-** : 85-89 points (Bon)
- **B+** : 80-84 points (Satisfaisant)
- **B** : 75-79 points (Acceptable)
- **C** : 60-74 points (Médiocre)
- **D** : 50-59 points (Faible)
- **F** : 0-49 points (Échec)

## Exemples d'usage avancés

### Automatisation avec scripts

```bash
#!/bin/bash
# Script d'analyse automatisée

DOMAIN="example.com"
DATE=$(date +%Y%m%d-%H%M)

# Scanner le domaine
./testssl.sh --csvfile "${DOMAIN}_p443-${DATE}.csv" "https://${DOMAIN}"

# Analyser les résultats
python3 testssl-analyzer.py "${DOMAIN}_p443-${DATE}.csv" -o "rapport_${DOMAIN}_${DATE}.xlsx"

echo "Analyse terminée : rapport_${DOMAIN}_${DATE}.xlsx"
```

### Analyse comparative

```bash
# Comparer plusieurs scans du même domaine dans le temps
python3 testssl-analyzer.py \
  example.com_scan_janvier.csv \
  example.com_scan_fevrier.csv \
  example.com_scan_mars.csv \
  -o evolution_securite.xlsx
```

### Analyse multi-domaines

```bash
# Analyser la sécurité de plusieurs domaines
python3 testssl-analyzer.py \
  *.csv \
  -o rapport_infrastructure_complete.xlsx
```

## Interprétation des résultats

### ✅ **Bonnes pratiques détectées**

- TLS 1.3 activé
- Pas de protocoles obsolètes
- Forward Secrecy supporté
- Certificats valides
- Aucune vulnérabilité connue

### ⚠️ **Améliorations recommandées**

- Activation OCSP Stapling
- Mise à jour des chiffrements
- Configuration HSTS
- Optimisation des courbes elliptiques

### 🚨 **Problèmes critiques**

- Vulnérabilités connues
- Protocoles obsolètes activés
- Certificats expirés/invalides
- Chiffrements faibles

## Dépannage

### Erreur "Excel libraries not available"

```bash
# Installer les dépendances Excel
pip install openpyxl pandas
```

### Erreur de format CSV

Vérifiez que le CSV contient les colonnes requises :

```
"id","fqdn/ip","port","severity","finding","cve","cwe"
```

### Fichier non trouvé

```bash
# Vérifier l'existence du fichier
ls -la *.csv

# Utiliser le chemin complet
python3 testssl-analyzer.py /chemin/complet/vers/scan.csv
```

## Intégration CI/CD

### GitLab CI

```yaml
testssl_analysis:
  stage: security
  script:
    - ./testssl.sh --csvfile scan.csv https://production.example.com
    - python3 testssl-analyzer.py scan.csv -o security_report.xlsx
  artifacts:
    reports:
      junit: security_report.xlsx
    expire_in: 1 week
```

### GitHub Actions

```yaml
- name: SSL/TLS Security Analysis
  run: |
    ./testssl.sh --csvfile scan.csv https://${{ github.event.repository.name }}
    python3 testssl-analyzer.py scan.csv -o security_report.xlsx
- name: Upload Security Report
  uses: actions/upload-artifact@v2
  with:
    name: security-report
    path: security_report.xlsx
```

## Contribution

Pour contribuer à l'amélioration de l'outil :

1. Fork le repository
2. Créer une branche feature
3. Implémenter les améliorations
4. Tester avec différents types de scans
5. Soumettre une pull request

## Support

Pour obtenir de l'aide :

- Consulter les exemples d'usage
- Vérifier les logs d'erreur
- Tester avec `--console-only` d'abord
- Contacter l'équipe BOC Security Tools
