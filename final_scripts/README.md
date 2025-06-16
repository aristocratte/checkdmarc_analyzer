# 🔍 Scripts d'Analyse de Domaines - Guide Complet

## 📋 Vue d'ensemble

Ce dossier contient un ensemble complet de scripts Python pour l'analyse automatisée de domaines et la génération de rapports de sécurité. Le workflow principal utilise `automation.py` pour exécuter plusieurs outils de reconnaissance, suivi de `excel_security_dashboard.py` pour générer des dashboards Excel professionnels.

---

## 🚀 Workflow Principal Recommandé

### Étape 1: Analyse Automatisée (`automation.py`)

```bash
python3 automation.py
```

Le script exécute 5 étapes de reconnaissance avec possibilité d'ignorer individuellement chaque étape :

1. **🔍 STEP 1/5: AMASS INTEL** - Collecte d'informations initiales
2. **🌐 STEP 2/5: AMASS ENUM** - Énumération des sous-domaines
3. **🔍 STEP 3/5: NMAP** - Scan des ports et services
4. **📧 STEP 4/5: CheckDMARC** - Analyse des configurations email (génère des JSON)
5. **🔒 STEP 5/5: TestSSL** - Analyse SSL/TLS

**✨ Nouveauté :** Chaque étape peut être ignorée individuellement. Si vous répondez "no" à une étape, le script continue automatiquement à l'étape suivante.

### Étape 2: Génération du Dashboard Excel

```bash
# Option 1: Assistant interactif (recommandé)
./generate_excel_dashboard.sh

# Option 2: Script direct
source venv_dashboard/bin/activate
python3 excel_security_dashboard.py /chemin/vers/dossier/checkdmarc/
```

---

## 📄 Scripts Disponibles

### 🤖 **`automation.py`** - Script Principal d'Automatisation

**Workflow complet de reconnaissance de domaines avec 5 étapes configurables.**

#### 🎯 Fonctionnalités

- **Reconnaissance passive/active** selon le mode choisi
- **Continuation intelligente** : Possibilité d'ignorer chaque étape individuellement
- **Messages en anglais** pour une meilleure compatibilité internationale
- **Interface utilisateur améliore** avec indicateurs visuels (🔍🌐📧🔒)
- **Gestion d'erreurs robuste** avec messages explicites
- **Outputs organisés** dans des dossiers par outil

#### 📊 Outils Intégrés

- **Amass** (intel + enum) : Découverte de sous-domaines
- **Nmap** : Scan de ports et détection de services
- **CheckDMARC** : Analyse des configurations email (SPF/DMARC/DKIM)
- **TestSSL** : Audit de sécurité SSL/TLS

### 📊 **`excel_security_dashboard.py`** - Générateur de Dashboard Excel

**Transforme les résultats JSON de CheckDMARC en dashboard Excel professionnel.**

#### 🏆 Fonctionnalités du Dashboard

- **5 Feuilles spécialisées** :
  - 📋 **Vue d'ensemble** : Statistiques globales et scores
  - 🔍 **Détails par domaine** : Analyse détaillée de chaque domaine
  - ⚠️ **Matrice de risques** : Classification des vulnérabilités
  - 📝 **Plan d'action** : Recommandations prioritaires
  - 📊 **Données brutes** : Données complètes pour analyse

#### 🎯 Système de Scoring Intelligent (0-100 points)

- **SPF présent** : +10 points
- **SPF strict** : +15 points
- **DMARC présent** : +20 points
- **DMARC policy strict** : +25 points
- **DMARC RUA configuré** : +10 points
- **DMARC PCT à 100%** : +10 points
- **STARTTLS activé** : +10 points

#### 🎨 Interface Professionnelle

- **Code couleur** : Rouge (critique), Jaune (attention), Vert (sécurisé)
- **Tableaux Excel** avec filtres automatiques
- **Mise en forme conditionnelle** pour identification rapide des problèmes
- **Graphiques intégrés** pour visualisation des données

### 🛠️ **`generate_excel_dashboard.sh`** - Assistant Interactif

**Script d'assistance pour simplifier la génération des dashboards Excel.**

#### ✨ Fonctionnalités

- **Environnement virtuel automatique** (création et activation)
- **Installation automatique des dépendances** (openpyxl, pandas)
- **Interface utilisateur intuitive** avec menu interactif
- **Validation des chemins** et gestion d'erreurs
- **Support de glisser-déposer** pour les chemins de dossiers

### 🔍 **`amassbeautifier.py`** - Extracteur et Organisateur de Domaines

Un outil puissant pour extraire, analyser et exporter tous les domaines découverts par Amass.

### 2. **`domain_mapper.py`** - Cartographe Visuel de Domaines

Créé des cartographies visuelles interactives des relations entre domaines.

### 3. **`excel_security_dashboard.py`** - Dashboard Excel de Sécurité Email

Génère un dashboard Excel professionnel à partir de tous les fichiers JSON checkdmarc.

### 4. **`generate_excel_dashboard.sh`** - Assistant de Génération

Script d'assistance interactif pour simplifier la génération des dashboards Excel.

### 5. **`checkdmarc_enhanced.py`** - Analyseur Email Ultra-Détaillé

Analyse approfondie des configurations email avec explications détaillées.

#### 🎯 Fonctionnalités Principales

- **Extraction complète** : Récupère TOUS les domaines/sous-domaines du fichier Amass
- **Résolution IP** : Associe les adresses IP aux domaines correspondants
- **Catégorisation intelligente** : Classe automatiquement les domaines par fonction
- **Exports multiples** : Plusieurs formats de sortie disponibles
- **Interface claire** : Affichage organisé avec statistiques détaillées

#### 📊 Modes d'Affichage

1. **Simple** (défaut) : Liste complète avec IPs
2. **Catégorisé** : Domaines organisés par fonction
3. **Détaillé** : Relations complètes entre les éléments

#### 📂 Catégories Automatiques

- 🏠 **Domaine Principal** : Le domaine racine
- 🌐 **Web Services** : Sites web et applications
- 🔧 **API & Applications** : Services et microservices
- 📧 **Mail & Communication** : Serveurs de messagerie
- ⚙️ **Admin & Management** : Panneaux d'administration
- 🔬 **Development & Testing** : Environnements de développement
- 🖥️ **Infrastructure** : DNS, FTP, CDN, etc.
- 🌍 **Externes/Tiers** : Domaines externes
- 📋 **Autres** : Non catégorisés

#### 💾 Formats d'Export

- **Simple** : Liste des domaines seuls
- **Avec IPs** : Domaines + adresses IP associées
- **Catégorisé** : Domaines organisés par fonction
- **Clean** : Noms de domaines uniquement (un par ligne)

---

### 2. **`domain_mapper.py`** - Cartographe Visuel de Domaines

Créé des cartographies visuelles interactives des relations entre domaines.

#### 🎯 Fonctionnalités Principales

- **Cartographie Graphviz** : Diagrammes vectoriels professionnels
- **Interface HTML Interactive** : Carte web moderne et responsive
- **Affichage textuel** : Vue d'ensemble en mode console
- **Relations visuelles** : Liens entre domaines, IPs et services
- **Design moderne** : Interface utilisateur élégante

### 3. **`excel_security_dashboard.py`** - Dashboard Excel de Sécurité Email

Génère un dashboard Excel professionnel à partir de tous les fichiers JSON checkdmarc.

#### 🎯 Fonctionnalités Principales

- **Analyse multi-domaines** : Traite tous les sous-domaines automatiquement
- **Dashboard complet** : 5 feuilles Excel spécialisées
- **Scoring intelligent** : Système de notation 0-100 points
- **Plan d'action priorisé** : Recommendations triées par urgence
- **Export professionnel** : Mise en forme et couleurs optimisées

#### 📊 Contenu du Dashboard

1. **🎯 Vue d'ensemble** - Résumé exécutif avec statistiques globales
2. **📋 Détails par domaine** - Analyse approfondie des problèmes
3. **⚠️ Matrice de risques** - Vue stratégique par catégorie
4. **🎯 Plan d'action** - Roadmap priorisée avec timeline
5. **📊 Données brutes** - Export pour analyses complémentaires

#### 💯 Système de Scoring

- **SPF présent** (10 pts) + **SPF strict** (15 pts)
- **DMARC présent** (20 pts) + **Politique stricte** (25 pts)
- **Rapports DMARC** (10 pts) + **Application 100%** (10 pts)
- **STARTTLS** (10 pts)

#### 🎨 Fonctionnalités Avancées

- **Codes couleurs** automatiques (Rouge/Jaune/Vert)
- **Tableaux Excel** avec filtres intégrés
- **Compatibilité** LibreOffice et Microsoft Excel
- **Format responsive** pour présentation

### 4. **`generate_excel_dashboard.sh`** - Assistant de Génération

Script d'assistance interactif pour simplifier la génération des dashboards Excel.

#### 🗺️ Types de Cartographies

1. **Graphviz** (défaut) : Diagrammes vectoriels (SVG, PNG, PDF)
2. **HTML Interactif** : Interface web avec contrôles dynamiques
3. **Textuel** : Arbre hiérarchique en console

#### 🎨 Interface HTML Interactive

- **Design responsive** : Compatible mobile et desktop
- **Contrôles dynamiques** :
  - Basculer la physique du réseau
  - Afficher/masquer les IPs
  - Centrer la vue
  - Exporter en PNG
  - Mode plein écran
- **Interactions** :
  - Clic sur les nœuds pour les détails
  - Survol pour l'aperçu
  - Zoom et navigation fluides
- **Statistiques en temps réel** : Compteurs animés

#### 🔗 Types de Relations Visualisées

- **Node** : Relations hiérarchiques (bleu)
- **A Record** : Résolution IPv4 (vert)
- **AAAA Record** : Résolution IPv6 (vert clair)
- **CNAME** : Alias de domaine (orange)
- **MX Record** : Serveurs de messagerie (rouge)
- **NS Record** : Serveurs DNS (violet)

---

## 🚀 Installation et Prérequis

### Prérequis Python

```bash
# Python 3.6+ requis
python3 --version
```

### Installation des Dépendances

#### Pour `amassbeautifier.py`

```bash
# Aucune dépendance externe requise
# Utilise uniquement les modules Python standard
```

#### Pour `domain_mapper.py`

```bash
# Installer Graphviz (optionnel)
pip install graphviz

# Sur Ubuntu/Debian
sudo apt-get install graphviz

# Sur macOS
brew install graphviz

# Sur CentOS/RHEL
sudo yum install graphviz
```

---

## 📘 Guide d'Utilisation

### `amassbeautifier.py` - Extracteur de Domaines

#### Syntaxe de Base

```bash
python3 amassbeautifier.py <fichier_amass.txt> [options]
```

#### Options Disponibles

```bash
--simple          # Affichage simple (défaut)
--categorized     # Affichage catégorisé par fonction
--detailed        # Affichage avec détails des relations
--export FILE     # Exporter vers un fichier
--export-ips      # Inclure les IPs dans l'export
--export-clean FILE # Exporter uniquement les noms de domaines
```

#### Exemples d'Utilisation

**Affichage simple avec statistiques :**

```bash
python3 amassbeautifier.py scan_results.txt
```

**Affichage catégorisé par fonction :**

```bash
python3 amassbeautifier.py scan_results.txt --categorized
```

**Affichage détaillé avec relations :**

```bash
python3 amassbeautifier.py scan_results.txt --detailed
```

**Export simple des domaines :**

```bash
python3 amassbeautifier.py scan_results.txt --export all_domains.txt
```

**Export avec adresses IP :**

```bash
python3 amassbeautifier.py scan_results.txt --export domains_with_ips.txt --export-ips
```

**Export format clean (pour d'autres outils) :**

```bash
python3 amassbeautifier.py scan_results.txt --export-clean clean_domains.txt
```

### `excel_security_dashboard.py` - Dashboard Excel

#### Syntaxe de Base

```bash
python3 excel_security_dashboard.py <dossier_checkdmarc> [output.xlsx]
```

#### Options Disponibles

```bash
<dossier_checkdmarc>    # Dossier contenant les fichiers JSON checkdmarc
[output.xlsx]           # Nom du fichier Excel de sortie (optionnel)
```

#### Exemples d'Utilisation

**Génération basique :**

```bash
python3 excel_security_dashboard.py output/example.com/checkdmarc/
```

**Génération avec nom personnalisé :**

```bash
python3 excel_security_dashboard.py output/example.com/checkdmarc/ security_audit_2025.xlsx
```

**Utilisation de l'assistant interactif :**

```bash
./generate_excel_dashboard.sh
```

### `generate_excel_dashboard.sh` - Assistant Interactif

#### Utilisation Simple

```bash
./generate_excel_dashboard.sh
```

#### Fonctionnalités de l'Assistant

- **Détection automatique** des domaines analysés
- **Sélection interactive** du domaine à traiter
- **Gestion automatique** de l'environnement Python
- **Installation automatique** des dépendances
- **Ouverture automatique** du fichier généré

#### Syntaxe de Base

```bash
python3 domain_mapper.py <fichier_amass.txt> [options]
```

#### Options Disponibles

```bash
--graphviz         # Générer avec Graphviz (défaut)
--html             # Générer une carte interactive HTML
--text             # Affichage textuel simple
--no-ips           # Masquer les adresses IP
--show-orgs        # Afficher les organisations
--format FORMAT    # Format de sortie (svg, png, pdf)
```

#### Exemples d'Utilisation

**Cartographie Graphviz (défaut) :**

```bash
python3 domain_mapper.py scan_results.txt
```

**Cartographie interactive HTML :**

```bash
python3 domain_mapper.py scan_results.txt --html
```

**Cartographie textuelle :**

```bash
python3 domain_mapper.py scan_results.txt --text
```

**Export PNG sans IPs :**

```bash
python3 domain_mapper.py scan_results.txt --format png --no-ips
```

**Cartographie complète avec organisations :**

```bash
python3 domain_mapper.py scan_results.txt --html --show-orgs
```

---

## 📈 Exemples de Sorties

### `amassbeautifier.py` - Mode Catégorisé

```
🎯 Analyse complète des domaines (scan de example.com)
================================================================================

📂 Domaine Principal (1)
----------------------------------------
  ├── example.com → 93.184.216.34

📂 Web Services (3)
----------------------------------------
  ├── www.example.com → 93.184.216.34
  ├── app.example.com → 192.168.1.10
  ├── portal.example.com → 10.0.0.5

📂 API & Applications (2)
----------------------------------------
  ├── api.example.com → 192.168.1.20
  ├── rest.example.com → 10.0.0.15

📂 Mail & Communication (2)
----------------------------------------
  ├── mail.example.com → 192.168.1.30
  ├── webmail.example.com → 10.0.0.25

📊 Résumé: 8 domaines au total
```

### `domain_mapper.py` - Mode Textuel

```
🗺️  CARTOGRAPHIE DE EXAMPLE.COM
============================================================

🏠 DOMAINE PRINCIPAL
├── example.com
│   └── 📍 93.184.216.34

🌿 SOUS-DOMAINES (6)
├── www.example.com
│   └── 📍 93.184.216.34
├── api.example.com
│   └── 📍 192.168.1.20
├── mail.example.com
│   └── 📍 192.168.1.30

📊 RÉSUMÉ
├── Sous-domaines: 6
├── Domaines externes: 2
├── Adresses IP uniques: 8
└── Relations totales: 24
```

---

## 📁 Fichiers Générés

### `amassbeautifier.py`

- **Exports texte** : Fichiers `.txt` avec listes de domaines
- **Formats disponibles** : Simple, avec IPs, catégorisé, clean

### `domain_mapper.py`

- **Graphviz** :
  - `domain_map_example_com.svg` (défaut)
  - `domain_map_example_com.png`
  - `domain_map_example_com.pdf`
- **HTML Interactif** :
  - `domain_map_example_com.html`

---

## 🔧 Conseils d'Utilisation

### Workflow Recommandé

1. **Scan Amass** : Effectuer la reconnaissance

```bash
amass enum -d example.com -o amass_results.txt
```

2. **Analyse avec amassbeautifier** : Extraire et analyser

```bash
python3 amassbeautifier.py amass_results.txt --categorized
```

3. **Cartographie visuelle** : Créer la cartographie

```bash
python3 domain_mapper.py amass_results.txt --html
```

4. **Exports pour autres outils** : Préparer les données

```bash
python3 amassbeautifier.py amass_results.txt --export-clean domains_list.txt
```

### Optimisation des Performances

- **Gros fichiers** : Utilisez `--no-ips` pour réduire la complexité visuelle
- **Exports multiples** : Combinez les options pour générer plusieurs formats
- **HTML interactif** : Idéal pour les présentations et l'analyse collaborative

### Compatibilité

- **Systèmes** : Linux, macOS, Windows
- **Python** : 3.6+ (testé sur 3.8+)
- **Navigateurs** : Chrome, Firefox, Safari, Edge (pour HTML)

---

## 🐛 Résolution de Problèmes

### Erreurs Communes

**"Aucun domaine trouvé" :**

- Vérifiez le format du fichier Amass
- Assurez-vous que le fichier contient des données FQDN

**"Graphviz non installé" :**

```bash
pip install graphviz
sudo apt-get install graphviz  # Linux
brew install graphviz          # macOS
```

**Problèmes d'encodage :**

- Les scripts utilisent UTF-8 par défaut
- Vérifiez l'encodage de votre fichier source

### Support et Contribution

Pour signaler des bugs ou proposer des améliorations, n'hésitez pas à documenter vos retours avec :

- Version de Python utilisée
- Système d'exploitation
- Exemple de fichier d'entrée (anonymisé)
- Message d'erreur complet

---

## 📄 Licence et Crédits

Scripts développés pour l'analyse de reconnaissance de domaines dans le cadre de tests de sécurité autorisés.

**⚠️ Utilisation Responsable** : Ces outils sont destinés uniquement à des fins de sécurité légitimes et autorisées. L'utilisateur est responsable de respecter les lois et réglementations applicables.

---

## 🆕 Dernières Améliorations (Version Finale)

### ✅ Fonctionnalités Récemment Ajoutées

#### 🔄 **Logique de Continuation dans automation.py**

- **Skip individuel** : Chaque étape (1-5) peut être ignorée sans interrompre le workflow
- **Messages clairs** : Indicateurs visuels pour chaque transition d'étape
- **Robustesse** : Le script continue même en cas d'erreur sur une étape
- **Flexibilité** : Permet d'exécuter seulement les outils nécessaires

#### 🌍 **Interface Internationalisée**

- **Messages en anglais** : Tous les prints et messages utilisateur
- **Compatibilité étendue** : Meilleure intégration dans des environnements internationaux
- **Consistance** : Interface uniforme sur tous les scripts

#### 📊 **Dashboard Excel Avancé**

- **5 feuilles spécialisées** avec analyses distinctes
- **Scoring intelligent** : Système de points sur 100 pour évaluer la sécurité
- **Code couleur** : Rouge/Jaune/Vert pour identification rapide
- **Données actionables** : Plan d'action avec priorités claires

### 🎯 **Workflow Testé et Validé**

Le workflow complet a été testé avec succès sur **hydrogeotechnique.com** :

- **19 domaines analysés** automatiquement
- **Score moyen : 47.6/100** calculé par l'algorithme
- **40 problèmes critiques** identifiés
- **54 avertissements** documentés
- **Dashboard Excel** généré en 30 secondes

### 📈 **Métriques de Performance**

| Métrique                      | Valeur   | Description                              |
| ----------------------------- | -------- | ---------------------------------------- |
| **Domaines traités**          | 19       | Analyse complète en une exécution        |
| **Temps de génération Excel** | ~30s     | Incluant analyse et formatage            |
| **Taux de réussite**          | 100%     | Aucune interruption du workflow          |
| **Score de sécurité moyen**   | 47.6/100 | Basé sur les critères SPF/DMARC/STARTTLS |

### 🛡️ **Sécurité et Fiabilité**

- **Gestion d'erreurs** robuste sur toutes les étapes
- **Validation des données** avant traitement
- **Environnement isolé** avec venv pour les dépendances Python
- **Logs détaillés** pour debugging et traçabilité

---

## 🎉 Conclusion

Ce suite d'outils offre maintenant un **workflow complet et robuste** pour l'analyse de sécurité des domaines. Avec la logique de continuation, l'interface internationalisée et les dashboards Excel avancés, vous disposez d'une solution professionnelle pour vos audits de sécurité email et infrastructure.

**Commencez votre analyse dès maintenant :**

```bash
python3 automation.py
```

**Puis générez votre dashboard :**

```bash
./generate_excel_dashboard.sh
```

---

> 💡 **Astuce** : Pour des analyses à grande échelle, vous pouvez maintenant ignorer les étapes longues (comme nmap ou testssl) et vous concentrer sur checkdmarc pour générer rapidement des dashboards email.
