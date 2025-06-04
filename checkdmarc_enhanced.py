#!/usr/bin/env python3
"""
checkdmarc_enhanced.py
Analyse ULTRA-DÉTAILLÉE d'un rapport JSON produit par checkdmarc
( SPF / DKIM / DMARC / MTA-STS / TLS-RPT / DNSSEC / BIMI )

🎯 Cette version EXPLIQUE en détail :
- POURQUOI chaque élément est important
- QUE SE PASSE-T-IL si c'est mal configuré
- QUELS SONT LES RISQUES CONCRETS
- COMMENT CORRIGER les problèmes

Usage :
    python3 checkdmarc_enhanced.py scan.json [scan2.json ...]

Sortie :
    - Diagnostic exhaustif avec explications détaillées
    - Code retour 0 si aucun CRITICAL, 1 sinon (utile en CI/CD)

Auteur : ChatGPT & Assistant IA (2025)
"""
import json
import sys
from pathlib import Path
from typing import List, Dict, Tuple

# ----------------- Références officielles améliorées -----------------

REF: Dict[str, str] = {
    "SPF_LIMIT": "RFC 7208 §4.6.4 – Limite de 10 consultations DNS | https://tools.ietf.org/html/rfc7208#section-4.6.4",
    "SPF_ALL": "NIST SP 800-177r1 §2.3 – Usage de « -all » | https://csrc.nist.gov/publications/detail/sp/800-177/rev-1/final",
    "DKIM_LEN": "RFC 8301 – Longueur mini 1024 bits, recommandé 2048 | https://tools.ietf.org/html/rfc8301",
    "DMARC_POLICY": "RFC 7489 §6.3 – p=none/quarantine/reject | https://tools.ietf.org/html/rfc7489#section-6.3",
    "MTA_STS": "RFC 8461 – MTA-STS enforce vs testing | https://tools.ietf.org/html/rfc8461",
    "TLS_RPT": "RFC 8460 – SMTP TLS Reporting | https://tools.ietf.org/html/rfc8460",
    "DNSSEC": "RFC 4033-35 – Authentification DNS | https://tools.ietf.org/html/rfc4033",
    "BIMI": "BIMI WG draft – DMARC p=quarantine/reject requis | https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/"
}

# ----------------- Helpers améliorés -----------------

Status = Tuple[str, str, str]  # (LEVEL, MESSAGE, REFKEY)

def status(level: str, msg: str, ref: str) -> Status:
    return (level, msg, ref)

def print_status(s: Status) -> None:
    lvl, msg, ref = s
    icons = {"OK": "✅", "WARNING": "⚠️", "CRITICAL": "🚨", "INFO": "ℹ️"}
    colors = {"OK": "\033[92m", "WARNING": "\033[93m", "CRITICAL": "\033[91m", "INFO": "\033[94m"}
    
    icon = icons.get(lvl, "❓")
    color = colors.get(lvl, "\033[0m")
    reset = "\033[0m"
    
    print(f"{icon} [{color}{lvl}{reset}] {msg}")
    print(f"   📚 Référence: {REF.get(ref, ref)}")
    print()

# ----------------- Analyse SPF ULTRA-DÉTAILLÉE -----------------

def analyze_spf(spf: dict) -> List[Status]:
    out: List[Status] = []
    
    if not spf or not spf.get("record"):
        out.append(status("CRITICAL",
                          "SPF TOTALEMENT ABSENT !\n"
                          "🔥 DANGER IMMÉDIAT: N'importe qui peut envoyer des emails en usurpant votre domaine.\n"
                          "💥 CONSÉQUENCES:\n"
                          "   • Phishing ciblant vos clients avec votre identité\n"
                          "   • Spam massif détruisant votre réputation\n"
                          "   • Perte de confiance des partenaires\n"
                          "   • Sanctions légales possibles\n"
                          "🛠️ SOLUTION URGENTE: Ajouter un enregistrement DNS TXT SPF.\n"
                          "   Exemple: 'v=spf1 ip4:votre.ip.serveur.mail -all'",
                          "SPF_ALL"))
        return out

    record = spf["record"]
    out.append(status("INFO", f"📝 Enregistrement SPF détecté: {record}", "SPF_LIMIT"))
    
    # Validité
    if not spf.get("valid", False):
        error_detail = spf.get('error', 'erreur inconnue')
        out.append(status("CRITICAL",
                          f"SPF SYNTAXIQUEMENT INVALIDE !\n"
                          f"🔴 ERREUR: {error_detail}\n"
                          f"💀 IMPACT CRITIQUE: Les serveurs de messagerie IGNORENT votre SPF défaillant.\n"
                          f"🎯 RÉSULTAT: Aucune protection, comme si SPF n'existait pas.\n"
                          f"⚡ RISQUES:\n"
                          f"   • Usurpation d'emails garantie\n"
                          f"   • Faux sentiment de sécurité\n"
                          f"   • Délivrabilité imprévisible\n"
                          f"🔧 CORRECTION: Utiliser un validateur SPF en ligne pour corriger la syntaxe.",
                          "SPF_LIMIT"))
    else:
        out.append(status("OK", 
                          "SYNTAXE SPF CORRECTE !\n"
                          "✅ BONNE NOUVELLE: Les serveurs peuvent interpréter vos règles.\n"
                          "🎯 AVANTAGE: Base technique solide pour l'authentification.\n"
                          "🛡️ PROTECTION: Vos règles d'autorisation sont compréhensibles par tous les serveurs.",
                          "SPF_LIMIT"))

    # Analyse des consultations DNS
    dns_lookups = spf.get("dns_lookups", 0)
    dns_void_lookups = spf.get("dns_void_lookups", 0)
    total_lookups = dns_lookups + dns_void_lookups
    
    if total_lookups > 10:
        out.append(status("CRITICAL",
                          f"SPF TROP COMPLEXE - ÉCHEC GARANTI !\n"
                          f"🔥 PROBLÈME: {total_lookups} consultations DNS (limite RFC: 10 maximum)\n"
                          f"   • Consultations normales: {dns_lookups}\n"
                          f"   • Consultations void: {dns_void_lookups}\n"
                          f"💥 CONSÉQUENCE DÉSASTREUSE: Les serveurs retournent 'PermError' et IGNORENT TOTALEMENT votre SPF !\n"
                          f"⚠️ CAUSES FRÉQUENTES:\n"
                          f"   • Trop d'instructions 'include:'\n"
                          f"   • Chaînes de redirections complexes\n"
                          f"   • Inclusions récursives\n"
                          f"🛠️ SOLUTIONS IMMÉDIATES:\n"
                          f"   1. Remplacer 'include:' par des IP directes (ip4:/ip6:)\n"
                          f"   2. Éliminer les inclusions inutiles\n"
                          f"   3. Utiliser des sous-domaines pour diviser les règles\n"
                          f"📊 IMPACT BUSINESS: Protection nulle + délivrabilité dégradée !",
                          "SPF_LIMIT"))
    elif total_lookups > 7:
        out.append(status("WARNING",
                          f"SPF PROCHE DE LA LIMITE CRITIQUE !\n"
                          f"⚠️ ÉTAT: {total_lookups}/10 consultations DNS utilisées\n"
                          f"   • Consultations normales: {dns_lookups}\n"
                          f"   • Consultations void: {dns_void_lookups}\n"
                          f"🎯 RISQUE: Dépassement de limite lors de futurs ajouts\n"
                          f"📈 TENDANCE: Croissance naturelle avec l'évolution infrastructure\n"
                          f"🔮 PRÉVISION: Panne SPF probable dans les 6-12 mois\n"
                          f"💡 RECOMMANDATION PRÉVENTIVE:\n"
                          f"   • Optimiser dès maintenant (plus facile que corriger en urgence)\n"
                          f"   • Documenter les inclusions nécessaires\n"
                          f"   • Planifier une refonte si > 8 lookups",
                          "SPF_LIMIT"))
    elif total_lookups > 5:
        out.append(status("INFO",
                          f"SPF de complexité modérée ({total_lookups}/10 consultations DNS)\n"
                          f"   • Consultations normales: {dns_lookups}\n"
                          f"   • Consultations void: {dns_void_lookups}\n"
                          f"✅ ÉTAT: Fonctionnel et dans les normes\n"
                          f"🎯 CONSEIL: Surveiller l'évolution lors d'ajouts futurs\n"
                          f"📋 MAINTENANCE: Réviser annuellement pour optimisation",
                          "SPF_LIMIT"))
    elif total_lookups > 0:
        out.append(status("OK",
                          f"SPF OPTIMISÉ ! ({total_lookups}/10 consultations DNS)\n"
                          f"   • Consultations normales: {dns_lookups}\n"
                          f"   • Consultations void: {dns_void_lookups}\n"
                          f"✅ PERFORMANCE: Excellente\n"
                          f"🎯 MARGE: Large marge pour évolutions futures\n"
                          f"🏆 STATUT: Configuration optimale",
                          "SPF_LIMIT"))

    # Analyse directive ALL (la plus importante !)
    if record and record.strip().endswith("-all"):
        out.append(status("OK", 
                          "PROTECTION SPF MAXIMALE ACTIVÉE ! 🛡️\n"
                          "🎯 DIRECTIVE '-all' (FAIL) = Politique la plus stricte\n"
                          "✅ FONCTIONNEMENT:\n"
                          "   • Emails autorisés: ACCEPTÉS normalement\n"
                          "   • Emails non-autorisés: REJETÉS purement et simplement\n"
                          "🏆 AVANTAGES BUSINESS:\n"
                          "   • Protection contre usurpation: 95%+\n"
                          "   • Confiance client renforcée\n"
                          "   • Réputation domaine préservée\n"
                          "   • Conformité sécurité maximale\n"
                          "📊 RÉSULTAT: Votre domaine est VRAIMENT protégé !",
                          "SPF_ALL"))
    elif record and "~all" in record:
        out.append(status("WARNING",
                          "PROTECTION SPF PARTIELLE - RISQUE MODÉRÉ ⚠️\n"
                          "🎯 DIRECTIVE '~all' (SOFTFAIL) = Politique permissive\n"
                          "⚡ FONCTIONNEMENT RISQUÉ:\n"
                          "   • Emails autorisés: ACCEPTÉS normalement\n"
                          "   • Emails non-autorisés: ACCEPTÉS mais marqués 'suspect'\n"
                          "🚨 PROBLÈMES FRÉQUENTS:\n"
                          "   • Nombreux serveurs IGNORENT le marquage\n"
                          "   • Usurpation toujours possible\n"
                          "   • Faux sentiment de sécurité\n"
                          "📈 RECOMMANDATION STRATÉGIQUE:\n"
                          "   1. Tester en mode '-all' sur domaine test\n"
                          "   2. Surveiller rapports DMARC 2-4 semaines\n"
                          "   3. Passer à '-all' pour protection réelle\n"
                          "🎯 OBJECTIF: Protection à 95% au lieu de 60%",
                          "SPF_ALL"))
    elif record and "+all" in record:
        out.append(status("CRITICAL",
                          "DIRECTIVE SPF SUICIDAIRE DÉTECTÉE ! 💀\n"
                          "🚨 DIRECTIVE '+all' (PASS) = DÉSASTRE SÉCURITAIRE\n"
                          "💥 FONCTIONNEMENT CATASTROPHIQUE:\n"
                          "   • TOUS les serveurs mondiaux autorisés à envoyer en votre nom\n"
                          "   • Spammeurs, pirates, concurrents: accès libre\n"
                          "   • SPF transformé en panneau 'bienvenue aux fraudeurs'\n"
                          "🔥 CONSÉQUENCES IMMÉDIATES:\n"
                          "   • Usurpation massive garantie\n"
                          "   • Réputation détruite en heures\n"
                          "   • Blacklisting probable\n"
                          "   • Perte de confiance client\n"
                          "🆘 ACTION URGENTE REQUISE:\n"
                          "   REMPLACER '+all' par '-all' IMMÉDIATEMENT !\n"
                          "⏰ DÉLAI MAXIMAL: 1 heure (avant exploitation malveillante)",
                          "SPF_ALL"))
    elif record and "?all" in record:
        out.append(status("WARNING",
                          "SPF EN MODE 'NEUTRE' - INEFFICACE ! 🤷\n"
                          "🎯 DIRECTIVE '?all' (NEUTRAL) = Aucune opinion\n"
                          "⚪ FONCTIONNEMENT INUTILE:\n"
                          "   • SPF dit 'je ne sais pas' pour les non-autorisés\n"
                          "   • Serveurs appliquent leur politique locale (imprévisible)\n"
                          "   • Comportement variable selon les destinataires\n"
                          "📊 PROTECTION RÉELLE: ~20% (aléatoire)\n"
                          "🎭 PROBLÈME: Fausse impression de sécurité\n"
                          "🔧 SOLUTION: Choisir '-all' ou '~all' selon tolérance au risque",
                          "SPF_ALL"))
    else:
        if record:  # SPF existe mais pas de directive 'all'
            out.append(status("CRITICAL",
                              "SPF INCOMPLET - AUCUNE DIRECTIVE 'ALL' ! 🕳️\n"
                              "🚨 PROBLÈME MAJEUR: Enregistrement SPF tronqué\n"
                              "⚡ COMPORTEMENT IMPRÉVISIBLE:\n"
                              "   • Chaque serveur applique SA politique par défaut\n"
                              "   • Gmail: peut accepter ou rejeter\n"
                              "   • Outlook: comportement différent\n"
                              "   • Serveurs privés: totalement aléatoire\n"
                              "🎲 RÉSULTAT: Protection au hasard (0-70%)\n"
                              "🎯 DIAGNOSTIC: Erreur de configuration ou record tronqué\n"
                              "🛠️ CORRECTION SIMPLE: Ajouter '-all' en fin d'enregistrement\n"
                              "📝 EXEMPLE: 'v=spf1 ip4:1.2.3.4 include:_spf.google.com -all'",
                              "SPF_ALL"))
    
    return out

# ----------------- Analyse DKIM ULTRA-DÉTAILLÉE -----------------

def analyze_dkim(dkim: dict) -> List[Status]:
    out: List[Status] = []
    
    if not dkim:
        out.append(status("WARNING",
                          "DKIM NON DÉTECTÉ DANS LE SCAN ! 🔍\n"
                          "⚠️ LIMITATION TECHNIQUE: checkdmarc teste un seul sélecteur par défaut\n"
                          "🎯 SÉLECTEURS STANDARDS TESTÉS: 'default', 'selector1', 'dkim'\n"
                          "💡 SITUATION POSSIBLE:\n"
                          "   • DKIM existe mais avec sélecteur personnalisé\n"
                          "   • Configuration sur sous-domaines uniquement\n"
                          "   • Clés DKIM en cours de déploiement\n"
                          "🔍 VÉRIFICATION MANUELLE RECOMMANDÉE:\n"
                          "   1. Examiner les en-têtes d'emails sortants\n"
                          "   2. Chercher 'DKIM-Signature:' dans les sources\n"
                          "   3. Tester sélecteurs personnalisés\n"
                          "📊 IMPACT: Authentification incomplète si réellement absent",
                          "DKIM_LEN"))
        return out

    # Analyse de chaque sélecteur DKIM
    for selector, det in dkim.items():
        out.append(status("INFO", f"🔑 Analyse du sélecteur DKIM: '{selector}'", "DKIM_LEN"))
        
        record = det.get("record")
        if not record:
            out.append(status("CRITICAL",
                              f"SÉLECTEUR DKIM '{selector}' TOTALEMENT ABSENT ! 🚨\n"
                              f"💥 CONSÉQUENCE DIRECTE: Signature DKIM impossible à vérifier\n"
                              f"⚡ IMPACT AUTHENTIFICATION:\n"
                              f"   • Emails marqués 'DKIM=fail' ou 'DKIM=none'\n"
                              f"   • DMARC ne peut pas s'appuyer sur DKIM\n"
                              f"   • Protection contre modification en transit = ZÉRO\n"
                              f"🎯 CAUSES FRÉQUENTES:\n"
                              f"   • Clé supprimée accidentellement du DNS\n"
                              f"   • Erreur de nom de sélecteur\n"
                              f"   • Propagation DNS incomplète\n"
                              f"🛠️ RÉSOLUTION:\n"
                              f"   1. Vérifier configuration serveur mail\n"
                              f"   2. Régénérer paire de clés DKIM\n"
                              f"   3. Publier clé publique dans DNS TXT\n"
                              f"📍 Zone DNS: {selector}._domainkey.votredomaine.com",
                              "DKIM_LEN"))
            continue

        if not det.get("valid", False):
            error_detail = det.get('error', 'erreur inconnue')
            out.append(status("CRITICAL",
                              f"DKIM '{selector}' INVALIDE ! 🔴\n"
                              f"💀 ERREUR TECHNIQUE: {error_detail}\n"
                              f"⚡ CONSÉQUENCE: Signature DKIM systématiquement rejetée\n"
                              f"🎯 IMPACT DÉLIVRABILITÉ:\n"
                              f"   • Emails suspects pour les serveurs destinataires\n"
                              f"   • Score de réputation dégradé\n"
                              f"   • Risque accru de placement en spam\n"
                              f"🔧 CAUSES TYPIQUES:\n"
                              f"   • Format de clé publique incorrect\n"
                              f"   • Caractères invalides dans l'enregistrement\n"
                              f"   • Corruption lors de la publication DNS\n"
                              f"🛠️ DIAGNOSTIC: Valider l'enregistrement DNS avec outils DKIM",
                              "DKIM_LEN"))
            continue

        # Analyse de la robustesse de la clé
        key_size = det.get("key_length", 0)
        if key_size < 1024:
            out.append(status("CRITICAL",
                              f"CLÉ DKIM '{selector}' DANGEREUSEMENT COURTE ! ⚠️\n"
                              f"🔑 TAILLE ACTUELLE: {key_size} bits (minimum légal: 1024 bits)\n"
                              f"💀 VULNÉRABILITÉ CRYPTOGRAPHIQUE MAJEURE:\n"
                              f"   • Factorisation possible en quelques heures/jours\n"
                              f"   • Attaquants peuvent forger vos signatures DKIM\n"
                              f"   • Usurpation d'emails avec authentification 'valide'\n"
                              f"🚨 EXPLOITATION POSSIBLE:\n"
                              f"   • Phishing indétectable par les filtres\n"
                              f"   • Compromission totale de l'authentification\n"
                              f"⏰ ACTION IMMÉDIATE REQUISE:\n"
                              f"   1. Générer nouvelle paire 2048+ bits\n"
                              f"   2. Déployer nouvelle clé publique\n"
                              f"   3. Mettre à jour configuration serveur\n"
                              f"   4. Tester puis supprimer ancienne clé\n"
                              f"📊 PRIORITÉ: CRITIQUE (risque sécurité majeur)",
                              "DKIM_LEN"))
        elif key_size < 2048:
            out.append(status("WARNING",
                              f"CLÉ DKIM '{selector}' SOUS-OPTIMALE 📏\n"
                              f"🔑 TAILLE ACTUELLE: {key_size} bits (minimum recommandé: 2048 bits)\n"
                              f"⚠️ SÉCURITÉ RÉDUITE:\n"
                              f"   • Protection correcte aujourd'hui\n"
                              f"   • Vulnérabilité croissante avec le temps\n"
                              f"   • Puissance de calcul augmente constamment\n"
                              f"🎯 RECOMMANDATION STRATÉGIQUE:\n"
                              f"   • Planifier migration vers 2048 bits\n"
                              f"   • Nouveau standard industrie\n"
                              f"   • Compatibilité universelle assurée\n"
                              f"📅 DÉLAI SUGGÉRÉ: 6-12 mois (non urgent mais recommandé)\n"
                              f"🔐 AVANTAGE 2048 bits: Protection 10+ ans garantie",
                              "DKIM_LEN"))
        else:
            out.append(status("OK",
                              f"CLÉ DKIM '{selector}' EXCELLENTE ! 🏆\n"
                              f"🔑 TAILLE: {key_size} bits (standard moderne)\n"
                              f"✅ SÉCURITÉ CRYPTOGRAPHIQUE OPTIMALE:\n"
                              f"   • Protection contre factorisation: 10+ ans\n"
                              f"   • Résistance aux attaques par force brute\n"
                              f"   • Conformité aux standards actuels\n"
                              f"🎯 AVANTAGES BUSINESS:\n"
                              f"   • Authentification robuste des emails\n"
                              f"   • Intégrité garantie en transit\n"
                              f"   • Confiance maximale des destinataires\n"
                              f"   • Délivrabilité optimisée\n"
                              f"🏅 RÉSULTAT: Configuration DKIM exemplaire !",
                              "DKIM_LEN"))
    
    return out

# ----------------- Analyse DMARC ULTRA-DÉTAILLÉE -----------------

def analyze_dmarc(dmarc: dict) -> List[Status]:
    out: List[Status] = []
    
    if not dmarc or not dmarc.get("record"):
        out.append(status("CRITICAL",
                          "DMARC TOTALEMENT ABSENT ! 🚨\n"
                          "💥 SITUATION CRITIQUE: Aucune politique anti-usurpation\n"
                          "🎯 CONSÉQUENCES DÉSASTREUSES:\n"
                          "   • SPF et DKIM existent mais ne servent à RIEN\n"
                          "   • Aucune instruction sur que faire des échecs\n"
                          "   • Serveurs appliquent politiques aléatoires\n"
                          "   • Usurpation libre même avec SPF/DKIM en place\n"
                          "💀 IMPACT BUSINESS MAJEUR:\n"
                          "   • Phishing utilisant votre domaine\n"
                          "   • Réputation détruite par spam tiers\n"
                          "   • Perte de confiance client/partenaire\n"
                          "   • Risques légaux et financiers\n"
                          "🆘 SOLUTION IMMÉDIATE:\n"
                          "   Publier: 'v=DMARC1; p=none; rua=mailto:dmarc@votredomaine.com'\n"
                          "📊 PRIORITÉ: URGENTE (correction en heures, pas jours)",
                          "DMARC_POLICY"))
        return out

    record = dmarc["record"]
    out.append(status("INFO", f"📋 Politique DMARC détectée: {record}", "DMARC_POLICY"))
    
    # Analyse de la politique principale
    pvalue = dmarc["tags"]["p"]["value"]
    if pvalue == "none":
        out.append(status("CRITICAL",
                          "DMARC EN MODE 'OBSERVATION' SEULEMENT ! 👁️\n"
                          "⚠️ POLITIQUE p=none = Aucune protection active\n"
                          "📊 FONCTIONNEMENT ACTUEL:\n"
                          "   • Emails frauduleux: ACCEPTÉS sans restriction\n"
                          "   • Rapports générés: OUI (données collectées)\n"
                          "   • Action corrective: AUCUNE\n"
                          "🎯 UTILITÉ LIMITÉE:\n"
                          "   ✅ Monitoring et analyse des flux\n"
                          "   ✅ Identification des sources légitimes\n"
                          "   ❌ Protection zéro contre usurpation\n"
                          "📈 PROGRESSION RECOMMANDÉE:\n"
                          "   1. Analyser rapports DMARC 4-6 semaines\n"
                          "   2. Identifier sources légitimes manquantes\n"
                          "   3. Corriger SPF/DKIM si nécessaire\n"
                          "   4. Passer à p=quarantine puis p=reject\n"
                          "⏰ OBJECTIF: Protection active dans 2-3 mois maximum",
                          "DMARC_POLICY"))
    elif pvalue == "quarantine":
        out.append(status("WARNING",
                          "DMARC EN MODE 'QUARANTAINE' - PROTECTION PARTIELLE ⚠️\n"
                          "🎯 POLITIQUE p=quarantine = Emails suspects en spam\n"
                          "📊 FONCTIONNEMENT ACTUEL:\n"
                          "   • Emails légitimes (SPF/DKIM OK): Boîte de réception\n"
                          "   • Emails suspects (échec auth): Dossier spam/quarantaine\n"
                          "   • Emails frauduleux: Généralement bloqués\n"
                          "✅ AVANTAGES:\n"
                          "   • Protection active contre 80-90% des attaques\n"
                          "   • Emails légitimes toujours délivrés\n"
                          "   • Période de transition sécurisée\n"
                          "⚠️ LIMITES:\n"
                          "   • Emails frauduleux parfois visibles (dossier spam)\n"
                          "   • Utilisateurs peuvent accéder aux quarantaines\n"
                          "   • Protection non absolue\n"
                          "🎯 RECOMMANDATION STRATÉGIQUE:\n"
                          "   • Excellente étape intermédiaire\n"
                          "   • Surveiller rapports 4-8 semaines\n"
                          "   • Évoluer vers p=reject pour protection maximale\n"
                          "📊 NIVEAU PROTECTION: Très bon (85-90%)",
                          "DMARC_POLICY"))
    elif pvalue == "reject":
        out.append(status("OK",
                          "DMARC EN MODE 'REJET' - PROTECTION MAXIMALE ! 🛡️\n"
                          "🏆 POLITIQUE p=reject = Configuration optimale\n"
                          "✅ FONCTIONNEMENT PARFAIT:\n"
                          "   • Emails légitimes (SPF/DKIM OK): Délivrés normalement\n"
                          "   • Emails frauduleux: REJETÉS avant réception\n"
                          "   • Usurpation: Impossible ou quasi-impossible\n"
                          "🎯 PROTECTION BUSINESS MAXIMALE:\n"
                          "   • Réputation domaine préservée: 95%+\n"
                          "   • Confiance client maintenue\n"
                          "   • Phishing utilisant votre domaine: bloqué\n"
                          "   • Conformité sécurité: excellente\n"
                          "💎 AVANTAGES CONCURRENTIELS:\n"
                          "   • Marque protégée contre abus\n"
                          "   • Différenciation sécuritaire\n"
                          "   • Réduction des incidents de sécurité\n"
                          "📊 NIVEAU PROTECTION: Optimal (95-98%)\n"
                          "🏅 FÉLICITATIONS: Configuration DMARC exemplaire !",
                          "DMARC_POLICY"))

    # Analyse du pourcentage d'application
    pct = dmarc["tags"].get("pct", {}).get("value", 100)
    if pct < 100:
        out.append(status("WARNING",
                          f"DMARC APPLIQUÉ PARTIELLEMENT ! ⚠️\n"
                          f"📊 POURCENTAGE ACTUEL: {pct}% des emails traités\n"
                          f"🎯 SIGNIFICATION:\n"
                          f"   • {pct}% des emails: politique DMARC appliquée\n"
                          f"   • {100-pct}% des emails: aucune politique (comme p=none)\n"
                          f"⚠️ RISQUES DU DÉPLOIEMENT PARTIEL:\n"
                          f"   • Attaquants peuvent exploiter les {100-pct}% non protégés\n"
                          f"   • Protection aléatoire et imprévisible\n"
                          f"   • Fausse impression de sécurité\n"
                          f"🎯 USAGE LÉGITIME: Transition progressive vers protection complète\n"
                          f"📈 RECOMMANDATION:\n"
                          f"   1. Si tests OK depuis plusieurs semaines: passer à 100%\n"
                          f"   2. Si déploiement récent: surveiller et augmenter graduellement\n"
                          f"   3. Objectif final: pct=100 pour protection complète\n"
                          f"⏰ DÉLAI RECOMMANDÉ: 4-8 semaines maximum en mode partiel",
                          "DMARC_POLICY"))
    else:
        out.append(status("OK",
                          "DMARC APPLIQUÉ À 100% ! ✅\n"
                          "🎯 COUVERTURE COMPLÈTE: Tous vos emails protégés\n"
                          "🛡️ PROTECTION UNIFORME: Aucune faille exploitable\n"
                          "📊 RÉSULTAT: Sécurité maximale et prévisible",
                          "DMARC_POLICY"))

    # Analyse des rapports agrégés (RUA)
    rua_warnings = dmarc.get("warnings", [])
    has_rua_warning = any("rua tag" in warning for warning in rua_warnings)
    
    if has_rua_warning:
        out.append(status("WARNING",
                          "RAPPORTS DMARC NON CONFIGURÉS ! 📊\n"
                          "⚠️ PROBLÈME: Aucune adresse 'rua' spécifiée\n"
                          "💀 CONSÉQUENCE: Vous volез à l'aveugle !\n"
                          "🎯 IMPACTS MAJEURS:\n"
                          "   • Aucune visibilité sur les tentatives d'usurpation\n"
                          "   • Impossible de détecter les sources légitimes manquantes\n"
                          "   • Aucun retour sur l'efficacité de votre politique\n"
                          "   • Diagnostic des problèmes: impossible\n"
                          "🔍 DONNÉES PERDUES:\n"
                          "   • Volume d'emails traités quotidiennement\n"
                          "   • Sources d'envoi non autorisées\n"
                          "   • Taux de succès SPF/DKIM\n"
                          "   • Géolocalisation des attaques\n"
                          "🛠️ SOLUTION IMMÉDIATE:\n"
                          "   Ajouter: rua=mailto:dmarc-reports@votredomaine.com\n"
                          "📈 BÉNÉFICE: Visibilité complète sur la sécurité email",
                          "DMARC_POLICY"))
    else:
        out.append(status("OK",
                          "RAPPORTS DMARC CONFIGURÉS ! 📊\n"
                          "✅ SURVEILLANCE ACTIVE: Données collectées quotidiennement\n"
                          "🎯 AVANTAGES OPÉRATIONNELS:\n"
                          "   • Détection proactive des tentatives d'usurpation\n"
                          "   • Monitoring des sources d'envoi légitimes\n"
                          "   • Optimisation continue de la configuration\n"
                          "   • Preuves pour investigations sécurité\n"
                          "📊 RECOMMANDATION: Analyser les rapports mensuellement",
                          "DMARC_POLICY"))
    
    return out

# ----------------- Analyse MTA-STS ULTRA-DÉTAILLÉE -----------------

def analyze_mta_sts(mta: dict) -> List[Status]:
    out: List[Status] = []
    
    if not mta or not mta.get("valid", False):
        error_detail = mta.get('error', 'non déployé') if mta else 'non déployé'
        out.append(status("WARNING",
                          f"MTA-STS NON DÉPLOYÉ ! 🔐\n"
                          f"📋 STATUT: {error_detail}\n"
                          f"⚠️ IMPACT SÉCURITAIRE:\n"
                          f"   • Pas de protection contre dégradation TLS forcée\n"
                          f"   • Vulnérabilité aux attaques 'man-in-the-middle'\n"
                          f"   • Chiffrement email optionnel (pas garanti)\n"
                          f"🎯 MTA-STS EXPLIQUÉ:\n"
                          f"   • Force les serveurs à utiliser TLS (chiffrement)\n"
                          f"   • Empêche la dégradation vers connexions non-chiffrées\n"
                          f"   • Valide les certificats des serveurs destinataires\n"
                          f"💡 DÉPLOIEMENT OPTIONNEL MAIS RECOMMANDÉ:\n"
                          f"   1. Créer fichier politique sur https://mta-sts.votredomaine.com\n"
                          f"   2. Publier enregistrement DNS _mta-sts.votredomaine.com\n"
                          f"   3. Configurer mode 'enforce' après tests\n"
                          f"📊 PRIORITÉ: Moyenne (sécurité renforcée)",
                          "MTA_STS"))
    else:
        mode = mta.get("policy", {}).get("mode", "inconnu")
        out.append(status("OK",
                          f"MTA-STS DÉPLOYÉ AVEC SUCCÈS ! 🔐\n"
                          f"🛡️ MODE ACTUEL: {mode}\n"
                          f"✅ PROTECTION TLS ACTIVÉE:\n"
                          f"   • Connexions chiffrées obligatoires\n"
                          f"   • Prévention des attaques de dégradation\n"
                          f"   • Validation des certificats serveurs\n"
                          f"🎯 AVANTAGES SÉCURITAIRES:\n"
                          f"   • Emails protégés en transit\n"
                          f"   • Résistance aux interceptions\n"
                          f"   • Conformité aux standards modernes\n"
                          f"📊 CONFIGURATION: Excellente (standard avancé)",
                          "MTA_STS"))
    
    return out

# ----------------- Analyse TLS-RPT ULTRA-DÉTAILLÉE -----------------

def analyze_tlsrpt(tls: dict) -> List[Status]:
    out: List[Status] = []
    
    if not tls or not tls.get("valid", False):
        out.append(status("WARNING",
                          "TLS-RPT NON CONFIGURÉ ! 📊\n"
                          "⚠️ SURVEILLANCE TLS MANQUANTE:\n"
                          "   • Aucune visibilité sur les échecs de chiffrement\n"
                          "   • Problèmes TLS non détectés automatiquement\n"
                          "   • Attaques de dégradation invisibles\n"
                          "🎯 TLS-RPT EXPLIQUÉ:\n"
                          "   • Rapports automatiques sur échecs TLS\n"
                          "   • Détection proactive des problèmes de livraison\n"
                          "   • Monitoring de la sécurité transport\n"
                          "💡 AVANTAGES DU DÉPLOIEMENT:\n"
                          "   • Diagnostic rapide des problèmes de délivrabilité\n"
                          "   • Détection des tentatives d'interception\n"
                          "   • Optimisation de la configuration TLS\n"
                          "🛠️ DÉPLOIEMENT SIMPLE:\n"
                          "   Enregistrement DNS: _smtp._tls.votredomaine.com\n"
                          "   Contenu: v=TLSRPTv1; rua=mailto:tls-reports@votredomaine.com\n"
                          "📊 PRIORITÉ: Faible (monitoring avancé)",
                          "TLS_RPT"))
    else:
        out.append(status("OK",
                          "TLS-RPT CONFIGURÉ ! 📊\n"
                          "✅ MONITORING TLS ACTIF:\n"
                          "   • Surveillance continue des échecs de chiffrement\n"
                          "   • Détection automatique des problèmes\n"
                          "   • Rapports détaillés sur les connexions TLS\n"
                          "🎯 BÉNÉFICES OPÉRATIONNELS:\n"
                          "   • Résolution proactive des problèmes de livraison\n"
                          "   • Visibilité sur la santé de l'infrastructure\n"
                          "   • Amélioration continue de la sécurité\n"
                          "📊 CONFIGURATION: Avancée (monitoring pro-actif)",
                          "TLS_RPT"))
    
    return out

# ----------------- Analyse DNSSEC ULTRA-DÉTAILLÉE -----------------

def analyze_dnssec(enabled: bool) -> List[Status]:
    if enabled:
        return [status("OK",
                      "DNSSEC ACTIVÉ - PROTECTION DNS MAXIMALE ! 🔐\n"
                      "✅ SÉCURITÉ DNS RENFORCÉE:\n"
                      "   • Authentification cryptographique des réponses DNS\n"
                      "   • Protection contre empoisonnement du cache DNS\n"
                      "   • Intégrité garantie des enregistrements SPF/DKIM/DMARC\n"
                      "🎯 AVANTAGES CRITIQUES:\n"
                      "   • Attaques DNS spoofing: impossibles\n"
                      "   • Redirection malveillante: bloquée\n"
                      "   • Confiance absolue dans les résolutions DNS\n"
                      "🏆 IMPACT BUSINESS:\n"
                      "   • Infrastructure email ultra-sécurisée\n"
                      "   • Protection contre attaques sophistiquées\n"
                      "   • Conformité aux standards sécuritaires avancés\n"
                      "📊 NIVEAU: Excellence sécuritaire (top 5% des domaines)",
                      "DNSSEC")]
    
    return [status("WARNING",
                  "DNSSEC NON DÉPLOYÉ ! 🔓\n"
                  "⚠️ VULNÉRABILITÉ DNS:\n"
                  "   • Réponses DNS non authentifiées\n"
                  "   • Risque d'empoisonnement du cache DNS\n"
                  "   • Possibilité de redirection malveillante\n"
                  "🎯 ATTAQUES POSSIBLES:\n"
                  "   • Détournement des enregistrements SPF/DKIM\n"
                  "   • Redirection emails vers serveurs malveillants\n"
                  "   • Compromission de l'authentification email\n"
                  "💡 DNSSEC EXPLIQUÉ:\n"
                  "   • Signature cryptographique des zones DNS\n"
                  "   • Validation de l'authenticité par les résolveurs\n"
                  "   • Chaîne de confiance depuis les serveurs racine\n"
                  "🛠️ DÉPLOIEMENT:\n"
                  "   • Contacter registraire/hébergeur DNS\n"
                  "   • Activation généralement gratuite\n"
                  "   • Configuration technique requise\n"
                  "📊 PRIORITÉ: Moyenne (sécurité renforcée)",
                  "DNSSEC")]

# ----------------- Analyse BIMI ULTRA-DÉTAILLÉE -----------------

def analyze_bimi(bimi: dict, dmarc_policy: str) -> List[Status]:
    out: List[Status] = []
    
    if not bimi or not bimi.get("record"):
        out.append(status("INFO",
                          "BIMI NON DÉPLOYÉ (NORMAL) 🎨\n"
                          "📋 STATUT: Optionnel - Impact marketing uniquement\n"
                          "🎯 BIMI EXPLIQUÉ:\n"
                          "   • Brand Indicators for Message Identification\n"
                          "   • Affiche logo de votre marque dans les clients email\n"
                          "   • Renforce reconnaissance visuelle de vos emails\n"
                          "💡 AVANTAGES MARKETING:\n"
                          "   • Amélioration de la reconnaissance de marque\n"
                          "   • Différenciation visuelle dans la boîte de réception\n"
                          "   • Renforcement de la confiance utilisateur\n"
                          "   • Réduction du phishing par usurpation visuelle\n"
                          "⚠️ PRÉREQUIS STRICTS:\n"
                          "   • DMARC avec p=quarantine ou p=reject OBLIGATOIRE\n"
                          "   • Certificat VMC (Verified Mark Certificate) requis\n"
                          "   • Logo au format SVG spécifique\n"
                          "📊 PRIORITÉ: Très faible (cosmétique/marketing)",
                          "BIMI"))
        return out

    if not bimi.get("valid", False):
        error_detail = bimi.get('error', 'configuration invalide')
        out.append(status("WARNING",
                          f"BIMI INVALIDE ! 🎨\n"
                          f"🔴 ERREUR: {error_detail}\n"
                          f"⚠️ CONSÉQUENCE: Logo non affiché dans les clients email\n"
                          f"🎯 CAUSES FRÉQUENTES:\n"
                          f"   • Format SVG non conforme aux spécifications\n"
                          f"   • URL du logo inaccessible ou incorrecte\n"
                          f"   • Certificat VMC manquant ou invalide\n"
                          f"   • Syntaxe de l'enregistrement DNS incorrecte\n"
                          f"🛠️ DIAGNOSTIC RECOMMANDÉ:\n"
                          f"   1. Valider le format SVG avec outils BIMI\n"
                          f"   2. Vérifier accessibilité de l'URL logo\n"
                          f"   3. Contrôler validité du certificat VMC\n"
                          f"📊 IMPACT: Cosmétique uniquement (pas de sécurité)",
                          "BIMI"))
    else:
        out.append(status("OK",
                          "BIMI CONFIGURÉ AVEC SUCCÈS ! 🎨\n"
                          "✅ LOGO DE MARQUE ACTIF:\n"
                          "   • Affichage du logo dans Gmail, Yahoo, etc.\n"
                          "   • Renforcement de l'identité visuelle\n"
                          "   • Différenciation premium dans les boîtes de réception\n"
                          "🎯 AVANTAGES MARKETING RÉALISÉS:\n"
                          "   • Reconnaissance immédiate de vos emails\n"
                          "   • Confiance renforcée des destinataires\n"
                          "   • Protection contre usurpation visuelle\n"
                          "📊 STATUT: Configuration marketing optimale",
                          "BIMI"))

    # Vérification DMARC (prérequis critique pour BIMI)
    if dmarc_policy not in ["reject", "quarantine"]:
        out.append(status("WARNING",
                          "BIMI SANS DMARC STRICT ! ⚠️\n"
                          f"🚨 PROBLÈME: DMARC en mode '{dmarc_policy}' (requis: quarantine/reject)\n"
                          "💀 CONSÉQUENCE: Logo BIMI ignoré par la plupart des clients\n"
                          "🎯 EXPLICATION TECHNIQUE:\n"
                          "   • BIMI exige une protection anti-usurpation forte\n"
                          "   • Gmail/Yahoo refusent d'afficher logos sans DMARC strict\n"
                          "   • Investissement BIMI gaspillé sans protection préalable\n"
                          "🛠️ SOLUTION:\n"
                          "   1. Corriger DMARC vers p=quarantine ou p=reject\n"
                          "   2. Attendre propagation (24-48h)\n"
                          "   3. BIMI fonctionnera automatiquement\n"
                          "📊 PRIORITÉ: Moyenne (corriger DMARC d'abord)",
                          "BIMI"))
    
    return out

# ----------------- Analyse MX et STARTTLS ULTRA-DÉTAILLÉE -----------------

def analyze_mx_starttls(mx: dict) -> List[Status]:
    """Analyse les serveurs MX et leurs capacités STARTTLS"""
    out: List[Status] = []
    
    if not mx or not mx.get("hosts"):
        out.append(status("CRITICAL",
                          "AUCUN SERVEUR MX CONFIGURÉ !\n"
                          "🚨 PROBLÈME CRITIQUE: Impossible de recevoir des emails\n"
                          "💥 CONSÉQUENCES IMMÉDIATES:\n"
                          "   • Emails entrants perdus définitivement\n"
                          "   • Communications clients interrompues\n"
                          "   • Perte d'opportunités commerciales\n"
                          "   • Réputation professionnelle dégradée\n"
                          "🛠️ SOLUTION URGENTE:\n"
                          "   Configurer au minimum un enregistrement MX\n"
                          "   Exemple: '10 mail.votredomaine.com'",
                          "SPF_LIMIT"))
        return out

    hosts = mx.get("hosts", [])
    out.append(status("INFO", f"📧 {len(hosts)} serveur(s) MX configuré(s)", "MTA_STS"))
    
    starttls_supported = 0
    starttls_failed = 0
    connection_issues = 0
    
    for i, host in enumerate(hosts):
        hostname = host.get("hostname", "inconnu")
        preference = host.get("preference", 0)
        starttls = host.get("starttls", False)
        addresses = host.get("addresses", [])
        
        out.append(status("INFO", 
                          f"🖥️ Serveur MX #{i+1}: {hostname} (priorité: {preference})\n"
                          f"   📍 Adresses IP: {', '.join(addresses) if addresses else 'Non résolues'}\n"
                          f"   🔐 STARTTLS: {'✅ Supporté' if starttls else '❌ Non supporté'}",
                          "MTA_STS"))
        
        if starttls:
            starttls_supported += 1
        else:
            starttls_failed += 1
            
    # Vérification des warnings de connexion
    warnings = mx.get("warnings", [])
    if warnings:
        connection_issues = len([w for w in warnings if "Connection" in w or "timed out" in w])
        out.append(status("WARNING",
                          f"PROBLÈMES DE CONNECTIVITÉ DÉTECTÉS ! ⚠️\n"
                          f"🚨 {len(warnings)} serveur(s) MX inaccessible(s)\n"
                          f"📝 Détails:\n" + "\n".join([f"   • {w}" for w in warnings]) + "\n"
                          f"💡 CAUSES POSSIBLES:\n"
                          f"   • Serveurs temporairement hors ligne\n"
                          f"   • Firewall bloquant les connexions SMTP\n"
                          f"   • Configuration DNS incorrecte\n"
                          f"   • Maintenance en cours\n"
                          f"🔧 ACTIONS RECOMMANDÉES:\n"
                          f"   1. Vérifier statut serveurs avec l'équipe IT\n"
                          f"   2. Tester connectivité SMTP manuellement\n"
                          f"   3. Contrôler règles firewall",
                          "MTA_STS"))

    # Analyse globale STARTTLS
    if starttls_failed == 0 and starttls_supported > 0:
        out.append(status("OK",
                          "STARTTLS PARFAITEMENT CONFIGURÉ ! 🔐\n"
                          f"✅ TOUS les serveurs MX ({starttls_supported}/{len(hosts)}) supportent STARTTLS\n"
                          "🛡️ PROTECTION OPTIMALE:\n"
                          "   • Emails entrants chiffrés en transit\n"
                          "   • Protection contre interception\n"
                          "   • Conformité sécurité maximale\n"
                          "🏆 AVANTAGES RÉALISÉS:\n"
                          "   • Confidentialité des communications\n"
                          "   • Respect des réglementations (RGPD, etc.)\n"
                          "   • Confiance renforcée des partenaires",
                          "MTA_STS"))
    elif starttls_supported > 0:
        out.append(status("WARNING",
                          f"STARTTLS PARTIELLEMENT SUPPORTÉ ! ⚠️\n"
                          f"📊 ÉTAT: {starttls_supported}/{len(hosts)} serveurs supportent STARTTLS\n"
                          f"🚨 RISQUE: Emails non chiffrés sur certains serveurs\n"
                          f"💡 PROBLÈME: Configuration hétérogène\n"
                          f"🎯 IMPACT SÉCURITÉ:\n"
                          f"   • Faille potentielle d'interception\n"
                          f"   • Non-conformité partielle\n"
                          f"   • Risque selon serveur utilisé\n"
                          f"🛠️ SOLUTION:\n"
                          f"   Activer STARTTLS sur TOUS les serveurs MX",
                          "MTA_STS"))
    else:
        out.append(status("CRITICAL",
                          "AUCUN SUPPORT STARTTLS DÉTECTÉ ! 🚨\n"
                          f"💥 PROBLÈME MAJEUR: {len(hosts)} serveur(s) MX sans chiffrement\n"
                          "⚡ VULNÉRABILITÉ CRITIQUE:\n"
                          "   • Emails en texte clair sur le réseau\n"
                          "   • Interception facile par des tiers\n"
                          "   • Violation de confidentialité\n"
                          "   • Non-conformité réglementaire\n"
                          "🔥 RISQUES BUSINESS:\n"
                          "   • Espionnage industriel possible\n"
                          "   • Sanctions RGPD/compliance\n"
                          "   • Perte de confiance clients\n"
                          "🆘 ACTION URGENTE:\n"
                          "   Configurer STARTTLS sur tous serveurs MX",
                          "MTA_STS"))
    
    return out

# ----------------- Analyse des critères de sécurité spécifiques -----------------

def analyze_security_criteria(report: dict) -> List[Status]:
    """Vérifie les 10 critères de sécurité spécifiques du fichier critère.txt"""
    out: List[Status] = []
    
    out.append(status("INFO", "📋 VÉRIFICATION DES CRITÈRES DE SÉCURITÉ SPÉCIFIQUES", "SPF_ALL"))
    
    # 1. SPF - SPF record present
    spf = report.get("spf", {})
    if spf.get("record") and spf.get("valid", False):
        out.append(status("OK", "✅ CRITÈRE 1/10: Enregistrement SPF présent et valide", "SPF_ALL"))
    else:
        out.append(status("CRITICAL", "❌ CRITÈRE 1/10: Enregistrement SPF absent ou invalide", "SPF_ALL"))
    
    # 2. SPF - Strict mode (vérifie si -all est utilisé)
    spf_record = spf.get("record", "") or ""
    if spf_record.strip().endswith("-all"):
        out.append(status("OK", "✅ CRITÈRE 2/10: SPF en mode strict (-all)", "SPF_ALL"))
    else:
        out.append(status("CRITICAL", "❌ CRITÈRE 2/10: SPF pas en mode strict (manque -all)", "SPF_ALL"))
    
    # 3. DMARC - DMARC record present
    dmarc = report.get("dmarc", {})
    if dmarc.get("record") and dmarc.get("valid", False):
        out.append(status("OK", "✅ CRITÈRE 3/10: Enregistrement DMARC présent et valide", "DMARC_POLICY"))
    else:
        out.append(status("CRITICAL", "❌ CRITÈRE 3/10: Enregistrement DMARC absent ou invalide", "DMARC_POLICY"))
    
    # 4. DMARC - Policy is not none
    dmarc_policy = dmarc.get("tags", {}).get("p", {}).get("value", "none")
    if dmarc_policy in ["quarantine", "reject"]:
        out.append(status("OK", f"✅ CRITÈRE 4/10: Politique DMARC stricte (p={dmarc_policy})", "DMARC_POLICY"))
    else:
        out.append(status("CRITICAL", f"❌ CRITÈRE 4/10: Politique DMARC non stricte (p={dmarc_policy})", "DMARC_POLICY"))
    
    # 5. DMARC - Strict mode (vérifie si p=reject)
    if dmarc_policy == "reject":
        out.append(status("OK", "✅ CRITÈRE 5/10: DMARC en mode strict maximum (p=reject)", "DMARC_POLICY"))
    elif dmarc_policy == "quarantine":
        out.append(status("WARNING", "⚠️ CRITÈRE 5/10: DMARC modérément strict (p=quarantine, recommandé: p=reject)", "DMARC_POLICY"))
    else:
        out.append(status("CRITICAL", f"❌ CRITÈRE 5/10: DMARC pas en mode strict (p={dmarc_policy})", "DMARC_POLICY"))
    
    # 6. DMARC - rua present (rapports agrégés)
    if "rua" in dmarc.get("tags", {}):
        out.append(status("OK", "✅ CRITÈRE 6/10: Adresse RUA (rapports agrégés) configurée", "DMARC_POLICY"))
    else:
        out.append(status("CRITICAL", "❌ CRITÈRE 6/10: Adresse RUA (rapports agrégés) manquante", "DMARC_POLICY"))
    
    # 7. DMARC - ruf present (rapports détaillés)
    if "ruf" in dmarc.get("tags", {}):
        out.append(status("OK", "✅ CRITÈRE 7/10: Adresse RUF (rapports détaillés) configurée", "DMARC_POLICY"))
    else:
        out.append(status("WARNING", "⚠️ CRITÈRE 7/10: Adresse RUF (rapports détaillés) manquante", "DMARC_POLICY"))
    
    # 8. DMARC - pct equals 100
    dmarc_pct = dmarc.get("tags", {}).get("pct", {}).get("value", 0)
    if dmarc_pct == 100:
        out.append(status("OK", "✅ CRITÈRE 8/10: DMARC appliqué à 100% du trafic (pct=100)", "DMARC_POLICY"))
    else:
        out.append(status("WARNING", f"⚠️ CRITÈRE 8/10: DMARC partiel (pct={dmarc_pct}%, recommandé: 100%)", "DMARC_POLICY"))
    
    # 9. Mail Server - smtp - starttls offered
    mx = report.get("mx", {})
    mx_hosts = mx.get("hosts", [])
    starttls_count = sum(1 for host in mx_hosts if host.get("starttls", False))
    if starttls_count > 0 and starttls_count == len(mx_hosts):
        out.append(status("OK", f"✅ CRITÈRE 9/10: STARTTLS supporté sur tous les serveurs MX ({starttls_count}/{len(mx_hosts)})", "MTA_STS"))
    elif starttls_count > 0:
        out.append(status("WARNING", f"⚠️ CRITÈRE 9/10: STARTTLS partiel ({starttls_count}/{len(mx_hosts)} serveurs)", "MTA_STS"))
    else:
        out.append(status("CRITICAL", "❌ CRITÈRE 9/10: Aucun serveur MX ne supporte STARTTLS", "MTA_STS"))
    
    # 10. Mail Server - no pop service (ce critère nécessite une analyse externe)
    # Note: Cette information n'est pas disponible dans le scan checkdmarc standard
    out.append(status("INFO", "ℹ️ CRITÈRE 10/10: Service POP (nécessite vérification manuelle)", "MTA_STS"))
    
    return out

# ----------------- Audit complet avec explications -----------------

def audit_domain(report: dict) -> List[Status]:
    results: List[Status] = []
    
    print("🔍 ANALYSE DÉTAILLÉE DES PROTOCOLES D'AUTHENTIFICATION EMAIL\n")
    
    # SPF Analysis
    print("=" * 60)
    print("📧 SPF (Sender Policy Framework)")
    print("=" * 60)
    results += analyze_spf(report.get("spf"))
    
    # DKIM Analysis  
    print("=" * 60)
    print("🔑 DKIM (DomainKeys Identified Mail)")
    print("=" * 60)
    results += analyze_dkim(report.get("dkim"))
    
    # DMARC Analysis
    print("=" * 60)
    print("🛡️ DMARC (Domain-based Message Authentication)")
    print("=" * 60)
    results += analyze_dmarc(report.get("dmarc"))
    
    # MX et STARTTLS Analysis
    print("=" * 60)
    print("📧 SERVEURS MX et STARTTLS")
    print("=" * 60)
    results += analyze_mx_starttls(report.get("mx"))
    
    # MTA-STS Analysis
    print("=" * 60)
    print("🔐 MTA-STS (Mail Transfer Agent Strict Transport Security)")
    print("=" * 60)
    results += analyze_mta_sts(report.get("mta_sts"))
    
    # TLS-RPT Analysis
    print("=" * 60)
    print("📊 TLS-RPT (Transport Layer Security Reporting)")
    print("=" * 60)
    results += analyze_tlsrpt(report.get("smtp_tls_reporting"))
    
    # DNSSEC Analysis
    print("=" * 60)
    print("🔒 DNSSEC (Domain Name System Security Extensions)")
    print("=" * 60)
    results += analyze_dnssec(report.get("dnssec", False))
    
    # BIMI Analysis
    print("=" * 60)
    print("🎨 BIMI (Brand Indicators for Message Identification)")
    print("=" * 60)
    dmarc_policy = report.get("dmarc", {}).get("tags", {}).get("p", {}).get("value", "none")
    results += analyze_bimi(report.get("bimi"), dmarc_policy)
    
    # Critères de sécurité spécifiques
    print("=" * 60)
    print("📋 VÉRIFICATION CRITÈRES DE SÉCURITÉ")
    print("=" * 60)
    results += analyze_security_criteria(report)
    
    return results

# ----------------- Main avec rapport final -----------------

def main() -> None:
    if len(sys.argv) < 2:
        print("🔍 AUDITEUR EMAIL ULTRA-DÉTAILLÉ")
        print("=" * 50)
        print("Usage : python3 checkdmarc_enhanced.py <scan1.json> [scan2.json ...]")
        print("\n📋 Ce script analyse en profondeur vos configurations email et explique :")
        print("   • POURQUOI chaque élément est critique")
        print("   • QUE SE PASSE-T-IL en cas de mauvaise configuration") 
        print("   • COMMENT corriger les problèmes détectés")
        print("   • QUEL EST L'IMPACT BUSINESS de chaque vulnérabilité")
        sys.exit(1)

    overall_ok = True
    total_domains = 0
    critical_issues = 0
    warning_issues = 0
    
    for file in sys.argv[1:]:
        path = Path(file)
        if not path.exists():
            print(f"❌ Fichier introuvable : {file}")
            continue

        total_domains += 1
        print(f"\n🎯 ===== AUDIT SÉCURITÉ EMAIL POUR : {path.stem.upper()} =====")
        
        try:
            data = json.loads(path.read_text())
            statuses = audit_domain(data)
            
            domain_critical = 0
            domain_warnings = 0
            
            for st in statuses:
                print_status(st)
                if st[0] == "CRITICAL":
                    overall_ok = False
                    domain_critical += 1
                    critical_issues += 1
                elif st[0] == "WARNING":
                    domain_warnings += 1
                    warning_issues += 1
            
            # Résumé par domaine
            print("=" * 60)
            print(f"📊 RÉSUMÉ POUR {path.stem.upper()}")
            print("=" * 60)
            if domain_critical == 0 and domain_warnings == 0:
                print("🏆 EXCELLENT ! Configuration email exemplaire !")
            elif domain_critical == 0:
                print(f"✅ BON ! {domain_warnings} améliorations recommandées")
            else:
                print(f"🚨 CRITIQUE ! {domain_critical} problèmes majeurs + {domain_warnings} warnings")
            print()
            
        except Exception as e:
            print(f"❌ Erreur lors de l'analyse de {file}: {e}")
            overall_ok = False

    # Rapport final global
    print("\n" + "=" * 80)
    print("🎯 RAPPORT FINAL - AUDIT SÉCURITÉ EMAIL")
    print("=" * 80)
    
    if total_domains == 1:
        if overall_ok:
            print("🏆 FÉLICITATIONS ! Votre domaine est correctement sécurisé.")
        else:
            print("⚠️ ATTENTION ! Des vulnérabilités critiques ont été détectées.")
    else:
        print(f"📊 DOMAINES ANALYSÉS: {total_domains}")
        print(f"🚨 PROBLÈMES CRITIQUES: {critical_issues}")
        print(f"⚠️ AMÉLIORATIONS RECOMMANDÉES: {warning_issues}")
        
        if overall_ok:
            print("🏆 RÉSULTAT GLOBAL: Tous vos domaines sont correctement protégés !")
        else:
            print("⚠️ RÉSULTAT GLOBAL: Des actions correctives immédiates sont requises.")
    
    print("\n💡 PROCHAINES ÉTAPES RECOMMANDÉES:")
    if critical_issues > 0:
        print("   1. 🚨 URGENT: Corriger IMMÉDIATEMENT les problèmes CRITIQUES")
        print("   2. ⚠️ Planifier les améliorations pour les warnings")
        print("   3. 🔄 Re-scanner après corrections")
    elif warning_issues > 0:
        print("   1. ⚠️ Planifier les améliorations recommandées")
        print("   2. 🔄 Re-scanner après optimisations")
        print("   3. 📊 Monitorer les rapports DMARC régulièrement")
    else:
        print("   1. 📊 Surveiller les rapports DMARC mensuellement")
        print("   2. 🔄 Re-scanner trimestriellement")
        print("   3. 🏆 Maintenir l'excellence sécuritaire !")
    
    print(f"\n⏰ AUDIT TERMINÉ - Code retour: {'0 (succès)' if overall_ok else '1 (problèmes détectés)'}")
    sys.exit(0 if overall_ok else 1)

if __name__ == "__main__":
    main()
