#!/usr/bin/env python3
"""
Script pour comparer les domaines dans critère.txt avec les hostnames de subfinder_output.json
et générer un rapport des différences.
"""

import json
import re
from urllib.parse import urlparse
from typing import Set, List, Dict

def extract_domains_from_criteria(file_path: str) -> Set[str]:
    """Extrait les domaines/hostnames du fichier critère.txt"""
    domains = set()
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Parser l'URL pour extraire le hostname
                if line.startswith(('http://', 'https://')):
                    parsed = urlparse(line)
                    hostname = parsed.netloc
                    if hostname:
                        domains.add(hostname)
                else:
                    # Si ce n'est pas une URL complète, considérer comme un hostname
                    if '.' in line and not line.startswith('#'):
                        domains.add(line)
    
    except FileNotFoundError:
        print(f"❌ Fichier critère.txt non trouvé: {file_path}")
        return set()
    except Exception as e:
        print(f"❌ Erreur lors de la lecture de critère.txt: {e}")
        return set()
    
    return domains

def extract_hostnames_from_subfinder(file_path: str) -> Set[str]:
    """Extrait les hostnames du fichier JSON de subfinder"""
    hostnames = set()
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    if 'host' in data:
                        hostnames.add(data['host'])
                except json.JSONDecodeError:
                    continue
    
    except FileNotFoundError:
        print(f"❌ Fichier subfinder_output.json non trouvé: {file_path}")
        return set()
    except Exception as e:
        print(f"❌ Erreur lors de la lecture de subfinder_output.json: {e}")
        return set()
    
    return hostnames

def extract_hostnames_from_amass(file_path: str) -> Set[str]:
    """Extrait les hostnames du fichier JSON d'amass"""
    hostnames = set()
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    if 'name' in data:
                        hostnames.add(data['name'])
                except json.JSONDecodeError:
                    continue
    
    except FileNotFoundError:
        print(f"❌ Fichier amass.json non trouvé: {file_path}")
        return set()
    except Exception as e:
        print(f"❌ Erreur lors de la lecture de amass.json: {e}")
        return set()
    
    return hostnames

def categorize_domains(domains: Set[str]) -> Dict[str, List[str]]:
    """Catégorise les domaines par domaine principal"""
    categories = {}
    
    for domain in domains:
        # Extraire le domaine principal (les deux derniers segments)
        parts = domain.split('.')
        if len(parts) >= 2:
            main_domain = '.'.join(parts[-2:])
            if main_domain not in categories:
                categories[main_domain] = []
            categories[main_domain].append(domain)
    
    # Trier les domaines dans chaque catégorie
    for main_domain in categories:
        categories[main_domain].sort()
    
    return categories

def generate_comparison_report(criteria_domains: Set[str], subfinder_hostnames: Set[str], amass_hostnames: Set[str] = None) -> str:
    """Génère un rapport de comparaison détaillé"""
    
    # Si amass_hostnames n'est pas fourni, utiliser un ensemble vide
    if amass_hostnames is None:
        amass_hostnames = set()
    
    # Calculs des différences
    in_criteria_subfinder = criteria_domains & subfinder_hostnames
    in_criteria_amass = criteria_domains & amass_hostnames
    in_subfinder_amass = subfinder_hostnames & amass_hostnames
    in_all_three = criteria_domains & subfinder_hostnames & amass_hostnames
    
    only_in_criteria = criteria_domains - subfinder_hostnames - amass_hostnames
    only_in_subfinder = subfinder_hostnames - criteria_domains - amass_hostnames
    only_in_amass = amass_hostnames - criteria_domains - subfinder_hostnames
    
    # Catégorisation
    criteria_by_domain = categorize_domains(criteria_domains)
    subfinder_by_domain = categorize_domains(subfinder_hostnames)
    amass_by_domain = categorize_domains(amass_hostnames)
    all_three_by_domain = categorize_domains(in_all_three)
    only_criteria_by_domain = categorize_domains(only_in_criteria)
    only_subfinder_by_domain = categorize_domains(only_in_subfinder)
    only_amass_by_domain = categorize_domains(only_in_amass)
    
    report = []
    report.append("=" * 80)
    report.append("RAPPORT DE COMPARAISON - DOMAINES/HOSTNAMES")
    report.append("Critère.txt vs Subfinder vs Amass")
    report.append("=" * 80)
    report.append("")
    
    # Statistiques générales
    report.append("📊 STATISTIQUES GÉNÉRALES")
    report.append("-" * 40)
    report.append(f"Total domaines dans critère.txt: {len(criteria_domains)}")
    report.append(f"Total hostnames dans subfinder: {len(subfinder_hostnames)}")
    if amass_hostnames:
        report.append(f"Total hostnames dans amass: {len(amass_hostnames)}")
    report.append("")
    
    # Intersections
    report.append("🔄 INTERSECTIONS")
    report.append("-" * 20)
    report.append(f"Communs à tous (critère + subfinder + amass): {len(in_all_three)}")
    report.append(f"Critère ∩ Subfinder: {len(in_criteria_subfinder)}")
    if amass_hostnames:
        report.append(f"Critère ∩ Amass: {len(in_criteria_amass)}")
        report.append(f"Subfinder ∩ Amass: {len(in_subfinder_amass)}")
    report.append("")
    
    # Uniques
    report.append("🎯 DOMAINES UNIQUES")
    report.append("-" * 25)
    report.append(f"Uniquement dans critère.txt: {len(only_in_criteria)}")
    report.append(f"Uniquement dans subfinder: {len(only_in_subfinder)}")
    if amass_hostnames:
        report.append(f"Uniquement dans amass: {len(only_in_amass)}")
    report.append("")
    
    # Pourcentages
    if len(criteria_domains) > 0:
        subfinder_coverage = (len(in_criteria_subfinder) / len(criteria_domains)) * 100
        report.append(f"🎯 Couverture subfinder: {subfinder_coverage:.1f}% des domaines de critère.txt")
        
        if amass_hostnames:
            amass_coverage = (len(in_criteria_amass) / len(criteria_domains)) * 100
            report.append(f"🎯 Couverture amass: {amass_coverage:.1f}% des domaines de critère.txt")
            
            combined_coverage = (len(criteria_domains & (subfinder_hostnames | amass_hostnames)) / len(criteria_domains)) * 100
            report.append(f"🎯 Couverture combinée (subfinder + amass): {combined_coverage:.1f}%")
    
    report.append("")
    report.append("")
    
    # Domaines communs aux trois
    if in_all_three:
        report.append("✅ DOMAINES COMMUNS AUX TROIS SOURCES")
        report.append("-" * 50)
        for main_domain in sorted(all_three_by_domain.keys()):
            report.append(f"\n🌐 {main_domain}:")
            for domain in all_three_by_domain[main_domain]:
                report.append(f"  ✓ {domain}")
        report.append("")
        report.append("")
    
    # Uniquement dans critère.txt
    if only_in_criteria:
        report.append("⚠️  UNIQUEMENT DANS CRITÈRE.TXT (manqués par tous les outils)")
        report.append("-" * 70)
        for main_domain in sorted(only_criteria_by_domain.keys()):
            report.append(f"\n🌐 {main_domain}:")
            for domain in only_criteria_by_domain[main_domain]:
                report.append(f"  ❌ {domain}")
        report.append("")
        report.append("")
    
    # Uniquement dans subfinder
    if only_in_subfinder:
        report.append("🆕 UNIQUEMENT DANS SUBFINDER (découvertes exclusives)")
        report.append("-" * 60)
        for main_domain in sorted(only_subfinder_by_domain.keys()):
            report.append(f"\n🌐 {main_domain}:")
            for domain in only_subfinder_by_domain[main_domain]:
                report.append(f"  ➕ {domain}")
        report.append("")
        report.append("")
    
    # Uniquement dans amass
    if only_in_amass and amass_hostnames:
        report.append("🔍 UNIQUEMENT DANS AMASS (découvertes exclusives)")
        report.append("-" * 55)
        for main_domain in sorted(only_amass_by_domain.keys()):
            report.append(f"\n🌐 {main_domain}:")
            for domain in only_amass_by_domain[main_domain]:
                report.append(f"  ➕ {domain}")
        report.append("")
        report.append("")
    
    # Comparaison outils uniquement (subfinder vs amass)
    if amass_hostnames:
        subfinder_only_vs_amass = subfinder_hostnames - amass_hostnames
        amass_only_vs_subfinder = amass_hostnames - subfinder_hostnames
        
        if subfinder_only_vs_amass:
            report.append("🔄 SUBFINDER vs AMASS - Découvertes exclusives Subfinder")
            report.append("-" * 65)
            subfinder_exclusive_by_domain = categorize_domains(subfinder_only_vs_amass)
            for main_domain in sorted(subfinder_exclusive_by_domain.keys()):
                report.append(f"\n🌐 {main_domain}:")
                for domain in subfinder_exclusive_by_domain[main_domain]:
                    report.append(f"  📡 {domain}")
            report.append("")
            report.append("")
        
        if amass_only_vs_subfinder:
            report.append("🔄 SUBFINDER vs AMASS - Découvertes exclusives Amass")
            report.append("-" * 60)
            amass_exclusive_by_domain = categorize_domains(amass_only_vs_subfinder)
            for main_domain in sorted(amass_exclusive_by_domain.keys()):
                report.append(f"\n🌐 {main_domain}:")
                for domain in amass_exclusive_by_domain[main_domain]:
                    report.append(f"  🎯 {domain}")
            report.append("")
            report.append("")
    
    # Résumé par domaine principal
    report.append("📋 RÉSUMÉ PAR DOMAINE PRINCIPAL")
    report.append("-" * 40)
    
    all_main_domains = set(criteria_by_domain.keys()) | set(subfinder_by_domain.keys()) | set(amass_by_domain.keys())
    
    for main_domain in sorted(all_main_domains):
        criteria_count = len(criteria_by_domain.get(main_domain, []))
        subfinder_count = len(subfinder_by_domain.get(main_domain, []))
        amass_count = len(amass_by_domain.get(main_domain, []))
        
        report.append(f"\n🌐 {main_domain}:")
        report.append(f"  📄 Critère.txt: {criteria_count} domaines")
        report.append(f"  📡 Subfinder: {subfinder_count} hostnames")
        if amass_hostnames:
            report.append(f"  🎯 Amass: {amass_count} hostnames")
        
        if criteria_count > 0:
            subfinder_common = len([d for d in criteria_by_domain[main_domain] 
                                  if d in subfinder_hostnames])
            subfinder_coverage = (subfinder_common / criteria_count) * 100
            report.append(f"  📊 Couverture Subfinder: {subfinder_coverage:.1f}% ({subfinder_common}/{criteria_count})")
            
            if amass_hostnames:
                amass_common = len([d for d in criteria_by_domain[main_domain] 
                                  if d in amass_hostnames])
                amass_coverage = (amass_common / criteria_count) * 100
                report.append(f"  📊 Couverture Amass: {amass_coverage:.1f}% ({amass_common}/{criteria_count})")
                
                combined_common = len([d for d in criteria_by_domain[main_domain] 
                                     if d in (subfinder_hostnames | amass_hostnames)])
                combined_coverage = (combined_common / criteria_count) * 100
                report.append(f"  📊 Couverture Combinée: {combined_coverage:.1f}% ({combined_common}/{criteria_count})")
    
    report.append("")
    report.append("=" * 80)
    
    return "\n".join(report)

def main():
    """Fonction principale"""
    print("🔍 Comparaison des domaines - critère.txt vs subfinder vs amass")
    print("=" * 70)
    
    # Chemins des fichiers
    criteria_file = "/home/root-02/Desktop/boc-tools/scripts/critère.txt"
    subfinder_file = "/home/root-02/Desktop/boc-tools/scripts/final_scripts/output/hydrogeotechnique.com/subfinder/subfinder_output.json"
    amass_file = "/home/root-02/Desktop/boc-tools/scripts/final_scripts/output/hydrogeotechnique.com/amass/amass.json"
    
    # Extraction des domaines
    print("📄 Lecture de critère.txt...")
    criteria_domains = extract_domains_from_criteria(criteria_file)
    print(f"   ✓ {len(criteria_domains)} domaines extraits")
    
    print("📡 Lecture de subfinder_output.json...")
    subfinder_hostnames = extract_hostnames_from_subfinder(subfinder_file)
    print(f"   ✓ {len(subfinder_hostnames)} hostnames extraits")
    
    print("🎯 Lecture de amass.json...")
    amass_hostnames = extract_hostnames_from_amass(amass_file)
    print(f"   ✓ {len(amass_hostnames)} hostnames extraits")
    
    if not criteria_domains and not subfinder_hostnames and not amass_hostnames:
        print("❌ Aucun domaine trouvé dans les fichiers!")
        return
    
    # Génération du rapport
    print("📊 Génération du rapport de comparaison...")
    report = generate_comparison_report(criteria_domains, subfinder_hostnames, amass_hostnames)
    
    # Sauvegarde du rapport
    output_file = "/home/root-02/Desktop/boc-tools/scripts/final_scripts/domain_comparison_report_complete.txt"
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"✅ Rapport sauvegardé: {output_file}")
    except Exception as e:
        print(f"❌ Erreur lors de la sauvegarde: {e}")
    
    # Affichage du résumé
    print("\n" + "=" * 60)
    print("📊 RÉSUMÉ RAPIDE")
    print("=" * 60)
    
    # Intersections
    in_criteria_subfinder = criteria_domains & subfinder_hostnames
    in_criteria_amass = criteria_domains & amass_hostnames
    in_subfinder_amass = subfinder_hostnames & amass_hostnames
    in_all_three = criteria_domains & subfinder_hostnames & amass_hostnames
    
    # Uniques
    only_in_criteria = criteria_domains - subfinder_hostnames - amass_hostnames
    only_in_subfinder = subfinder_hostnames - criteria_domains - amass_hostnames
    only_in_amass = amass_hostnames - criteria_domains - subfinder_hostnames
    
    print(f"Total domaines critère.txt: {len(criteria_domains)}")
    print(f"Total hostnames subfinder: {len(subfinder_hostnames)}")
    print(f"Total hostnames amass: {len(amass_hostnames)}")
    print("")
    print("🔄 INTERSECTIONS:")
    print(f"  Communs aux 3 sources: {len(in_all_three)}")
    print(f"  Critère ∩ Subfinder: {len(in_criteria_subfinder)}")
    print(f"  Critère ∩ Amass: {len(in_criteria_amass)}")
    print(f"  Subfinder ∩ Amass: {len(in_subfinder_amass)}")
    print("")
    print("🎯 DÉCOUVERTES UNIQUES:")
    print(f"  Uniquement critère.txt: {len(only_in_criteria)}")
    print(f"  Uniquement subfinder: {len(only_in_subfinder)}")
    print(f"  Uniquement amass: {len(only_in_amass)}")
    
    if len(criteria_domains) > 0:
        subfinder_coverage = (len(in_criteria_subfinder) / len(criteria_domains)) * 100
        amass_coverage = (len(in_criteria_amass) / len(criteria_domains)) * 100
        combined_coverage = (len(criteria_domains & (subfinder_hostnames | amass_hostnames)) / len(criteria_domains)) * 100
        
        print("")
        print("📈 COUVERTURES:")
        print(f"  Subfinder: {subfinder_coverage:.1f}%")
        print(f"  Amass: {amass_coverage:.1f}%")
        print(f"  Combinée: {combined_coverage:.1f}%")

if __name__ == "__main__":
    main()
