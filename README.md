# TP1 - Analyse Forensique

Ce dépôt contient le rendu du TP d'analyse forensique, organisé en deux parties distinctes.

---

## 📁 Structure du dépôt

### [Partie 1 - Analyse Malware](./Partie1_Analyse_Malware/)

Analyse complète de malware (Res.exe et Env.exe) utilisant des techniques de reverse engineering et d'analyse statique.

**Contenu :**
- 📄 [README.md](./Partie1_Analyse_Malware/README.md) - Rapport d'analyse malware complet
- 📄 [ANALYSE_MALWARE.md](./Partie1_Analyse_Malware/ANALYSE_MALWARE.md) - Analyse détaillée du malware
- 📄 [DECOMPILATION_DETAILLEE.md](./Partie1_Analyse_Malware/DECOMPILATION_DETAILLEE.md) - Décompilation et analyse du code
- 📄 [GUIDE_OUTILS_REVERSE_ENGINEERING.md](./Partie1_Analyse_Malware/GUIDE_OUTILS_REVERSE_ENGINEERING.md) - Guide des outils utilisés
- 📄 [TUTORIEL_COMPLET_COMMANDES.md](./Partie1_Analyse_Malware/TUTORIEL_COMPLET_COMMANDES.md) - Tutoriel des commandes d'analyse

**Résumé :** Identification et analyse d'un dropper/spyware avec capacités d'exfiltration SMTP, persistance via registre Windows, et comportements malveillants confirmés.

---

### [Partie 2 - Analyse Dump RAM](./Partie2_Dump_RAM/)

Analyse forensique d'un dump mémoire RAM utilisant Volatility Framework.

**Contenu :**
- 📄 [RAPPORT_DUMP_RAM.md](./Partie2_Dump_RAM/RAPPORT_DUMP_RAM.md) - Rapport d'analyse du dump mémoire
- 📄 [COMMANDE_DUMP_RAM.md](./Partie2_Dump_RAM/COMMANDE_DUMP_RAM.md) - Commandes Volatility utilisées
- 📁 [results/](./Partie2_Dump_RAM/results/) - Résultats des analyses Volatility

**Résumé :** Investigation mémoire pour identifier les processus, connexions réseau, artefacts malveillants et autres IOCs présents dans le dump RAM.

---

## 🛠️ Technologies utilisées

**Partie 1 :**
- Kali Linux (environnement isolé)
- `strings`, `file`, `objdump`
- Analyse statique de binaires PE32
- Reverse engineering

**Partie 2 :**
- Volatility Framework
- Analyse forensique mémoire
- Investigation d'incidents

---

## ⚠️ Avertissement

Ce dépôt contient des analyses de malware à des fins éducatives uniquement. Les binaires analysés sont dangereux et ne doivent **JAMAIS** être exécutés en dehors d'un environnement isolé.

---

## 📝 Licence

Voir le fichier [LICENSE](./LICENSE) pour plus d'informations.

---

**Date:** 2025-12-01
**Environnement:** Kali Linux
