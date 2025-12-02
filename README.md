# TP1 - Analyse Forensique

Ce dépôt contient le rendu du TP d'analyse forensique, organisé en trois parties distinctes.

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
- 📄 [COMMANDES_DUMP_RAM.md](./Partie2_Dump_RAM/COMMANDES_DUMP_RAM.md) - Commandes Volatility utilisées
- 📁 [results/](./Partie2_Dump_RAM/results/) - Résultats des analyses Volatility

**Résumé :** Investigation mémoire pour identifier les processus, connexions réseau, artefacts malveillants et autres IOCs présents dans le dump RAM.

---

### [Partie 3 - Copie Bit-à-Bit de Disque](./Partie3_copie_disque/)

Acquisition forensique d'une partition disque avec copie bit-à-bit et vérification d'intégrité.

**Contenu :**
- 📄 [RAPPORT_COPIE_DISQUE.md](./Partie3_copie_disque/RAPPORT_COPIE_DISQUE.md) - Rapport forensique complet de l'acquisition
- 📄 [GUIDE_COPIE_DISQUE.md](./Partie3_copie_disque/GUIDE_COPIE_DISQUE.md) - Guide pratique avec tutoriel et commandes
- 📁 [images/](./Partie3_copie_disque/images/) - Image bit-à-bit de la partition (sda1.img - 976 Mo)
- 📁 [hashes/](./Partie3_copie_disque/hashes/) - Hashes MD5/SHA1/SHA256 pour vérification d'intégrité
- 📁 [logs/](./Partie3_copie_disque/logs/) - Métadonnées d'acquisition et logs

**Résumé :** Création d'une image forensique bit-à-bit de la partition EFI (/dev/sda1) avec dd, calcul de hashes cryptographiques (MD5, SHA1, SHA256) et vérification d'intégrité complète. L'image est une copie exacte vérifiée pour analyse forensique.

---

## 🛠️ Technologies utilisées

**Partie 1 :**
- Kali Linux (environnement isolé)
- `strings`, `file`, `objdump`
- Analyse statique de binaires PE32
- Reverse engineering

**Partie 2 :**
- LiME (Linux Memory Extractor)
- Volatility Framework
- Analyse forensique mémoire
- Investigation d'incidents

**Partie 3 :**
- dd (disk dump)
- Copie bit-à-bit (disk imaging)
- Hashing cryptographique (MD5, SHA1, SHA256)
- Vérification d'intégrité forensique
- Chaîne de traçabilité

---

## ⚠️ Avertissement

Ce dépôt contient des analyses de malware à des fins éducatives uniquement. Les binaires analysés sont dangereux et ne doivent **JAMAIS** être exécutés en dehors d'un environnement isolé.

---

## 📝 Licence

Voir le fichier [LICENSE](./LICENSE) pour plus d'informations.

---

**Date de dernière mise à jour:** 2025-12-02
**Environnement:** Kali Linux 6.16.8+kali-amd64
**Auteur:** nyx

## 📊 Statistiques du TP

| Partie | Fichiers | Taille totale | Durée |
|--------|----------|---------------|-------|
| **Partie 1** | 5 documents | ~120 Ko | ~3h |
| **Partie 2** | 2 documents + dump 12 Go | ~12 Go | ~20 min |
| **Partie 3** | 2 documents + image 976 Mo | ~976 Mo | ~20 min |
| **TOTAL** | **9 documents** | **~13 Go** | **~4h** |
