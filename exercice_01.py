import re
import argparse
from pathlib import Path
from typing import List, Optional

PATTERNS: List[str] = [
    r"(?i)(password|passwd|pwd|secret|token|api_key|key)\s*=\s*[\"'].*?[\"']",  # password = "1234"
    r"(?i)(password|passwd|pwd|secret|token|api_key|key)\s*:\s*[\"'].*?[\"']",  # "password": "1234"
    r"[\"'][A-Za-z0-9+/]{32,}[\"']",  # Clés API ou tokens longs
    r"[\"'][A-Za-z0-9+/=]{32,}[\"']"  # Chaînes encodées en base64
]

STRICT_PATTERNS = [
    r"(?i)\b(password|passwd|pwd|secret|token|api_key|key)\b\s*=",  # Détection de noms de variables
    r"(?i)(auth|login|credentials)\s*=\s*[\"'][^\"']{3,}[\"']"      # Autres mots-clés sensibles
]

ALLOWED_EXTENSIONS: List[str] = ['.py']

def detect_hardcoded_secrets(file_path: Path, strict: bool = False) -> None:
    """Analyse un fichier Python et affiche les lignes suspectes."""
    patterns = PATTERNS + (STRICT_PATTERNS if strict else [])
    with file_path.open('r', encoding='utf-8') as file:
        for line_number, line in enumerate(file, start=1):
            for pattern in patterns:
                if re.search(pattern, line):
                    print("-" * 50 + "\n") # Ligne de séparation
                    print(f"Fichier: {file_path}, Ligne {line_number}: {line.strip()}\n")
                    if strict:
                        print(f"Le mot-clé suspect a été trouvé dans le fichier {file_path} à la ligne {line_number}.")
                        print(f"{line.strip()}\n")
                        return

def scan_directory(directory: str, strict: bool = False, exclude: Optional[str] = None) -> None:
    """Parcours un répertoire et analyse tous les fichiers Python."""
    path = Path(directory)
    exclude_path = Path(exclude) if exclude else None

    if not path.is_dir():
        print(f"Le répertoire {directory} n'existe pas.")
        return

    if strict:
        print(f"Le mode strict est activé: \n")

    for file_path in path.rglob('*'):
        if exclude_path and exclude_path in file_path.parents:
            continue
        if file_path.suffix in ALLOWED_EXTENSIONS:
            detect_hardcoded_secrets(file_path, strict)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Détecteur de mots de passe en dur dans le code source.")
    parser.add_argument("directory", type=str, help="Dossier contenant les fichiers Python à analyser.")
    parser.add_argument("--strict", action="store_true", help="Activer le mode strict.")
    parser.add_argument("--exclude", type=str, help="Dossier ou fichier à exclure de l'analyse.")
    args = parser.parse_args()

    scan_directory(args.directory, args.strict, args.exclude)