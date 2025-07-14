
#!/usr/bin/env python3
"""
Script pour créer un package zip de django-security-scanner prêt pour publication.
"""

import os
import shutil
import zipfile
from pathlib import Path


def create_package_zip():
    """Crée un fichier zip contenant le package complet."""
    
    # Répertoire racine du projet
    project_root = Path(__file__).parent.parent
    
    # Nom du package zip
    zip_name = "django-security-scanner-v1.0.0.zip"
    zip_path = project_root / zip_name
    
    # Fichiers et dossiers à inclure
    include_files = [
        "django_security_scanner/",
        "tests/",
        "examples/",
        "scripts/",
        ".github/",
        "setup.py",
        "pyproject.toml",
        "README.md",
        "LICENSE",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "MANIFEST.in",
        ".gitignore"
    ]
    
    # Créer le fichier zip
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for item in include_files:
            item_path = project_root / item
            
            if item_path.is_file():
                # Ajouter un fichier
                zipf.write(item_path, item)
                print(f"✓ Ajouté: {item}")
            elif item_path.is_dir():
                # Ajouter un dossier récursivement
                for root, dirs, files in os.walk(item_path):
                    # Exclure __pycache__ et .pyc
                    dirs[:] = [d for d in dirs if d != '__pycache__']
                    
                    for file in files:
                        if not file.endswith('.pyc'):
                            file_path = Path(root) / file
                            archive_path = file_path.relative_to(project_root)
                            zipf.write(file_path, archive_path)
                            print(f"✓ Ajouté: {archive_path}")
    
    print(f"\n🎉 Package créé avec succès: {zip_name}")
    print(f"📦 Taille: {zip_path.stat().st_size / 1024:.1f} KB")
    print(f"📍 Emplacement: {zip_path}")
    
    return zip_path


if __name__ == "__main__":
    create_package_zip()
