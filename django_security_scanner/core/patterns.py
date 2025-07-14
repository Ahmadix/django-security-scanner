
"""Security patterns and rules for vulnerability detection."""

from typing import Dict, Tuple, Callable, Any

# Risk weights for scoring
RISK_WEIGHTS: Dict[str, float] = {
    "critique": 1.0,
    "élevé": 0.5,
    "moyen": 0.25
}

# Security patterns to detect
SECURITY_PATTERNS: Dict[str, Tuple[str, str, str]] = {
    # 🛑 Code execution vulnerabilities
    "eval": ("eval", "critique", "Évite l'exécution de code arbitraire (RCE)."),
    "exec": ("exec", "critique", "Permet l'exécution dynamique de code, très dangereux."),
    "compile": ("compile(", "critique", "Permet de compiler et d'exécuter du code arbitraire."),
    "dynamic_import": ("__import__", "critique", "Import dynamique, peut charger des modules non sûrs."),
    
    # ⚠️ System commands / shell
    "os_system": ("os.system", "élevé", "Exécution de commandes système, risque d'injection."),
    "subprocess": ("subprocess", "élevé", "Exécution de sous-processus, attention aux injections."),
    "popen": ("popen(", "élevé", "Ouvre un sous-processus, dangereux si mal contrôlé."),
    "shlex_split": ("shlex.split", "élevé", "Peut être détourné pour manipuler des commandes système."),
    
    # ⚠️ Unsafe deserialization
    "pickle_load": ("pickle.load", "critique", "Désérialisation dangereuse, risque d'exécution de code."),
    "pickle_loads": ("pickle.loads", "critique", "Désérialisation dangereuse, risque d'exécution de code."),
    "marshal_loads": ("marshal.loads", "critique", "Désérialisation non sécurisée, risque RCE."),
    "yaml_unsafe": ("yaml.load", "critique", "Utilisation non sécurisée de yaml.load, favorisez safe_load."),
    "literal_eval": ("ast.literal_eval", "moyen", "Désérialisation plus sûre, mais à vérifier selon contexte."),
    "json_loads": ("json.loads(", "moyen", "Chargement JSON, attention si données non vérifiées."),
    
    # ⚠️ Input/File operations
    "input": ("input(", "moyen", "Lecture d'input utilisateur, peut causer des problèmes."),
    "open_file": ("open(", "moyen", "Ouverture de fichiers, attention aux chemins non sécurisés."),
    "globals": ("globals(", "moyen", "Accès/modification de l'espace global, dangereux."),
    "locals": ("locals(", "moyen", "Manipulation de variables locales, risqué."),
    
    # ⚠️ SQL injection
    "raw_sql": (".raw(", "élevé", "Requêtes SQL brutes, risque d'injection SQL."),
    "cursor_execute": ("cursor.execute(", "élevé", "Exécution SQL directe, attention aux injections."),
    
    # ⚠️ XSS / Template / CSRF
    "render_to_string": ("render_to_string", "moyen", "Peut entraîner des vulnérabilités XSS si mal utilisé."),
    "mark_safe": ("mark_safe", "élevé", "Désactive l'échappement HTML, fort risque XSS."),
    "unsafe_format": ("format(", "moyen", "Formatage de chaînes, attention aux injections."),
    "csrf_exempt": ("@csrf_exempt", "élevé", "Désactive la protection CSRF, à éviter."),
    
    # ⚠️ Authentication & Sessions
    "login_call": ("login(", "moyen", "Vérifier la gestion correcte des sessions."),
    "authenticate": ("authenticate(", "moyen", "Vérifier l'authentification sécurisée."),
    "session_access": ("session[", "moyen", "Accès direct aux sessions, attention aux manipulations."),
    
    # ⚠️ Permissions (DRF)
    "permission_classes_empty": ("permission_classes = []", "élevé", "Aucune permission définie, dangereux en API."),
    "allow_any": ("permissions.AllowAny", "élevé", "API accessible sans restriction, critique en prod."),
    
    # ⚠️ SSRF
    "requests_get": ("requests.get(", "moyen", "Risque SSRF si URL non contrôlée."),
    "requests_post": ("requests.post(", "moyen", "Risque SSRF si URL non contrôlée."),
    "http_connection": ("http.client.HTTPConnection(", "moyen", "Risque SSRF si hôte non validé."),
    
    # ⚠️ Open Redirect
    "http_response_redirect": ("HttpResponseRedirect(", "moyen", "Risque de redirection non sécurisée."),
    "redirect": ("redirect(", "moyen", "Risque de redirection non sécurisée."),
    
    # ⚠️ Information disclosure
    "logging_debug": ("logging.debug(", "moyen", "Risque de fuite d'informations sensibles."),
    "traceback_exc": ("traceback.print_exc(", "moyen", "Affiche des traces d'erreurs, fuite possible en prod."),
    
    # ⚠️ Environment variables
    "os_getenv": ("os.getenv(", "moyen", "Utilisation de variables d'environnement, vérifier l'usage."),
    "os_environ": ("os.environ[", "moyen", "Lecture directe des variables d'environnement."),
    
    # ⚠️ Hardcoded credentials
    "hardcoded_token": ("token=", "critique", "Ne jamais stocker de tokens en dur dans le code."),
    "hardcoded_api_key": ("api_key=", "critique", "Ne jamais stocker d'API key en dur dans le code."),
    "password_in_code": ("password=", "critique", "Mot de passe en dur dans le code, proscrit."),
    "aws_secret_access_key": ("AWS_SECRET_ACCESS_KEY", "critique", "Clé AWS détectée en clair dans le code."),
    "db_password": ("DB_PASSWORD", "critique", "Mot de passe de base de données détecté dans le code."),
    
    # ⚠️ Weak cryptography
    "md5": ("md5(", "élevé", "Ne jamais utiliser md5, trop faible."),
    "sha1": ("sha1(", "élevé", "Ne jamais utiliser sha1, trop faible."),
    
    # ⚠️ Django specific
    "settings_secret_key": ("SECRET_KEY", "critique", "Fuite de la clé secrète, compromet la sécurité globale."),
    "get_object_or_404": ("get_object_or_404(", "élevé", "Peut révéler des objets non-autorisés."),
    "admin_allow_tags": ("allow_tags", "élevé", "Deprecated, risque XSS dans l'admin Django."),
    "file_response": ("FileResponse(", "élevé", "Peut servir des fichiers dangereux aux utilisateurs."),
    
    # ⚠️ URL patterns
    "path_catchall": ("path('',", "moyen", "Route catch-all détectée, risque d'exposition accidentelle."),
    "re_path_catchall": ("re_path(r'^.*',", "élevé", "Route catch-all Regex, risque critique d'exposition."),
    "admin_url": ("include('django.contrib.admin')", "moyen", "Interface admin exposée, à désactiver en production."),
    "api_unprotected": ("@api_view(", "élevé", "Vue API, vérifiez la présence de permissions adaptées."),
}

# Security decorators that provide protection
SECURITY_DECORATORS = (
    "@login_required",
    "@permission_required", 
    "@staff_member_required",
    "@user_passes_test",
    "@csrf_protect",
    "@authentication_classes",
)

# Expected Django settings for security
SETTINGS_CHECKS = [
    ("DEBUG", False, "critique", "Désactivez DEBUG en production."),
    ("SECURE_SSL_REDIRECT", True, "élevé", "Activez SECURE_SSL_REDIRECT."),
    ("SESSION_COOKIE_SECURE", True, "élevé", "Activez SESSION_COOKIE_SECURE."),
    ("CSRF_COOKIE_SECURE", True, "élevé", "Activez CSRF_COOKIE_SECURE."),
    ("ALLOWED_HOSTS", lambda v: bool(v and "*" not in v), "élevé", "Configurez correctement ALLOWED_HOSTS (évitez '*')."),
    ("SECURE_HSTS_SECONDS", lambda v: isinstance(v, int) and v >= 31536000, "élevé", "Activez SECURE_HSTS_SECONDS avec une valeur >= 31536000 (1 an)."),
    ("SECURE_HSTS_INCLUDE_SUBDOMAINS", True, "moyen", "Activez SECURE_HSTS_INCLUDE_SUBDOMAINS."),
    ("SECURE_CONTENT_TYPE_NOSNIFF", True, "élevé", "Activez SECURE_CONTENT_TYPE_NOSNIFF."),
    ("SECURE_BROWSER_XSS_FILTER", True, "moyen", "Activez SECURE_BROWSER_XSS_FILTER."),
    ("X_FRAME_OPTIONS", lambda v: v in ("DENY", "SAMEORIGIN"), "élevé", "Définissez X_FRAME_OPTIONS à 'DENY' ou 'SAMEORIGIN'."),
    ("SESSION_COOKIE_HTTPONLY", True, "moyen", "Activez SESSION_COOKIE_HTTPONLY."),
    ("CSRF_COOKIE_HTTPONLY", True, "moyen", "Activez CSRF_COOKIE_HTTPONLY."),
    ("SECRET_KEY", lambda v: bool(v and len(str(v)) >= 50), "critique", "La SECRET_KEY doit être définie et suffisamment longue (>50 caractères)."),
]
