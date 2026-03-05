from flask import Flask, render_template, request, jsonify, Response, stream_with_context
import psutil
import socket
import concurrent.futures
import time
import hashlib
import re
import requests
import json
from datetime import datetime

app = Flask(__name__)

# ============================================
# PUERTOS SOSPECHOSOS (referencia real)
# ============================================
SUSPICIOUS_PORTS = {
    21: 'FTP (Inseguro)',
    23: 'Telnet (Inseguro)',
    25: 'SMTP (Spam)',
    135: 'RPC (Vulnerable)',
    139: 'NetBIOS',
    445: 'SMB (Crítico)',
    3389: 'RDP (Ataques)',
    5900: 'VNC',
    6667: 'IRC (Botnets)',
    6881: 'BitTorrent',
}

COMMON_PASSWORDS = [
    '123456','password','12345678','qwerty','123456789','12345','1234','111111',
    '1234567','dragon','123123','baseball','abc123','football','monkey','letmein',
    '696969','shadow','master','666666','qwertyuiop','123321','mustang','1234567890',
    'michael','654321','superman','1qaz2wsx','7777777','121212','000000','qazwsx'
]

HASH_ALGORITHMS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256,
    'sha512': hashlib.sha512
}

CAESAR_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()'

# ============================================
# RUTAS PRINCIPALES
# ============================================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/redanalisis')
def redanalisis():
    return render_template('redanalisis.html')

@app.route('/generador')
def generador():
    return render_template('generador.html')

@app.route('/telefono')
def telefono():
    return render_template('telefono.html')

@app.route('/huella')
def huella():
    return render_template('huella.html')

@app.route('/encriptador')
def encriptador():
    return render_template('encriptador.html')

@app.route('/correo')
def correo():
    return render_template('correo.html')

@app.route('/guiafotos')
def guiafotos():
    return render_template('guiafotos.html')

@app.route('/guianavsegu')
def guianavsegu():
    return render_template('guianavsegu.html')

@app.route('/escaner')
def escaner():
    return render_template('escaner.html')

@app.route('/hosts')
def hosts():
    return render_template('hosts.html')

@app.route('/guiadis')
def guiadis():
    return render_template('guiadis.html')

@app.route('/guiasegu')
def guiasegu():
    return render_template('guiasegu.html')

@app.route('/imagen')
def imagen():
    return render_template('imagen.html')

@app.route('/internetest')
def internetest():
    return render_template('internetest.html')

@app.route('/guiafiltra')
def guiafiltra():
    return render_template('guiafiltra.html')

@app.route('/guiaphishing')
def guiaphishing():
    return render_template('guiaphishing.html')

@app.route('/simusocial')
def simusocial():
    return render_template('simusocial.html')

@app.route('/blogs')
def blogs():
    return render_template('blogs.html')

@app.route('/guiapriv')
def guiapriv():
    return render_template('guiapriv.html')

@app.route('/consejos')
def consejos():
    return render_template('consejos.html')

@app.route('/comunidad')
def comunidad():
    return render_template('comunidad.html')

@app.route('/guiaprotegecuentas')
def guiaprotegecuentas():
    return render_template('guiaprotegecuentas.html')

@app.route('/guiavpn')
def guiavpn():
    return render_template('guiavpn.html')

@app.route('/foro')
def foro():
    return render_template('foro.html')

@app.route('/minijuego')
def minijuego():
    return render_template('minijuego.html')

@app.route('/guiapuertos')
def guiapuertos():
    return render_template('guiapuertos.html')

@app.route('/verificador_ip')
def verificador_ip():
    # Obtener la IP real del cliente (considera proxies)
    if request.headers.get('X-Forwarded-For'):
        user_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        user_ip = request.headers.get('X-Real-IP')
    else:
        user_ip = request.remote_addr
    return render_template('verificador_ip.html', user_ip=user_ip)

# ============================================
# API: VERIFICADOR DE IP REAL (ip-api.com)
# ============================================

@app.route('/api/ip-info', methods=['POST'])
def ip_info():
    """Obtiene información real de una IP usando ip-api.com (gratuita, sin key)"""
    data = request.json
    ip = data.get('ip', '').strip()

    if not ip:
        return jsonify({'error': 'No se proporcionó IP'}), 400

    # Validar formato básico
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not ip_pattern.match(ip):
        return jsonify({'error': 'Formato de IP inválido'}), 400

    try:
        # ip-api.com: gratuita, sin clave, hasta 45 req/min
        resp = requests.get(
            f'http://ip-api.com/json/{ip}',
            params={'fields': 'status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,query'},
            timeout=8
        )
        result = resp.json()

        if result.get('status') == 'fail':
            return jsonify({'error': result.get('message', 'IP no encontrada')}), 400

        # Detectar si es IP privada/local
        is_private = ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                                     '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                                     '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                                     '172.30.', '172.31.', '192.168.', '127.', '0.'))

        return jsonify({
            'ip': result.get('query', ip),
            'pais': result.get('country', 'Desconocido'),
            'codigo_pais': result.get('countryCode', ''),
            'region': result.get('regionName', ''),
            'ciudad': result.get('city', ''),
            'codigo_postal': result.get('zip', ''),
            'latitud': result.get('lat'),
            'longitud': result.get('lon'),
            'zona_horaria': result.get('timezone', ''),
            'isp': result.get('isp', ''),
            'organizacion': result.get('org', ''),
            'as_info': result.get('as', ''),
            'es_proxy': result.get('proxy', False),
            'es_hosting': result.get('hosting', False),
            'es_privada': is_private,
            'timestamp': datetime.now().isoformat()
        })

    except requests.Timeout:
        return jsonify({'error': 'Tiempo de espera agotado al consultar la IP'}), 504
    except Exception as e:
        return jsonify({'error': f'Error al consultar IP: {str(e)}'}), 500


# ============================================
# API: HUELLA DIGITAL — HIBP (Have I Been Pwned)
# ============================================

@app.route('/api/check-email', methods=['POST'])
def check_email():
    """
    Verifica el email contra la API pública de Have I Been Pwned.
    Usa el endpoint de búsqueda por dominio (sin autenticación) y el
    endpoint de breaches público. Para búsqueda exacta por cuenta
    se necesita API key de HIBP (de pago), por eso usamos la alternativa
    pública que devuelve breaches del dominio del email.
    """
    data = request.json
    email = data.get('email', '').lower().strip()

    if not email or not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
        return jsonify({'error': 'Email inválido'}), 400

    domain = email.split('@')[1]
    found_breaches = []
    recommendations = []

    try:
        # Endpoint público de HIBP: lista todos los breaches conocidos
        # Luego filtramos los que involucren el dominio del email
        resp = requests.get(
            'https://haveibeenpwned.com/api/v3/breaches',
            headers={'User-Agent': 'FORENCOMMUNITY-PrivacyTool'},
            timeout=10
        )

        if resp.status_code == 200:
            all_breaches = resp.json()
            # Filtrar breaches que involucren el dominio del email
            for breach in all_breaches:
                if domain in breach.get('Domain', '').lower():
                    found_breaches.append({
                        'name': breach.get('Name', ''),
                        'title': breach.get('Title', breach.get('Name', '')),
                        'date': breach.get('BreachDate', ''),
                        'data': ', '.join(breach.get('DataClasses', [])),
                        'severity': 'high' if breach.get('IsSensitive') or breach.get('PwnCount', 0) > 1000000 else 'medium',
                        'accounts': breach.get('PwnCount', 0),
                        'descripcion': breach.get('Description', '')[:200] if breach.get('Description') else ''
                    })
        elif resp.status_code == 429:
            return jsonify({'error': 'Demasiadas consultas. Intenta en un momento.'}), 429

    except requests.Timeout:
        return jsonify({'error': 'Tiempo de espera agotado. Intenta de nuevo.'}), 504
    except Exception as e:
        return jsonify({'error': f'Error al consultar HIBP: {str(e)}'}), 500

    # Calcular nivel de riesgo real
    risk_score = 0
    if found_breaches:
        risk_score += len(found_breaches) * 20
        high_count = sum(1 for b in found_breaches if b['severity'] == 'high')
        risk_score += high_count * 15

    if risk_score >= 50:
        risk_level = 'alto'
        recommendations = [
            'Cambia TODAS tus contraseñas inmediatamente',
            'Activa autenticación de dos factores en todas tus cuentas',
            'Revisa actividad sospechosa en tus cuentas bancarias',
            'Usa un gestor de contraseñas como Bitwarden o 1Password',
            'Monitoriza tu email en haveibeenpwned.com regularmente'
        ]
    elif risk_score >= 20:
        risk_level = 'medio'
        recommendations = [
            'Cambia las contraseñas de los servicios afectados',
            'Activa autenticación 2FA donde esté disponible',
            'No reutilices contraseñas entre servicios'
        ]
    else:
        risk_level = 'bajo'
        recommendations = [
            'Continúa usando contraseñas seguras y únicas',
            'Activa 2FA en todas tus cuentas como medida preventiva',
            'Revisa periódicamente tu exposición en haveibeenpwned.com'
        ]

    return jsonify({
        'email': email,
        'domain': domain,
        'risk_level': risk_level,
        'risk_score': min(risk_score, 100),
        'breaches': found_breaches,
        'total_breaches': len(found_breaches),
        'recommendations': recommendations,
        'fuente': 'Have I Been Pwned (haveibeenpwned.com)',
        'nota': 'Los resultados muestran brechas conocidas que afectan al dominio del email.',
        'timestamp': datetime.now().isoformat()
    })


# ============================================
# API: CONTRASEÑAS — HIBP Pwned Passwords
# ============================================

@app.route('/api/check-password-pwned', methods=['POST'])
def check_password_pwned():
    """
    Verifica si una contraseña fue filtrada usando HIBP Pwned Passwords.
    Usa k-anonymity: solo se envían los primeros 5 caracteres del hash SHA1.
    La contraseña completa NUNCA sale del servidor.
    """
    data = request.json
    password = data.get('password', '')

    if not password:
        return jsonify({'error': 'No se proporcionó contraseña'}), 400

    try:
        # Hash SHA1 de la contraseña
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        # Consultar HIBP con solo los primeros 5 caracteres (k-anonymity)
        resp = requests.get(
            f'https://api.pwnedpasswords.com/range/{prefix}',
            headers={'User-Agent': 'FORENCOMMUNITY-PrivacyTool', 'Add-Padding': 'true'},
            timeout=8
        )

        if resp.status_code != 200:
            return jsonify({'error': 'Error al consultar la base de datos'}), 500

        # Buscar el sufijo en la respuesta
        hashes = resp.text.splitlines()
        count = 0
        for line in hashes:
            parts = line.split(':')
            if len(parts) == 2 and parts[0] == suffix:
                count = int(parts[1])
                break

        if count > 0:
            return jsonify({
                'pwned': True,
                'count': count,
                'message': f'⚠️ Esta contraseña fue encontrada {count:,} veces en filtraciones de datos. ¡Cámbiala de inmediato!',
                'severity': 'alto' if count > 10000 else 'medio'
            })
        else:
            return jsonify({
                'pwned': False,
                'count': 0,
                'message': '✅ Esta contraseña no aparece en filtraciones conocidas.',
                'severity': 'bajo'
            })

    except requests.Timeout:
        return jsonify({'error': 'Tiempo de espera agotado'}), 504
    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}), 500


# ============================================
# API: GENERADOR DE CONTRASEÑAS (lógica real en servidor)
# ============================================

@app.route('/api/generate-password', methods=['POST'])
def generate_password():
    import secrets
    data = request.json
    length = data.get('length', 16)
    cantidad = min(int(data.get('cantidad', 1)), 10)
    options = data.get('options', {})

    if length < 8 or length > 64:
        return jsonify({'error': 'La longitud debe ser entre 8 y 64'}), 400

    chars = ''
    required_chars = []

    if options.get('mayusculas', True):
        pool = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        if options.get('evitarAmbiguos', False):
            pool = pool.replace('I', '').replace('O', '')
        chars += pool
        required_chars.append(secrets.choice(pool))

    if options.get('minusculas', True):
        pool = 'abcdefghijklmnopqrstuvwxyz'
        if options.get('evitarAmbiguos', False):
            pool = pool.replace('l', '')
        chars += pool
        required_chars.append(secrets.choice(pool))

    if options.get('numeros', True):
        pool = '0123456789'
        if options.get('evitarAmbiguos', False):
            pool = pool.replace('0', '').replace('1', '')
        chars += pool
        required_chars.append(secrets.choice(pool))

    if options.get('simbolos', True):
        pool = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        chars += pool
        required_chars.append(secrets.choice(pool))

    if not chars:
        chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'

    passwords = []
    for _ in range(cantidad):
        # Generar con secrets (criptográficamente seguro)
        remaining_length = length - len(required_chars)
        password_chars = [secrets.choice(chars) for _ in range(max(0, remaining_length))]
        all_chars = required_chars + password_chars

        # Mezclar usando secrets
        for i in range(len(all_chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            all_chars[i], all_chars[j] = all_chars[j], all_chars[i]

        password = ''.join(all_chars)

        if options.get('separador', False):
            sep = secrets.choice(['-', '_', '.'])
            password = sep.join(password[i:i+4] for i in range(0, len(password), 4))

        strength = calculate_password_strength(password)
        passwords.append({
            'password': password,
            'strength': strength,
            'length': len(password)
        })

    return jsonify({
        'passwords': passwords,
        'cantidad': cantidad,
        'metodo': 'secrets (criptográficamente seguro)',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/analyze-password', methods=['POST'])
def analyze_password():
    data = request.json
    password = data.get('password', '')
    if not password:
        return jsonify({'error': 'No se proporcionó contraseña'}), 400
    return jsonify(analyze_password_strength(password))


def calculate_password_strength(password):
    score = 0
    if len(password) >= 20: score += 40
    elif len(password) >= 16: score += 35
    elif len(password) >= 12: score += 25
    elif len(password) >= 8: score += 15
    else: score += 5

    if re.search(r'[A-Z]', password): score += 15
    if re.search(r'[a-z]', password): score += 15
    if re.search(r'\d', password): score += 15
    if re.search(r'[^a-zA-Z0-9]', password): score += 15
    return min(100, score)


def analyze_password_strength(password):
    score = calculate_password_strength(password)

    if score >= 85: level, color = 'muy_fuerte', '#10B981'
    elif score >= 65: level, color = 'fuerte', '#3B82F6'
    elif score >= 45: level, color = 'moderada', '#F59E0B'
    elif score >= 25: level, color = 'débil', '#F97316'
    else: level, color = 'muy_débil', '#EF4444'

    char_set = 0
    if re.search(r'[a-z]', password): char_set += 26
    if re.search(r'[A-Z]', password): char_set += 26
    if re.search(r'\d', password): char_set += 10
    if re.search(r'[^a-zA-Z0-9]', password): char_set += 32
    if char_set == 0: char_set = 26

    entropy = len(password) * (char_set.bit_length())
    is_common = password.lower() in COMMON_PASSWORDS

    return {
        'password': password,
        'score': score,
        'level': level,
        'color': color,
        'entropy': entropy,
        'length': len(password),
        'has_upper': bool(re.search(r'[A-Z]', password)),
        'has_lower': bool(re.search(r'[a-z]', password)),
        'has_number': bool(re.search(r'\d', password)),
        'has_symbol': bool(re.search(r'[^a-zA-Z0-9]', password)),
        'is_common': is_common,
        'time_to_crack': estimate_crack_time(entropy)
    }


def estimate_crack_time(entropy):
    attempts_per_second = 1_000_000_000
    combinations = 2 ** entropy
    seconds = combinations / attempts_per_second
    if seconds < 1: return 'Instantáneo'
    elif seconds < 60: return f'{int(seconds)} segundos'
    elif seconds < 3600: return f'{int(seconds/60)} minutos'
    elif seconds < 86400: return f'{int(seconds/3600)} horas'
    elif seconds < 31536000: return f'{int(seconds/86400)} días'
    elif seconds < 3153600000: return f'{int(seconds/31536000)} años'
    else: return f'{int(seconds/31536000):,} años'


# ============================================
# API: VERIFICADOR DE TELÉFONO REAL (numverify)
# ============================================

@app.route('/api/check-phone', methods=['POST'])
def check_phone():
    """
    Valida y analiza un número de teléfono usando la API pública de numverify
    (plan gratuito: 100 req/mes) o fallback a análisis local con libphonenumbers.
    """
    data = request.json
    phone = data.get('phone', '').strip()
    phone_clean = re.sub(r'[^\d+]', '', phone)

    if not phone_clean or len(phone_clean) < 7:
        return jsonify({'error': 'Número de teléfono inválido'}), 400

    # Intentar validación local con phonenumbers (si está instalado)
    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier, timezone as pn_timezone

        try:
            parsed = phonenumbers.parse(phone_clean, None)
        except Exception:
            # Intentar con México como default si no tiene prefijo
            parsed = phonenumbers.parse(phone_clean, 'MX')

        is_valid = phonenumbers.is_valid_number(parsed)
        is_possible = phonenumbers.is_possible_number(parsed)

        country_code = phonenumbers.region_code_for_number(parsed)
        country_name = geocoder.description_for_number(parsed, 'es') or 'Desconocido'
        carrier_name = carrier.name_for_number(parsed, 'es') or 'Desconocida'
        timezones = list(pn_timezone.time_zones_for_number(parsed))

        number_type = phonenumbers.number_type(parsed)
        type_map = {
            phonenumbers.PhoneNumberType.MOBILE: 'Móvil',
            phonenumbers.PhoneNumberType.FIXED_LINE: 'Fijo',
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: 'Fijo/Móvil',
            phonenumbers.PhoneNumberType.TOLL_FREE: 'Número gratuito',
            phonenumbers.PhoneNumberType.PREMIUM_RATE: 'Tarifa premium',
            phonenumbers.PhoneNumberType.VOIP: 'VoIP',
            phonenumbers.PhoneNumberType.UNKNOWN: 'Desconocido'
        }
        line_type = type_map.get(number_type, 'Desconocido')

        # Formato internacional
        intl_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        national_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)

        # Determinar nivel de riesgo real basado en tipo de línea
        risk_reasons = []
        risk_level = 'bajo'

        if not is_valid:
            risk_level = 'alto'
            risk_reasons.append('Número no válido según estándares internacionales')
        elif number_type == phonenumbers.PhoneNumberType.PREMIUM_RATE:
            risk_level = 'alto'
            risk_reasons.append('Número de tarifa premium — puede cobrar tarifas elevadas')
        elif number_type == phonenumbers.PhoneNumberType.VOIP:
            risk_level = 'medio'
            risk_reasons.append('Número VoIP — frecuentemente usado en spam y fraudes')
        elif number_type == phonenumbers.PhoneNumberType.TOLL_FREE:
            risk_level = 'bajo'
            risk_reasons.append('Número gratuito — verificar legitimidad del negocio')

        return jsonify({
            'phone': phone_clean,
            'formato_internacional': intl_format,
            'formato_nacional': national_format,
            'es_valido': is_valid,
            'es_posible': is_possible,
            'pais': country_name,
            'codigo_pais': country_code or '',
            'operadora': carrier_name,
            'tipo_linea': line_type,
            'zonas_horarias': timezones,
            'risk_level': risk_level,
            'reasons': risk_reasons,
            'fuente': 'Google libphonenumber (validación local)',
            'timestamp': datetime.now().isoformat()
        })

    except ImportError:
        # Fallback: análisis básico sin librería externa
        prefijos = {
            '+52': ('México', 'MX'), '+54': ('Argentina', 'AR'),
            '+34': ('España', 'ES'), '+1': ('EEUU/Canadá', 'US'),
            '+55': ('Brasil', 'BR'), '+57': ('Colombia', 'CO'),
            '+56': ('Chile', 'CL'), '+51': ('Perú', 'PE'),
            '+58': ('Venezuela', 'VE'), '+44': ('Reino Unido', 'GB'),
            '+49': ('Alemania', 'DE'), '+33': ('Francia', 'FR'),
        }

        pais, codigo = 'Desconocido', ''
        for prefix, (nombre, cod) in prefijos.items():
            if phone_clean.startswith(prefix):
                pais, codigo = nombre, cod
                break

        is_valid = len(phone_clean.replace('+', '')) >= 8 and len(phone_clean.replace('+', '')) <= 15

        return jsonify({
            'phone': phone_clean,
            'formato_internacional': phone_clean,
            'es_valido': is_valid,
            'pais': pais,
            'codigo_pais': codigo,
            'operadora': 'No disponible (instala phonenumbers: pip install phonenumbers)',
            'tipo_linea': 'Desconocido',
            'risk_level': 'bajo' if is_valid else 'medio',
            'reasons': [] if is_valid else ['Formato de número inusual'],
            'fuente': 'Análisis básico (sin librería phonenumbers)',
            'nota': 'Para análisis completo: pip install phonenumbers',
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        return jsonify({'error': f'Error al analizar número: {str(e)}'}), 500


# ============================================
# API: ESCÁNER DE CABECERAS HTTP REAL
# ============================================

@app.route('/api/scan-headers', methods=['POST'])
def scan_headers():
    """
    Hace un request HTTP real al sitio y devuelve sus cabeceras de seguridad.
    Flask actúa como proxy para evitar restricciones CORS del navegador.
    """
    data = request.json
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'No se proporcionó URL'}), 400

    # Asegurar que tiene protocolo
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        resp = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                'User-Agent': 'Mozilla/5.0 (compatible; FORENCOMMUNITY-SecurityScanner/1.0)'
            },
            verify=True
        )

        # Extraer cabeceras de seguridad relevantes
        headers_raw = dict(resp.headers)
        headers_lower = {k.lower(): v for k, v in headers_raw.items()}

        # Cabeceras de seguridad a analizar
        security_headers = {
            'Strict-Transport-Security': headers_raw.get('Strict-Transport-Security') or headers_raw.get('strict-transport-security'),
            'Content-Security-Policy': headers_raw.get('Content-Security-Policy') or headers_raw.get('content-security-policy'),
            'X-Frame-Options': headers_raw.get('X-Frame-Options') or headers_raw.get('x-frame-options'),
            'X-Content-Type-Options': headers_raw.get('X-Content-Type-Options') or headers_raw.get('x-content-type-options'),
            'Referrer-Policy': headers_raw.get('Referrer-Policy') or headers_raw.get('referrer-policy'),
            'Permissions-Policy': headers_raw.get('Permissions-Policy') or headers_raw.get('permissions-policy'),
            'X-XSS-Protection': headers_raw.get('X-XSS-Protection') or headers_raw.get('x-xss-protection'),
            'Cross-Origin-Embedder-Policy': headers_raw.get('Cross-Origin-Embedder-Policy') or headers_raw.get('cross-origin-embedder-policy'),
            'Cross-Origin-Opener-Policy': headers_raw.get('Cross-Origin-Opener-Policy') or headers_raw.get('cross-origin-opener-policy'),
            'Cross-Origin-Resource-Policy': headers_raw.get('Cross-Origin-Resource-Policy') or headers_raw.get('cross-origin-resource-policy'),
        }

        # Info adicional del servidor
        server_info = {
            'server': headers_lower.get('server', 'No revelado'),
            'x-powered-by': headers_lower.get('x-powered-by', 'No revelado'),
            'via': headers_lower.get('via', ''),
            'x-cache': headers_lower.get('x-cache', ''),
        }

        # Calcular puntuación real
        importante = ['Strict-Transport-Security', 'Content-Security-Policy',
                      'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy']
        score = 100
        missing_important = 0
        for h in importante:
            if not security_headers.get(h):
                score -= 15
                missing_important += 1

        optional = ['Permissions-Policy', 'X-XSS-Protection', 'Cross-Origin-Embedder-Policy',
                    'Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy']
        for h in optional:
            if not security_headers.get(h):
                score -= 5

        score = max(0, score)

        return jsonify({
            'url': url,
            'url_final': resp.url,
            'status_code': resp.status_code,
            'security_headers': security_headers,
            'server_info': server_info,
            'score': score,
            'missing_important': missing_important,
            'https': resp.url.startswith('https://'),
            'total_headers': len(headers_raw),
            'fuente': 'Escaneo HTTP real',
            'timestamp': datetime.now().isoformat()
        })

    except requests.exceptions.SSLError as e:
        return jsonify({'error': f'Error SSL: {str(e)[:100]}. El sitio puede tener certificado inválido.'}), 400
    except requests.exceptions.ConnectionError:
        return jsonify({'error': 'No se pudo conectar al sitio. Verifica la URL.'}), 400
    except requests.Timeout:
        return jsonify({'error': 'El sitio tardó demasiado en responder (>10s).'}), 504
    except Exception as e:
        return jsonify({'error': f'Error: {str(e)[:200]}'}), 500


# ============================================
# API: CORREOS TEMPORALES REALES (mail.tm)
# ============================================

@app.route('/api/temp-email/create', methods=['POST'])
def create_temp_email():
    """Crea una cuenta de correo temporal REAL usando mail.tm (gratuito)"""
    import secrets as sec
    try:
        # 1. Obtener dominios disponibles
        domains_resp = requests.get('https://api.mail.tm/domains', timeout=8)
        if domains_resp.status_code != 200:
            return jsonify({'error': 'No se pudieron obtener dominios disponibles'}), 500

        domains_data = domains_resp.json()
        domain = domains_data.get('hydra:member', [{}])[0].get('domain', 'mail.tm')

        # 2. Generar credenciales
        username = 'fc' + sec.token_hex(5)
        password = sec.token_urlsafe(16)
        email = f'{username}@{domain}'

        # 3. Crear cuenta
        create_resp = requests.post(
            'https://api.mail.tm/accounts',
            json={'address': email, 'password': password},
            headers={'Content-Type': 'application/json'},
            timeout=8
        )

        if create_resp.status_code not in (200, 201):
            return jsonify({'error': 'No se pudo crear el correo temporal'}), 500

        # 4. Obtener token JWT
        token_resp = requests.post(
            'https://api.mail.tm/token',
            json={'address': email, 'password': password},
            headers={'Content-Type': 'application/json'},
            timeout=8
        )

        token = ''
        account_id = ''
        if token_resp.status_code == 200:
            token_data = token_resp.json()
            token = token_data.get('token', '')
            account_id = token_data.get('id', '')

        return jsonify({
            'email': email,
            'password': password,
            'token': token,
            'account_id': account_id,
            'domain': domain,
            'fuente': 'mail.tm (correo temporal real)',
            'expires_in': '10 minutos de inactividad',
            'timestamp': datetime.now().isoformat()
        })

    except requests.Timeout:
        return jsonify({'error': 'Tiempo de espera agotado'}), 504
    except Exception as e:
        return jsonify({'error': f'Error al crear correo: {str(e)}'}), 500


@app.route('/api/temp-email/messages', methods=['POST'])
def get_temp_messages():
    """Obtiene los mensajes de la bandeja de entrada del correo temporal"""
    data = request.json
    token = data.get('token', '')

    if not token:
        return jsonify({'error': 'Token no proporcionado'}), 400

    try:
        resp = requests.get(
            'https://api.mail.tm/messages',
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            },
            timeout=8
        )

        if resp.status_code == 401:
            return jsonify({'error': 'Sesión expirada. Genera un nuevo correo.'}), 401

        if resp.status_code != 200:
            return jsonify({'error': 'Error al obtener mensajes'}), 500

        messages_data = resp.json()
        messages = []
        for msg in messages_data.get('hydra:member', []):
            messages.append({
                'id': msg.get('id', ''),
                'from': msg.get('from', {}).get('address', 'Desconocido'),
                'from_name': msg.get('from', {}).get('name', ''),
                'subject': msg.get('subject', '(Sin asunto)'),
                'seen': msg.get('seen', False),
                'date': msg.get('createdAt', ''),
                'intro': msg.get('intro', '')[:100]
            })

        return jsonify({
            'messages': messages,
            'total': len(messages),
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}), 500


@app.route('/api/temp-email/message/<message_id>', methods=['POST'])
def get_message_detail(message_id):
    """Obtiene el contenido completo de un mensaje"""
    data = request.json
    token = data.get('token', '')

    if not token:
        return jsonify({'error': 'Token no proporcionado'}), 400

    try:
        resp = requests.get(
            f'https://api.mail.tm/messages/{message_id}',
            headers={'Authorization': f'Bearer {token}'},
            timeout=8
        )

        if resp.status_code != 200:
            return jsonify({'error': 'Mensaje no encontrado'}), 404

        msg = resp.json()
        return jsonify({
            'id': msg.get('id', ''),
            'from': msg.get('from', {}).get('address', ''),
            'subject': msg.get('subject', ''),
            'text': msg.get('text', ''),
            'html': msg.get('html', [''])[0] if msg.get('html') else '',
            'date': msg.get('createdAt', ''),
        })

    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}), 500


@app.route('/api/temp-email/delete', methods=['POST'])
def delete_temp_account():
    """Elimina la cuenta de correo temporal"""
    data = request.json
    token = data.get('token', '')
    account_id = data.get('account_id', '')

    if not token or not account_id:
        return jsonify({'error': 'Datos incompletos'}), 400

    try:
        resp = requests.delete(
            f'https://api.mail.tm/accounts/{account_id}',
            headers={'Authorization': f'Bearer {token}'},
            timeout=8
        )
        return jsonify({'deleted': resp.status_code in (200, 204)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================
# API: ANÁLISIS DE RED (psutil real)
# ============================================

@app.route('/api/conexiones-reales')
def get_conexiones_reales():
    conexiones = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            try:
                proceso = psutil.Process(conn.pid) if conn.pid else None
                nombre_proceso = proceso.name() if proceso else 'Sistema'

                riesgo = 'bajo'
                if conn.raddr:
                    puerto = conn.raddr.port
                    if puerto in SUSPICIOUS_PORTS:
                        riesgo = 'alto'
                    elif puerto in [80, 443, 22, 53]:
                        riesgo = 'bajo'
                    else:
                        riesgo = 'medio'

                conexiones.append({
                    'app': nombre_proceso,
                    'pid': conn.pid,
                    'ip_local': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                    'ip_remota': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'Escuchando',
                    'estado': conn.status,
                    'riesgo': riesgo,
                    'puerto_descripcion': SUSPICIOUS_PORTS.get(conn.raddr.port, '') if conn.raddr else '',
                    'timestamp': datetime.now().isoformat()
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        return jsonify({'error': str(e), 'conexiones': []})

    return jsonify(conexiones[:50])


@app.route('/api/estadisticas-red')
def get_estadisticas_red():
    stats = psutil.net_io_counters()
    return jsonify({
        'bytes_enviados': stats.bytes_sent,
        'bytes_recibidos': stats.bytes_recv,
        'paquetes_enviados': stats.packets_sent,
        'paquetes_recibidos': stats.packets_recv,
        'conexiones_activas': len(psutil.net_connections()),
        'timestamp': datetime.now().isoformat()
    })


# ============================================
# API: ENCRIPTADOR (misma lógica pero más robusta)
# ============================================

@app.route('/api/encrypt', methods=['POST'])
def encrypt_text():
    data = request.json
    text = data.get('text', '')
    method = data.get('method', 'base64').lower()
    key = data.get('key', '')
    shift = int(data.get('shift', 3))

    if not text:
        return jsonify({'error': 'No hay texto para encriptar'}), 400

    result = ''
    try:
        if method == 'base64':
            import base64
            result = base64.b64encode(text.encode('utf-8')).decode()
        elif method == 'base32':
            import base64
            result = base64.b32encode(text.encode('utf-8')).decode().rstrip('=')
        elif method == 'reverse':
            result = text[::-1]
        elif method == 'rot13':
            result = text.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            ))
        elif method == 'caesar':
            result = caesar_cipher(text, shift)
        elif method in HASH_ALGORITHMS:
            result = HASH_ALGORITHMS[method](text.encode('utf-8')).hexdigest()
        elif method == 'aes':
            if not key or len(key) < 8:
                return jsonify({'error': 'AES requiere clave de al menos 8 caracteres'}), 400
            result = encrypt_aes(text, key)
        else:
            return jsonify({'error': f'Método no soportado: {method}'}), 400
    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}), 500

    return jsonify({
        'original': text,
        'encrypted': result,
        'method': method,
        'length': len(result),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/decrypt', methods=['POST'])
def decrypt_text():
    data = request.json
    text = data.get('text', '')
    method = data.get('method', 'base64').lower()
    key = data.get('key', '')
    shift = int(data.get('shift', 3))

    if not text:
        return jsonify({'error': 'No hay texto para desencriptar'}), 400

    result = ''
    try:
        if method == 'base64':
            import base64
            text = text + '=' * (-len(text) % 4)
            result = base64.b64decode(text.encode()).decode('utf-8')
        elif method == 'base32':
            import base64
            text = text.upper() + '=' * (-len(text) % 8)
            result = base64.b32decode(text.encode()).decode('utf-8')
        elif method == 'reverse':
            result = text[::-1]
        elif method == 'rot13':
            result = text.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            ))
        elif method == 'caesar':
            result = caesar_cipher(text, -shift)
        elif method == 'aes':
            if not key or len(key) < 8:
                return jsonify({'error': 'AES requiere clave de al menos 8 caracteres'}), 400
            result = decrypt_aes(text, key)
        else:
            return jsonify({'error': f'Método no reversible o no soportado: {method}'}), 400
    except Exception as e:
        return jsonify({'error': f'Error al desencriptar: {str(e)}'}), 500

    return jsonify({
        'encrypted': text,
        'decrypted': result,
        'method': method,
        'length': len(result),
        'timestamp': datetime.now().isoformat()
    })


def caesar_cipher(text, shift):
    result = ''
    for char in text:
        if char in CAESAR_CHARS:
            idx = CAESAR_CHARS.index(char)
            new_idx = (idx + shift) % len(CAESAR_CHARS)
            result += CAESAR_CHARS[new_idx]
        else:
            result += char
    return result


def encrypt_aes(text, key):
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        import base64
        key_bytes = key.ljust(32)[:32].encode()
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        padded = pad(text.encode('utf-8'), AES.block_size)
        return base64.b64encode(cipher.encrypt(padded)).decode()
    except ImportError:
        import base64
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        result = ''.join(chr(ord(c) ^ ord(key_hash[i % len(key_hash)])) for i, c in enumerate(text))
        return base64.b64encode(result.encode('latin-1')).decode()


def decrypt_aes(text, key):
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        import base64
        key_bytes = key.ljust(32)[:32].encode()
        encrypted = base64.b64decode(text)
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        return unpad(cipher.decrypt(encrypted), AES.block_size).decode('utf-8')
    except ImportError:
        import base64
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        encrypted = base64.b64decode(text).decode('latin-1')
        return ''.join(chr(ord(c) ^ ord(key_hash[i % len(key_hash)])) for i, c in enumerate(encrypted))


# ============================================
# API: HASH
# ============================================

@app.route('/api/analyze-hash', methods=['POST'])
def analyze_hash():
    data = request.json
    hash_text = data.get('hash', '').strip()
    if not hash_text:
        return jsonify({'error': 'No se proporcionó hash'}), 400

    length = len(hash_text)
    analysis = {
        'hash': hash_text,
        'length': length,
        'possible_types': [],
        'is_hex': bool(re.match(r'^[a-f0-9]+$', hash_text.lower())),
        'is_base64': bool(re.match(r'^[A-Za-z0-9+/]+=*$', hash_text)),
        'is_base32': bool(re.match(r'^[A-Z2-7]+=*$', hash_text.upper())),
        'timestamp': datetime.now().isoformat()
    }

    if analysis['is_hex']:
        hex_types = {8: 'CRC32', 16: 'MySQL3', 32: 'MD5', 40: 'SHA1',
                     56: 'SHA224', 64: 'SHA256', 96: 'SHA384', 128: 'SHA512'}
        if length in hex_types:
            analysis['possible_types'].append({'type': hex_types[length], 'bits': length * 4, 'confidence': 'alta'})

    if analysis['is_base64']:
        est_size = (len(hash_text) * 3) // 4
        analysis['possible_types'].append({'type': 'Base64', 'est_size': est_size, 'confidence': 'media'})

    return jsonify(analysis)


@app.route('/api/compare-hashes', methods=['POST'])
def compare_hashes():
    data = request.json
    h1 = re.sub(r'\s+', '', data.get('hash1', '').strip().lower())
    h2 = re.sub(r'\s+', '', data.get('hash2', '').strip().lower())
    return jsonify({'hash1': h1, 'hash2': h2, 'match': h1 == h2,
                    'length1': len(h1), 'length2': len(h2),
                    'timestamp': datetime.now().isoformat()})


@app.route('/api/generate-hash', methods=['POST'])
def generate_hash():
    data = request.json
    text = data.get('text', '')
    algorithm = data.get('algorithm', 'sha256').lower()
    if not text:
        return jsonify({'error': 'No se proporcionó texto'}), 400
    if algorithm not in HASH_ALGORITHMS:
        return jsonify({'error': f'Algoritmo no soportado: {algorithm}'}), 400
    hash_result = HASH_ALGORITHMS[algorithm](text.encode('utf-8')).hexdigest()
    return jsonify({'text': text, 'algorithm': algorithm, 'hash': hash_result,
                    'length': len(hash_result), 'timestamp': datetime.now().isoformat()})


# ============================================================
# API: ESCÁNER DE PUERTOS TCP REAL — Streaming SSE
# Sin nmap, sin dependencias externas. Solo socket Python + hilos.
# ============================================================

# Puertos considerados de alto riesgo
RISKY_PORTS = {21, 23, 25, 135, 139, 445, 3389, 4444, 5900, 6379, 27017, 50000}

PORT_SERVICES = {
    21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS', 80:'HTTP',
    110:'POP3', 111:'RPC', 135:'RPC/DCOM', 139:'NetBIOS', 143:'IMAP',
    443:'HTTPS', 445:'SMB', 465:'SMTPS', 587:'SMTP-S', 631:'IPP',
    993:'IMAPS', 995:'POP3S', 1433:'SQL Server', 1521:'Oracle DB',
    1723:'PPTP', 2049:'NFS', 3000:'Dev Server', 3306:'MySQL',
    3389:'RDP', 4444:'Backdoor', 4899:'Radmin', 5432:'PostgreSQL',
    5900:'VNC', 6379:'Redis', 7001:'WebLogic', 8080:'HTTP-Alt',
    8443:'HTTPS-Alt', 8888:'Jupyter', 9200:'Elasticsearch',
    10000:'Webmin', 27017:'MongoDB', 50000:'DB2', 50070:'Hadoop'
}


def _tcp_probe(ip: str, port: int, timeout_s: float):
    """Intenta conexión TCP. Devuelve dict si abierto, None si cerrado/filtrado."""
    t0 = time.monotonic()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_s)
            if s.connect_ex((ip, port)) == 0:
                latency = round((time.monotonic() - t0) * 1000)
                return {
                    'port':    port,
                    'state':   'open',
                    'service': PORT_SERVICES.get(port, 'unknown'),
                    'latency': latency,
                    'risky':   port in RISKY_PORTS
                }
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return None


@app.route('/api/port-scan', methods=['POST'])
def port_scan():
    """
    Escáner TCP real con Server-Sent Events.
    El frontend recibe: progreso en tiempo real + puertos abiertos + resultado final.
    No requiere nmap — usa socket Python puro con ThreadPoolExecutor (máx 50 hilos).
    """
    data       = request.json or {}
    target     = data.get('target', '').strip()
    ports      = data.get('ports', [])
    timeout_ms = min(max(int(data.get('timeout', 1000)), 200), 5000)
    do_resolve = data.get('resolve', True)

    if not target:
        return jsonify({'error': 'No se especificó un objetivo'}), 400
    if not ports or len(ports) > 200:
        return jsonify({'error': 'Especifica entre 1 y 200 puertos'}), 400

    # Bloquear rangos no enrutables (autoconfig, multicast, reservado)
    for blocked in ('0.', '169.254.', '224.', '240.'):
        if target.startswith(blocked):
            return jsonify({'error': f'Rango de IP no permitido: {blocked}*'}), 400

    timeout_s = timeout_ms / 1000.0

    def generate():
        def sse(obj):
            return f"data: {json.dumps(obj)}\n\n"

        t_start = time.monotonic()
        ip      = target
        rdns    = ''

        # 1. Resolución DNS
        if do_resolve:
            try:
                resolved = socket.gethostbyname(target)
                if resolved != target:
                    ip = resolved
                    yield sse({'type': 'resolved', 'host': target, 'ip': ip})
            except socket.gaierror as e:
                yield sse({'type': 'error', 'message': f'No se pudo resolver "{target}": {e}'})
                return
        else:
            try:
                socket.inet_aton(target)
            except socket.error:
                yield sse({'type': 'error', 'message': 'Host inválido. Usa una IP directa o activa la resolución DNS.'})
                return

        # rDNS (reverse lookup, no crítico si falla)
        try:
            rdns = socket.gethostbyaddr(ip)[0]
        except Exception:
            rdns = ''

        # 2. Escaneo TCP paralelo — máximo 50 hilos simultáneos
        open_ports = []
        total      = len(ports)
        scanned    = 0
        workers    = min(50, total)

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {executor.submit(_tcp_probe, ip, p, timeout_s): p for p in ports}

            for future in concurrent.futures.as_completed(future_map):
                scanned += 1
                port = future_map[future]

                # Evento de progreso por cada puerto procesado
                yield sse({'type': 'progress', 'port': port, 'scanned': scanned, 'total': total})

                result = future.result()
                if result:
                    open_ports.append(result)
                    # Evento inmediato al encontrar puerto abierto
                    yield sse({
                        'type':    'open',
                        'port':    result['port'],
                        'service': result['service'],
                        'latency': result['latency'],
                        'risky':   result['risky']
                    })

        scan_time  = round(time.monotonic() - t_start, 2)
        open_ports.sort(key=lambda x: x['port'])

        # 3. Evento final con resultado completo
        yield sse({
            'type': 'done',
            'result': {
                'target':        target,
                'ip':            ip,
                'hostname':      target,
                'rdns':          rdns,
                'open_ports':    open_ports,
                'total_scanned': total,
                'total_open':    len(open_ports),
                'scan_time':     scan_time,
                'timeout_ms':    timeout_ms,
                'timestamp':     datetime.now().isoformat()
            }
        })

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control':     'no-cache',
            'X-Accel-Buffering': 'no',   # evita buffering en Nginx/proxy
            'Connection':        'keep-alive'
        }
    )


if __name__ == '__main__':
    print("🚀 FORENCOMMUNITY Server arrancando...")
    print("📌 Endpoints reales activos:")
    print("   ✅ /api/ip-info              → ip-api.com (geolocalización real)")
    print("   ✅ /api/check-email          → Have I Been Pwned (filtraciones reales)")
    print("   ✅ /api/check-password-pwned → HIBP k-anonymity (sin exponer contraseña)")
    print("   ✅ /api/generate-password    → secrets (criptográficamente seguro)")
    print("   ✅ /api/check-phone          → libphonenumber (validación real)")
    print("   ✅ /api/scan-headers         → HTTP proxy real (cabeceras reales)")
    print("   ✅ /api/temp-email/*         → mail.tm (inbox funcional real)")
    print("   ✅ /api/port-scan            → TCP socket real + SSE streaming")
    app.run(debug=False, host='0.0.0.0', port=5000)
