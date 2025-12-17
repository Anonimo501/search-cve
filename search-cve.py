import requests
import re
import sys
from urllib.parse import urljoin

def cargar_listas_cve():
    """
    Carga las listas de CVEs desde los archivos de texto en GitHub
    """
    listas_cve = {
        'github.txt': [],
        'github-all.txt': []
    }
    
    base_url = "https://raw.githubusercontent.com/0xMarcio/cve/main/"
    
    for archivo in listas_cve.keys():
        try:
            url_archivo = urljoin(base_url, archivo)
            print(f"📥 Cargando {archivo}...")
            response = requests.get(url_archivo, timeout=10)
            if response.status_code == 200:
                lineas = response.text.split('\n')
                listas_cve[archivo] = [linea.strip() for linea in lineas if linea.strip()]
                print(f"   ✅ {len(listas_cve[archivo])} entradas cargadas")
            else:
                print(f"   ⚠️  No se pudo cargar {archivo} (código {response.status_code})")
        except Exception as e:
            print(f"   ❌ Error cargando {archivo}: {e}")
    
    return listas_cve

def buscar_cve_en_listas(cve_input, listas_cve):
    """
    Busca un CVE en las listas cargadas
    """
    cve_normalizado = cve_input.strip().upper()
    
    # Verificar formato
    if not re.match(r'^CVE-\d{4}-\d+$', cve_normalizado):
        print(f"⚠️  Formato de CVE incorrecto. Usa: CVE-AAAA-NNNN (ej: CVE-2025-0001)")
        return []
    
    resultados = []
    
    # Buscar en github.txt
    for linea in listas_cve['github.txt']:
        if cve_normalizado in linea.upper():
            # Extraer información de la línea
            partes = linea.split('|')
            if len(partes) >= 3:
                url = partes[0].strip()
                nombre = partes[1].strip() if len(partes) > 1 else "Sin nombre"
                descripcion = partes[2].strip() if len(partes) > 2 else ""
                resultados.append({
                    'fuente': 'github.txt',
                    'url': url,
                    'nombre': nombre,
                    'descripcion': descripcion,
                    'tiene_poc': 'poc' in descripcion.lower() or 'exploit' in descripcion.lower()
                })
    
    # Buscar en github-all.txt (formato diferente)
    for linea in listas_cve['github-all.txt']:
        if cve_normalizado in linea.upper():
            # Este archivo tiene un formato diferente
            if 'https://' in linea:
                # Buscar URL
                url_match = re.search(r'(https?://[^\s]+)', linea)
                if url_match:
                    url = url_match.group(1)
                    # Extraer nombre
                    nombre_match = re.search(r'CVE[-\w]+', linea, re.IGNORECASE)
                    nombre = nombre_match.group(0) if nombre_match else cve_normalizado
                    
                    resultados.append({
                        'fuente': 'github-all.txt',
                        'url': url,
                        'nombre': nombre,
                        'descripcion': linea,
                        'tiene_poc': 'poc' in linea.lower() or 'exploit' in linea.lower()
                    })
    
    return resultados

def buscar_directamente_en_github(cve_normalizado):
    """
    Búsqueda directa en GitHub como fallback
    """
    try:
        # Buscar en la API de GitHub
        api_url = f"https://api.github.com/search/repositories?q={cve_normalizado}+in:name+user:0xMarcio"
        response = requests.get(api_url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            resultados = []
            
            for item in data.get('items', []):
                resultados.append({
                    'fuente': 'github_api',
                    'url': item['html_url'],
                    'nombre': item['name'],
                    'descripcion': item.get('description', ''),
                    'tiene_poc': 'poc' in item.get('description', '').lower() or 
                                'exploit' in item.get('description', '').lower() or
                                'poc' in item['name'].lower()
                })
            
            return resultados
    except:
        pass
    
    return []

def mostrar_resultados(cve_normalizado, resultados):
    """
    Muestra los resultados de la búsqueda de forma organizada
    """
    if not resultados:
        print(f"\n❌ {cve_normalizado} NO encontrado en las listas")
        print(f"💡 Sugerencias:")
        print(f"   1. Verifica el formato (CVE-AAAA-NNNN)")
        print(f"   2. El CVE podría no estar en este repositorio")
        print(f"   3. Visita: https://github.com/0xMarcio/cve")
        print(f"   4. Prueba buscar en GitHub directamente")
        return
    
    print(f"\n✅ {cve_normalizado} ENCONTRADO - {len(resultados)} resultado(s)")
    print("=" * 70)
    
    # Agrupar por tipo
    repos_con_poc = []
    repos_sin_poc = []
    
    for resultado in resultados:
        if resultado['tiene_poc']:
            repos_con_poc.append(resultado)
        else:
            repos_sin_poc.append(resultado)
    
    # Mostrar repos con PoC primero
    if repos_con_poc:
        print(f"\n🟢 REPOSITORIOS CON PoC ({len(repos_con_poc)}):")
        print("-" * 70)
        
        for i, repo in enumerate(repos_con_poc, 1):
            print(f"\n📦 Repositorio {i}:")
            print(f"   📛 Nombre: {repo['nombre']}")
            print(f"   🔗 URL: {repo['url']}")
            print(f"   📝 Fuente: {repo['fuente']}")
            if repo['descripcion']:
                desc = repo['descripcion'][:120] + "..." if len(repo['descripcion']) > 120 else repo['descripcion']
                print(f"   📋 Descripción: {desc}")
            print(f"   {'─' * 60}")
    
    # Mostrar repos sin PoC
    if repos_sin_poc:
        print(f"\n🔴 REPOSITORIOS SIN PoC ({len(repos_sin_poc)}):")
        print("-" * 70)
        
        for i, repo in enumerate(repos_sin_poc, 1):
            print(f"\n📦 Repositorio {i}:")
            print(f"   📛 Nombre: {repo['nombre']}")
            print(f"   🔗 URL: {repo['url']}")
            print(f"   📝 Fuente: {repo['fuente']}")
            if repo['descripcion']:
                desc = repo['descripcion'][:100] + "..." if len(repo['descripcion']) > 100 else repo['descripcion']
                print(f"   📋 Descripción: {desc}")
            print(f"   {'─' * 60}")
    
    # Resumen
    print(f"\n📊 RESUMEN:")
    print(f"   • Total encontrados: {len(resultados)}")
    print(f"   • Con PoC: {len(repos_con_poc)}")
    print(f"   • Sin PoC: {len(repos_sin_poc)}")
    
    # Sugerir el mejor repo
    if repos_con_poc:
        mejor_repo = repos_con_poc[0]
        print(f"\n💡 RECOMENDACIÓN: Usa el repositorio '{mejor_repo['nombre']}'")
        print(f"   🔗 URL directa: {mejor_repo['url']}")

def main():
    """Función principal para ejecutar el script"""
    print("=" * 70)
    print("🚀 BUSCADOR AVANZADO DE CVE EN GITHUB")
    print("📚 Repositorio: https://github.com/0xMarcio/cve")
    print("=" * 70)
    print("💡 Este script busca en los archivos github.txt y github-all.txt")
    print("   que contienen todas las rutas de los repositorios de CVEs.")
    print("-" * 70)
    
    # Cargar listas al inicio
    print("\n⏳ Cargando bases de datos de CVEs...")
    listas_cve = cargar_listas_cve()
    
    if not listas_cve['github.txt'] and not listas_cve['github-all.txt']:
        print("⚠️  No se pudieron cargar las listas. Usando búsqueda alternativa...")
    
    print("\n" + "=" * 70)
    
    try:
        while True:
            try:
                print("\n📥 Ingresa un CVE (ej: CVE-2024-6387) o 'salir':")
                entrada = input("CVE: ").strip()
                
                # Manejar correcciones (backspace ya funciona nativamente)
                # Solo verificamos si hay entrada
                if not entrada:
                    continue
                
                if entrada.lower() in ['salir', 'exit', 'quit', 'q']:
                    print("\n👋 ¡Hasta luego! Gracias por usar el buscador.")
                    break
                
                # Validar formato básico
                if not re.match(r'(?i)cve-\d{4}-\d+', entrada):
                    print(f"⚠️  Formato inválido. Ejemplo: CVE-2024-6387")
                    continue
                
                # Normalizar
                cve_normalizado = entrada.strip().upper()
                
                print(f"\n🔍 Buscando {cve_normalizado}...")
                
                # Buscar en listas locales
                resultados = buscar_cve_en_listas(cve_normalizado, listas_cve)
                
                # Si no hay resultados en listas, buscar directamente
                if not resultados:
                    print("   🔎 No encontrado en listas. Buscando en GitHub...")
                    resultados = buscar_directamente_en_github(cve_normalizado)
                
                # Mostrar resultados
                mostrar_resultados(cve_normalizado, resultados)
                
            except KeyboardInterrupt:
                # Si el usuario presiona Ctrl+C durante input, mostrar opciones
                print("\n\n⌨️  Presiona Ctrl+C nuevamente para salir o escribe 'salir'")
                continue
                
    except KeyboardInterrupt:
        print("\n\n👋 Programa terminado por el usuario. ¡Hasta pronto!")
        sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Programa terminado. ¡Adiós!")
        sys.exit(0)
