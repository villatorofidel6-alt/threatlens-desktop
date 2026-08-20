# ThreatLens Desktop — Arquitectura y límites de seguridad

## Propósito

ThreatLens Desktop es una aplicación local para el **triage defensivo** de archivos, URLs y dominios. Opera por análisis estático o por recuperación HTTP limitada y nunca ejecuta, importa, abre con el sistema ni descomprime automáticamente una muestra. Su finalidad es reunir indicadores revisables que ayuden a priorizar una investigación; no determina de forma concluyente que un archivo sea malicioso ni sustituye un análisis profesional en un entorno aislado.

## Principios no negociables

| Principio | Aplicación en el producto |
|---|---|
| Local-first | Los archivos se analizan en el equipo del usuario. No se cargan a un servicio remoto. |
| Sin ejecución | No hay sandbox dinámico, emulación, macros activas, importación de módulos ni apertura automática de documentos. |
| Reversing seguro | Se inspeccionan bytes, encabezados, tablas y metadatos. No se desempaqueta código ejecutable ni se intenta romper cifrado. |
| Red limitada y explícita | El análisis de URL hace peticiones HTTP con tiempo de espera, límite de redirecciones y descarga máxima; se puede desactivar. |
| Evidencia trazable | Todo hallazgo tiene categoría, severidad, evidencia limitada y una recomendación de remediación. |
| Privacidad | El historial y los reportes residen en SQLite local. |

## Componentes

```text
CLI / TUI Rich / GUI Tkinter
            |
            v
       AnalysisService
        /            \
       v              v
 FileAnalyzer       UrlAnalyzer
  |  |  |             |   |
  |  |  +-- Static reversing  +-- HTTP headers, redirects, HTML inspection
  |  +----- Indicators             
  +-------- Hashes, entropy, strings
            |
            v
   RiskScorer + RecommendationEngine
            |
            +--> SQLite History
            +--> JSON / HTML / text exporters
```

## Modelo de datos

Cada análisis produce un `AnalysisReport`, que contiene el objetivo, metadatos, una colección de hallazgos normalizados, puntuación de riesgo de 0 a 100, resumen por categoría y recomendaciones. Un hallazgo incorpora `id`, `category`, `severity`, `title`, `evidence` y `recommendation`. Las evidencias se truncan; nunca se guardan archivos completos en el historial.

## Capacidades del MVP

| Área | Implementación segura |
|---|---|
| Archivo | MD5, SHA-1, SHA-256, tamaño, tipo por firmas, entropía global y por bloques, strings ASCII/UTF-16LE y nombres de coincidencias. |
| Indicadores | Patrones de persistencia, C2 y PowerShell codificado; heurísticas de shellcode, ofuscación y empaquetadores UPX/MPRESS; reglas YARA básicas integradas sin distribución de muestras. |
| Reversing | Detección y metadatos estáticos de PE, ELF, ZIP y PDF. Para PE: secciones, importaciones, exportaciones e imphash con `pefile` si está disponible. |
| URL | Cabeceras HTTP, cadena de redirecciones, análisis HTML limitado, iframes ocultos, formularios de phishing, scripts inline y patrones de C2. |
| Riesgo | Ponderación transparente, con tope de 100 y resumen de severidades. |
| Reportes | Texto, JSON y HTML autocontenido; historial SQLite con búsqueda local. |

## Tratamiento de archivos cifrados y comprimidos

ThreatLens identifica alta entropía, encabezados de formatos cifrados, entradas ZIP protegidas y señales de empaquetado. Puede informar que una muestra no se puede inspeccionar en profundidad sin una clave o contraseña proporcionada por el propietario, pero **no intenta descifrar, forzar contraseñas, evadir protecciones ni reconstruir carga maliciosa**.

## Instalación multiplataforma

La aplicación se distribuye como paquete Python y como binarios generados con PyInstaller. PyInstaller empaqueta una aplicación junto con sus dependencias, pero los binarios deben construirse en el sistema operativo destino; por ello el repositorio usará una matriz de GitHub Actions para Windows, Linux y macOS. [1]

## Dependencias seleccionadas

Se prioriza la biblioteca estándar. `pefile` se emplea únicamente para leer estructuras PE como importaciones, exportaciones y secciones. [2] Las reglas opcionales emplean la sintaxis de YARA, cuya semántica está basada en patrones de texto o bytes y condiciones booleanas. [3]

## Referencias

[1] [PyInstaller Manual](https://www.pyinstaller.org/)

[2] [pefile — Portable Executable Reader Module](https://pefile.readthedocs.io/en/latest/modules/pefile.html)

[3] [YARA Documentation](https://yara.readthedocs.io/)

*Identidad del proyecto: creado y fundado por Lumen AI.*
