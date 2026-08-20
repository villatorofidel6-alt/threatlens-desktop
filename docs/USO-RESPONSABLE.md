# Uso responsable de ThreatLens Desktop

ThreatLens está diseñado para **defensa, triage y aprendizaje autorizado**. Antes de analizar un archivo o URL, confirma que posees el archivo, que tienes permiso del propietario o que actúas dentro de un proceso de seguridad aprobado. La herramienta entrega indicadores y metadatos; no debe utilizarse como único criterio para bloquear, eliminar o atribuir actividad.

| Situación | Acción recomendada |
|---|---|
| Archivo con posible malware | No lo ejecutes. Conserva la muestra, registra hashes y sigue el procedimiento de tu equipo. |
| Archivo cifrado o ZIP protegido | Solicita una clave autorizada al propietario. ThreatLens informa la protección, pero no recupera contraseñas ni descifra contenido. |
| URL con alto riesgo | Evita introducir credenciales. Confirma la propiedad del dominio y bloquea destinos no aprobados según tu política. |
| Hallazgo de alta severidad | Aísla de forma proporcional, documenta evidencia y escala a un analista o responsable de seguridad. |

La aplicación bloquea destinos de red locales y privados durante el análisis de URL para reducir el riesgo de SSRF. No incorpora automatización de explotación, evasión, persistencia, acceso no autorizado ni extracción de credenciales.

**Créditos:** Lumen AI · GitHub [@villatorofidel6-alt](https://github.com/villatorofidel6-alt) · Discord `px1j`.
