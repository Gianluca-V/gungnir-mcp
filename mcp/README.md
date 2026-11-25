# Gungnir MCP

Servidor MCP para trabajar con Gungnir desde agentes como Claude Code u opencode. Corre en tu equipo por stdio y usa la API de Gungnir con una key de agente.

Guía completa, con ejemplos y configuraciones: [`docs/guia-gungnir-mcp.html`](../docs/guia-gungnir-mcp.html).

No ejecuta escaneos ni exploits. Le da al agente el alcance, la metodología y un lugar donde registrar; las herramientas las corre el agente en su propia terminal.

## Puesta en marcha

Hace falta Node 22.18 o posterior.

1. **Habilitá un engagement.** En el panel, Integraciones > Agentes > Acceso por engagement, elegí el nivel. Todos arrancan sin acceso.
2. **Creá una key.** En la pestaña Keys. Se muestra una sola vez.
3. **Compilá el servidor:**

   ```bash
   cd mcp
   npm ci
   npm run build
   ```

4. **Conectá tu cliente** con la ruta completa a `mcp/dist/index.js`.

### Claude Code

En `.mcp.json`, en la carpeta donde trabajás, con la key en una variable de entorno:

```json
{
  "mcpServers": {
    "gungnir": {
      "command": "node",
      "args": ["/ruta/completa/a/mcp/dist/index.js"],
      "env": {
        "GUNGNIR_URL": "http://localhost:3006",
        "GUNGNIR_API_KEY": "${GUNGNIR_API_KEY}"
      }
    }
  }
}
```

Verificá con `claude mcp list`.

### opencode

En `opencode.json`, con la key en una variable de entorno:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "gungnir": {
      "type": "local",
      "command": ["node", "/ruta/completa/a/mcp/dist/index.js"],
      "environment": {
        "GUNGNIR_URL": "http://localhost:3006",
        "GUNGNIR_API_KEY": "{env:GUNGNIR_API_KEY}"
      },
      "enabled": true
    }
  }
}
```

Verificá con `opencode mcp list`.

## Configuración

| Variable | Para qué | Por defecto |
|---|---|---|
| `GUNGNIR_URL` | Dirección de Gungnir | obligatoria |
| `GUNGNIR_API_KEY` | Key de agente | obligatoria |
| `GUNGNIR_CARPETA` | Única carpeta desde la que se suben archivos | la carpeta actual |
| `GUNGNIR_ENGAGEMENT` | Engagement por defecto | el único accesible |
| `GUNGNIR_TIEMPO_SEGUNDOS` | Espera máxima por pedido | 30 |
| `GUNGNIR_PERMITIR_HTTP` | `1` admite http hacia otro equipo. La key viaja sin cifrar | no |

En el servidor, `AGENTE_LIMITE_15MIN` cambia el límite de pedidos por key cada 15 minutos (3000).

## Niveles de autonomía

Vale el más restrictivo entre la key, el engagement, el rol de quien creó la key y el estado del engagement (entregado o archivado queda en Lectura). Lo controla el backend.

| Nivel | Puede |
|---|---|
| Sin acceso | Nada. Es el valor inicial de cada engagement |
| Lectura | Consultar |
| Propuesta | Además, registrar logs y evidencias. Los hallazgos esperan aprobación |
| Escritura | Además, crear y modificar hallazgos, metodología y técnicas |
| Total | Además, borrar hallazgos, logs y evidencias |

Ningún nivel permite cambiar el alcance, aprobar propuestas, ni administrar usuarios, configuración o keys.

## Herramientas

| Consulta | Escritura |
|---|---|
| `listar_engagements` `ver_engagement` | `registrar_log` |
| `ver_alcance` `verificar_alcance` | `crear_hallazgo` `modificar_hallazgo` |
| `listar_registros` `ver_hallazgo` | `adjuntar_evidencia` `importar_escaneo` |
| `ver_metodologia` `buscar_arsenal` | `marcar_metodologia` `registrar_tecnica` |
| `buscar_plantillas` `consultar_cve` | `borrar` |

Prompts: `planificacion`, `reconocimiento`, `escaneo`, `explotacion`, `post_explotacion` y `reporte`.

`importar_escaneo` lee nmap (`-oX`), Nessus, OpenVAS, Burp, ZAP y Nuclei (JSONL). Es la forma más económica en tokens: guarda el original como evidencia y devuelve un resumen. El informe PDF se genera desde el panel.

## Alcance

- Un dominio vale solo para sí mismo. Los subdominios se cargan como `*.dominio`.
- Una exclusión gana siempre. Un rango que toca una dirección excluida queda fuera entero. Con `10.0.0.5:22` excluido, `10.0.0.5` sin puerto también queda fuera.
- Una exclusión que no se entiende deja todo fuera hasta que se corrija. Cada IP o rango va completo: `10.0.0.5-20` o `10.0.0.0/24`, no `10.0.0.5,6,7`.
- Una URL acota esquema, puerto y ruta.
- Un log fuera de alcance se guarda, se marca y avisa en el panel. Un hallazgo fuera de alcance se rechaza.
- Los formatos SARIF y Trivy no se importan: no dicen a qué equipo corresponden.

## Límites que conviene conocer

- **El alcance se controla al registrar, no al ejecutar.** Un agente con terminal puede actuar sin avisar. Para acotarlo, usá el contenedor y reglas de red.
- **Se controla el objetivo declarado**, no lo que dice el comando, y no se resuelve DNS.
- **El ocultamiento es por patrones.** Reduce lo que llega al proveedor del modelo, no lo garantiza. Los objetivos y los nombres de archivo no se ocultan, y los comandos propios del arsenal salen como están.
- **El contenido de las evidencias no se entrega**, solo sus datos.
- **En el contenedor, `.claude` y `.config` persisten** y el agente puede escribirlos. Para empezar limpio: `docker compose -f agente/docker-compose.yml down -v`.
- **Exportar e importar un engagement en ZIP** no conserva la marca de fuera de alcance ni la key de cada log.
- **La key queda en la configuración del cliente.** Un agente con terminal puede leerla. Dale el nivel y los engagements justos, y revocala al terminar.

## Contenedor

Corre el agente sin acceso al resto del equipo: usuario sin privilegios, sin capacidades, sistema de archivos de solo lectura y una única carpeta compartida (`agente/trabajo`).

```bash
export GUNGNIR_API_KEY=gnga_...
docker compose -f agente/docker-compose.yml run --rm agente

# adentro
claude --mcp-config /opt/agente/mcp.json
opencode
```

En Linux, la carpeta compartida tiene que poder escribirla el usuario 1000.

Por defecto, nmap usa conexiones completas (`-sT`). Para paquetes crudos, sumá `-f agente/docker-compose.raw.yml`. El contenedor limita el equipo, no la red: lo que el equipo alcanza, el contenedor también.

## Desarrollo

```bash
npm test          # pruebas, sin red externa
npm run check     # tipos
```

Para sumar un ejecutor de herramientas, implementá `Ejecutor` (`src/ejecucion.ts`) y pasalo a `crearServidor`. El servidor verifica el alcance y registra antes de ejecutar.

En el backend: `npm test`. Para las pruebas de punta a punta de los agentes hace falta un MySQL descartable:

```bash
GUNGNIR_PRUEBA_DB=mysql://usuario:clave@127.0.0.1:3306/base_de_prueba node --test pruebas/agentes-mysql.test.js
```

Al traer novedades del upstream, corré `npm run arsenal` en `backend/`.
