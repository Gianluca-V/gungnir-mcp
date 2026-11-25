# Contenedor opcional para correr el agente (Claude Code u opencode) aislado del equipo.
# Se arma desde la raíz del repo: docker compose -f agente/docker-compose.yml build
FROM node:24-bookworm-slim AS mcp
WORKDIR /mcp
COPY mcp/package.json mcp/package-lock.json ./
RUN npm ci --silent
COPY mcp/tsconfig.json ./
COPY mcp/src ./src
RUN npm run build && npm prune --omit=dev --silent

FROM node:24-bookworm-slim
ARG CLAUDE_CODE_VERSION=2.1.300
ARG OPENCODE_VERSION=1.19.3
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl dnsutils git jq netcat-openbsd nmap openssl python3 ripgrep whois \
 && rm -rf /var/lib/apt/lists/* \
 && npm install -g --silent @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} opencode-ai@${OPENCODE_VERSION}
# La configuración y el servidor quedan fuera del alcance de escritura del agente.
COPY --from=mcp /mcp /opt/gungnir-mcp
COPY agente/mcp.json agente/opencode.json /opt/agente/
RUN install -d -o node -g node /trabajo /home/node/.claude /home/node/.config /home/node/.local /home/node/.cache
ENV CLAUDE_CONFIG_DIR=/home/node/.claude OPENCODE_CONFIG=/opt/agente/opencode.json GUNGNIR_CARPETA=/trabajo DISABLE_AUTOUPDATER=1
USER node
WORKDIR /trabajo
CMD ["bash"]
