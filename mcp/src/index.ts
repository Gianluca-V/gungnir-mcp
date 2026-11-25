#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { crearCliente } from './cliente.ts'
import { leerConfig } from './config.ts'
import { crearServidor } from './servidor.ts'

// La salida estándar es el canal del protocolo: los avisos van siempre por la de errores.
try {
  const cfg = leerConfig(process.env, process.cwd())
  const servidor = crearServidor({ cliente: crearCliente(cfg), carpeta: cfg.carpeta, engagement: cfg.engagement })
  await servidor.connect(new StdioServerTransport())
  console.error(`[gungnir-mcp] listo: ${cfg.url}, carpeta ${cfg.carpeta}`)
} catch (e) {
  console.error(`[gungnir-mcp] ${e instanceof Error ? e.message : 'no se pudo iniciar'}`)
  process.exit(1)
}
