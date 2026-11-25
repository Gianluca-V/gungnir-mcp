/**
 * Punto de extensión para un ejecutor de herramientas (por ejemplo, escaneos en contenedores).
 *
 * Esta versión no trae ninguno: el agente usa su propia terminal. Quien agregue uno lo pasa a
 * `crearServidor({ ejecutor })`, y el servidor suma la herramienta `ejecutar_herramienta`, que:
 *   1. verifica que todos los objetivos estén en el alcance, y si no, no ejecuta nada;
 *   2. registra el log antes de ejecutar;
 *   3. devuelve solo el resumen. El original va en `salida`, para importarlo o adjuntarlo.
 *
 * El control vale si el agente no tiene otra terminal. Si la tiene, puede ejecutar por afuera.
 */
export interface PedidoDeEjecucion {
  herramienta: string
  /**
   * Lista de argumentos, nunca una línea de comandos: el ejecutor no debe pasar por un shell.
   * El servidor solo verifica `objetivos`: el ejecutor tiene que armar él los objetivos del comando y
   * rechazar acá cualquier argumento que agregue otros (un host, una URL o un archivo de objetivos).
   */
  argumentos: string[]
  objetivos: string[]
}

export interface ResultadoDeEjecucion {
  codigo: number
  resumen: string
  /** Ruta de la salida completa, relativa a la carpeta de trabajo. */
  salida?: string
}

export interface Ejecutor {
  readonly herramientas: readonly string[]
  ejecutar(pedido: PedidoDeEjecucion, cancelar: AbortSignal): Promise<ResultadoDeEjecucion>
}
