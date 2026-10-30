/** Lo mínimo que se necesita de un OutputChannel; así exec y http se prueban sin VS Code. */
export interface LineSink {
  appendLine(value: string): void;
}

export interface Logger {
  info(message: string): void;
  command(display: string): void;
  output(text: string): void;
}

export function createLogger(sink: LineSink, clock: () => Date = () => new Date()): Logger {
  const stamp = () => {
    // Hora local del usuario: AAAA-MM-DD HH:MM:SS.
    const d = clock();
    const p = (n: number) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  };
  return {
    info: (message) => sink.appendLine(`[${stamp()}] ${message}`),
    command: (display) => sink.appendLine(`[${stamp()}] $ ${display}`),
    output: (text) => {
      const trimmed = text.replace(/\s+$/, '');
      if (trimmed) sink.appendLine(trimmed);
    },
  };
}
