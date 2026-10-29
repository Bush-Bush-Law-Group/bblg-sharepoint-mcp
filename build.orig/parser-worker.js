/**
 * Worker-thread entry for document parsing. Started by DocumentParser.parseDocumentIsolated with
 * the file bytes in workerData; posts exactly one ParserWorkerOutput message back. Isolating the
 * parse lets the parent enforce a wall-clock timeout and a heap limit that a synchronous parser
 * on the main thread could not honour.
 */
import { parentPort, workerData } from 'worker_threads';
import { DocumentParser } from './document-parser.js';
const port = parentPort;
if (!port) {
    throw new Error('parser-worker.js must be started as a worker thread by DocumentParser.parseDocumentIsolated');
}
const input = workerData;
DocumentParser.parseDocument(Buffer.from(input.bytes), input.filename, input.mimeType)
    .then((result) => ({ ok: true, result }))
    .catch((error) => ({ ok: false, error: error instanceof Error ? error.message : String(error) }))
    .then(output => port.postMessage(output));
