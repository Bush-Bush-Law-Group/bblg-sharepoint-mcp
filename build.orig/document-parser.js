/**
 * Document Parser Utility for SharePoint MCP Server
 * Supports PDF, Word (.docx), Excel, PowerPoint, HTML, RTF, and text files
 */
import * as XLSX from 'xlsx';
import yauzl from 'yauzl';
import { parse as parseHtml } from 'node-html-parser';
import { Worker } from 'worker_threads';
import { logger } from './logger.js';
// Security: Size limits for document parsing
const MAX_EXTRACTED_TEXT_LENGTH = 5 * 1024 * 1024; // 5MB max text output
const DEFAULT_MAX_ZIP_EXTRACTED_SIZE = 50 * 1024 * 1024; // 50MB max decompression size
const DEFAULT_MAX_SPREADSHEET_CELLS = 2_000_000; // rows x columns serialised per sheet
const DEFAULT_PARSE_TIMEOUT_MS = 60_000;
const DEFAULT_PARSE_WORKER_MAX_MEMORY_MB = 2048;
/** Positive integer from the environment, read at call time so operators (and tests) can tune it without a module restart. */
function positiveIntFromEnv(name, fallback) {
    const configured = parseInt(process.env[name] || '', 10);
    return Number.isFinite(configured) && configured > 0 ? configured : fallback;
}
const maxZipExtractedSize = () => positiveIntFromEnv('MAX_ZIP_EXTRACTED_SIZE', DEFAULT_MAX_ZIP_EXTRACTED_SIZE);
const maxSpreadsheetCells = () => positiveIntFromEnv('MAX_SPREADSHEET_CELLS', DEFAULT_MAX_SPREADSHEET_CELLS);
const SIZE_LIMIT_WARNING = '\n\n[WARNING: Extraction stopped - decompressed content exceeded size limit]';
// Security: Bounds on document-derived metadata. Text has its own 5MB cap; without these a
// PDF /Title or a page of <meta> tags could carry megabytes past it.
export const MAX_METADATA_STRING_LENGTH = 2 * 1024;
export const MAX_METADATA_TOTAL_LENGTH = 32 * 1024;
export const MAX_META_TAGS = 50;
const METADATA_TRUNCATION_MARKER = '…[truncated]';
const METADATA_TRUNCATED_FLAG = 'metadataTruncated';
// Security: Truncate text if it exceeds maximum length
function truncateText(text, maxLength = MAX_EXTRACTED_TEXT_LENGTH) {
    if (text.length > maxLength) {
        return text.substring(0, maxLength) + `\n\n[WARNING: Text truncated at ${(maxLength / 1024 / 1024).toFixed(1)}MB limit. Original size: ${(text.length / 1024 / 1024).toFixed(1)}MB]`;
    }
    return text;
}
/**
 * Bounds every document-derived metadata value: strings (and keys) to MAX_METADATA_STRING_LENGTH,
 * metaTags to MAX_META_TAGS entries and the serialised whole to MAX_METADATA_TOTAL_LENGTH. Entries
 * that no longer fit are dropped in insertion order, so the fixed fields written first survive, and
 * `metadataTruncated: true` records that anything was cut.
 */
function boundMetadata(metadata) {
    // Reserve room for the flag so setting it can never push the result over the cap.
    let remaining = MAX_METADATA_TOTAL_LENGTH - `"${METADATA_TRUNCATED_FLAG}":true,`.length;
    let truncated = false;
    const boundString = (value) => {
        if (value.length <= MAX_METADATA_STRING_LENGTH)
            return value;
        truncated = true;
        return value.slice(0, MAX_METADATA_STRING_LENGTH) + METADATA_TRUNCATION_MARKER;
    };
    /** Conservative JSON footprint of a leaf; Dates serialise to ISO strings. */
    const leafSize = (value) => value instanceof Date ? 30 : (JSON.stringify(value)?.length ?? 0);
    /** Charges `size` plus the entry's own key/quotes/colon/comma against the budget; false when it does not fit. */
    const charge = (key, size) => {
        const cost = size + key.length + 4;
        if (cost > remaining) {
            truncated = true;
            return false;
        }
        remaining -= cost;
        return true;
    };
    const bound = (value, key) => {
        if (typeof value === 'string') {
            const bounded = boundString(value);
            return { keep: charge(key, bounded.length + 2), value: bounded };
        }
        if (Array.isArray(value)) {
            if (!charge(key, 2))
                return { keep: false, value };
            const out = [];
            for (const item of value) {
                const entry = bound(item, '');
                if (!entry.keep)
                    break;
                out.push(entry.value);
            }
            return { keep: true, value: out };
        }
        if (value && typeof value === 'object' && !(value instanceof Date)) {
            if (!charge(key, 2))
                return { keep: false, value };
            const out = {};
            const entries = Object.entries(value);
            const limit = key === 'metaTags' ? MAX_META_TAGS : entries.length;
            if (entries.length > limit)
                truncated = true;
            for (const [childKey, childValue] of entries.slice(0, limit)) {
                const boundedKey = boundString(childKey);
                const entry = bound(childValue, boundedKey);
                if (!entry.keep)
                    break;
                out[boundedKey] = entry.value;
            }
            return { keep: true, value: out };
        }
        return { keep: charge(key, leafSize(value)), value };
    };
    const result = bound(metadata, '').value;
    if (truncated)
        result[METADATA_TRUNCATED_FLAG] = true;
    return result;
}
/** Bounding box of the cells that actually exist, ignoring the sheet's declared `!ref` dimension. */
function populatedRange(sheet) {
    let range;
    let cells = 0;
    for (const key of Object.keys(sheet)) {
        if (key.startsWith('!'))
            continue;
        const cell = XLSX.utils.decode_cell(key);
        cells++;
        if (!range) {
            range = { s: { r: cell.r, c: cell.c }, e: { r: cell.r, c: cell.c } };
            continue;
        }
        if (cell.r < range.s.r)
            range.s.r = cell.r;
        if (cell.r > range.e.r)
            range.e.r = cell.r;
        if (cell.c < range.s.c)
            range.s.c = cell.c;
        if (cell.c > range.e.c)
            range.e.c = cell.c;
    }
    return range ? { range, cells } : undefined;
}
// Security: Strip potentially dangerous XML declarations (XXE defense-in-depth)
function sanitizeXml(xml) {
    return xml
        .replace(/<!DOCTYPE[^>]*>/gi, '')
        .replace(/<!ENTITY[^>]*>/gi, '')
        .replace(/<\?xml-stylesheet[^>]*\?>/gi, '');
}
export class DocumentParser {
    /**
     * Parse a document based on its file extension and MIME type
     */
    static async parseDocument(buffer, filename, mimeType) {
        const extension = filename.toLowerCase().split('.').pop() || '';
        logger.info(`Parsing document: ${filename} (${extension}, ${mimeType})`);
        try {
            let result;
            switch (extension) {
                case 'pdf':
                    result = await this.parsePDF(buffer, filename);
                    break;
                case 'docx':
                    result = await this.parseWord(buffer);
                    break;
                case 'doc':
                    result = this.handleUnsupportedWordFormat(filename);
                    break;
                case 'xls':
                case 'xlsx':
                case 'xlsm':
                case 'xlsb':
                    result = await this.parseExcel(buffer);
                    break;
                case 'ppt':
                case 'pptx':
                    result = await this.parsePowerPoint(buffer);
                    break;
                case 'txt':
                case 'md':
                case 'json':
                case 'xml':
                case 'csv':
                case 'log':
                case 'ini':
                case 'yaml':
                case 'yml':
                    result = this.parseText(buffer, extension);
                    break;
                case 'html':
                case 'htm':
                    result = this.parseHTML(buffer);
                    break;
                case 'rtf':
                    result = this.parseRTF(buffer);
                    break;
                default:
                    // Try to parse as text if MIME type suggests it
                    if (mimeType && (mimeType.startsWith('text/') || mimeType.includes('json') || mimeType.includes('xml'))) {
                        result = this.parseText(buffer, extension);
                        break;
                    }
                    throw new Error(`Unsupported file format: ${extension}`);
            }
            return { text: truncateText(result.text), metadata: boundMetadata(result.metadata) };
        }
        catch (error) {
            logger.error(`Failed to parse ${extension} file: ${error.message}`);
            throw new Error(`Failed to parse ${extension} file: ${error.message}`);
        }
    }
    /**
     * Parses in a worker thread under a wall-clock timeout and a heap limit. Every parser runs
     * synchronously on whichever thread hosts it (pdfjs uses an in-process fake worker), so an
     * adversarial document must never share the thread that serves JSON-RPC. On expiry the worker
     * is terminated and the caller gets an error instead of a stalled server.
     */
    static async parseDocumentIsolated(buffer, filename, mimeType, options = {}) {
        if (options.inProcess) {
            return this.parseDocument(buffer, filename, mimeType);
        }
        const timeoutMs = options.timeoutMs ?? positiveIntFromEnv('PARSE_TIMEOUT_MS', DEFAULT_PARSE_TIMEOUT_MS);
        const maxOldGenerationSizeMb = positiveIntFromEnv('PARSE_WORKER_MAX_MEMORY_MB', DEFAULT_PARSE_WORKER_MAX_MEMORY_MB);
        const workerPath = options.workerPath ?? new URL('./parser-worker.js', import.meta.url);
        // Copy into a standalone ArrayBuffer: Node pools small Buffers, so transferring
        // buffer.buffer directly could detach memory that belongs to something else.
        const bytes = new Uint8Array(buffer.byteLength);
        bytes.set(buffer);
        const workerData = { bytes: bytes.buffer, filename, mimeType };
        return new Promise((resolve, reject) => {
            const worker = new Worker(workerPath, {
                workerData,
                transferList: [bytes.buffer],
                resourceLimits: { maxOldGenerationSizeMb },
            });
            let settled = false;
            const settle = (outcome) => {
                if (settled)
                    return;
                settled = true;
                clearTimeout(timer);
                outcome();
                worker.terminate().catch(() => { });
            };
            const timer = setTimeout(() => {
                logger.warn(`Document parsing of ${filename} timed out after ${timeoutMs}ms; terminating parser worker`);
                settle(() => reject(new Error(`Document parsing timed out after ${timeoutMs}ms and was stopped (PARSE_TIMEOUT_MS). The file may be too large or too complex to parse.`)));
            }, timeoutMs);
            worker.once('message', (message) => settle(() => {
                if (message.ok)
                    resolve(message.result);
                else
                    reject(new Error(message.error));
            }));
            worker.once('error', (error) => settle(() => reject(new Error(`Document parser worker failed: ${error.message}`))));
            worker.once('exit', (code) => settle(() => reject(new Error(`Document parser worker exited with code ${code} before returning a result`))));
        });
    }
    /**
     * Parse PDF files using pdfjs-dist
     */
    static async parsePDF(buffer, filename) {
        try {
            if (!Buffer.isBuffer(buffer)) {
                throw new Error('PDF data must be a Buffer');
            }
            if (buffer.length === 0) {
                throw new Error('PDF buffer is empty');
            }
            // Dynamic import for ESM compatibility
            const pdfjs = await import('pdfjs-dist/legacy/build/pdf.mjs');
            // Configure worker (optional, but recommended for better performance)
            // Note: Worker setup might need adjustment based on environment
            const loadingTask = pdfjs.getDocument({
                data: new Uint8Array(buffer),
                verbosity: 0, // Suppress console output
                useSystemFonts: true,
            });
            const pdf = await loadingTask.promise;
            let fullText = '';
            const pageTexts = [];
            // Extract text from each page
            for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {
                try {
                    const page = await pdf.getPage(pageNum);
                    const textContent = await page.getTextContent();
                    // Reconstruct text with proper spacing
                    let pageText = '';
                    let lastY = null;
                    for (const item of textContent.items) {
                        if ('str' in item) {
                            // Add line break if Y position changed significantly
                            if (lastY !== null && Math.abs(item.transform[5] - lastY) > 5) {
                                pageText += '\n';
                            }
                            pageText += item.str;
                            lastY = item.transform[5];
                        }
                    }
                    pageText = pageText.trim();
                    if (pageText) {
                        pageTexts.push(pageText);
                        fullText += `\n\n--- Page ${pageNum} ---\n${pageText}`;
                    }
                }
                catch (pageError) {
                    logger.warn(`Error extracting text from PDF page ${pageNum}: ${pageError.message}`);
                    fullText += `\n\n--- Page ${pageNum} ---\n[Error extracting text from this page]`;
                }
            }
            // Try to extract metadata
            let metadata = {
                format: 'PDF',
                pages: pdf.numPages,
                extractedBy: 'pdfjs-dist',
                filename: filename,
                size: buffer.length
            };
            try {
                const info = await pdf.getMetadata();
                if (info.info) {
                    const pdfInfo = info.info;
                    metadata = {
                        ...metadata,
                        title: pdfInfo.Title,
                        author: pdfInfo.Author,
                        subject: pdfInfo.Subject,
                        keywords: pdfInfo.Keywords,
                        creator: pdfInfo.Creator,
                        producer: pdfInfo.Producer,
                        creationDate: pdfInfo.CreationDate,
                        modificationDate: pdfInfo.ModDate,
                        pdfVersion: pdfInfo.PDFFormatVersion
                    };
                }
            }
            catch (metaError) {
                logger.debug(`Could not extract PDF metadata: ${metaError.message}`);
            }
            return {
                text: fullText.trim() || '[No text content found in PDF]',
                metadata
            };
        }
        catch (error) {
            logger.error(`PDF parsing error: ${error.message}`);
            throw new Error(`PDF parsing failed: ${error.message}. This may be due to an encrypted, corrupted, or unsupported PDF format.`);
        }
    }
    /**
     * Handle legacy .doc format - not supported
     */
    static handleUnsupportedWordFormat(filename) {
        logger.info(`Legacy .doc format not supported for parsing: ${filename}`);
        return {
            text: '[Legacy .doc format not supported. Please convert to .docx, PDF, or another supported format for text extraction.]',
            metadata: {
                format: 'Word Document (Legacy)',
                filename: filename,
                note: 'Legacy .doc files cannot be parsed. Modern .docx files are supported. Consider converting to .docx or PDF.',
                supportedFormats: ['PDF', 'Word (.docx)', 'Excel', 'PowerPoint', 'HTML', 'RTF', 'Text files']
            }
        };
    }
    /**
     * Parse Excel files using xlsx
     */
    static async parseExcel(buffer) {
        try {
            const cellBudget = maxSpreadsheetCells();
            // Security: sheetRows bounds what SheetJS materialises while parsing (a single column may
            // use the whole cell budget, so that is the tightest row bound consistent with it). The
            // declared `!ref` dimension is untrusted: the serialisers below walk every cell of it, so
            // each sheet is serialised over its populated bounding box, clamped to the cell budget.
            const workbook = XLSX.read(buffer, { type: 'buffer', cellDates: true, sheetRows: cellBudget });
            let text = '';
            const metadata = {
                format: 'Excel Spreadsheet',
                extractedBy: 'xlsx',
                sheets: [],
                totalRows: 0,
                totalCells: 0,
                size: buffer.length
            };
            workbook.SheetNames.forEach(sheetName => {
                const sheet = workbook.Sheets[sheetName];
                const declaredRange = sheet['!ref'];
                const populated = populatedRange(sheet);
                text += `\n\n=== Sheet: ${sheetName} ===\n`;
                if (!populated) {
                    metadata.sheets.push({ name: sheetName, rows: 0, columns: 0, range: declaredRange || 'Unknown' });
                    return;
                }
                const { range } = populated;
                const populatedRef = XLSX.utils.encode_range(range);
                const columns = range.e.c - range.s.c + 1;
                const rows = range.e.r - range.s.r + 1;
                let clamped = false;
                if (columns > cellBudget) {
                    range.e.c = range.s.c + cellBudget - 1;
                    clamped = true;
                }
                if (rows * (range.e.c - range.s.c + 1) > cellBudget) {
                    range.e.r = range.s.r + Math.max(1, Math.floor(cellBudget / (range.e.c - range.s.c + 1))) - 1;
                    clamped = true;
                }
                const rangeRef = XLSX.utils.encode_range(range);
                // Both serialisers walk `!ref` (sheet_to_csv ignores a range option), and the workbook
                // is local to this call, so the bounded range replaces the declared one in place.
                sheet['!ref'] = rangeRef;
                // Convert to CSV for text representation
                const csvData = XLSX.utils.sheet_to_csv(sheet, { blankrows: false });
                // Also get JSON for structured data
                const jsonData = XLSX.utils.sheet_to_json(sheet, { header: 1, defval: '' });
                text += csvData;
                if (clamped) {
                    text += `\n[WARNING: Sheet clamped to ${rangeRef}: populated range ${populatedRef} exceeds the ${cellBudget}-cell budget (MAX_SPREADSHEET_CELLS)]`;
                }
                const sheetInfo = {
                    name: sheetName,
                    rows: jsonData.length,
                    columns: jsonData[0] ? jsonData[0].length : 0,
                    range: rangeRef
                };
                if (declaredRange && declaredRange !== rangeRef)
                    sheetInfo.declaredRange = declaredRange;
                if (clamped) {
                    sheetInfo.clamped = true;
                    sheetInfo.populatedRange = populatedRef;
                }
                metadata.sheets.push(sheetInfo);
                metadata.totalRows += jsonData.length;
                metadata.totalCells += populated.cells;
            });
            // Extract workbook properties if available
            if (workbook.Props) {
                metadata.title = workbook.Props.Title;
                metadata.author = workbook.Props.Author;
                metadata.company = workbook.Props.Company;
                metadata.created = workbook.Props.CreatedDate;
                metadata.modified = workbook.Props.ModifiedDate;
            }
            return {
                text: text.trim() || '[No data found in Excel file]',
                metadata
            };
        }
        catch (error) {
            throw new Error(`Excel file parsing failed: ${error.message}`);
        }
    }
    /**
     * Parse PowerPoint files by extracting text from slides
     */
    static async parsePowerPoint(buffer) {
        return new Promise((resolve, reject) => {
            yauzl.fromBuffer(buffer, { lazyEntries: true }, (err, zipfile) => {
                if (err) {
                    resolve({
                        text: "[PowerPoint content - unable to extract]",
                        metadata: {
                            format: 'PowerPoint Presentation',
                            note: "PowerPoint file could not be parsed",
                            size: buffer.length
                        }
                    });
                    return;
                }
                const slides = [];
                let slideText = '';
                const slideContents = new Map();
                let totalExtracted = 0;
                let sizeLimitExceeded = false;
                const limit = maxZipExtractedSize();
                let settled = false;
                const finish = () => {
                    if (settled)
                        return;
                    settled = true;
                    // Sort slides by number and build text
                    const sortedSlides = Array.from(slideContents.entries()).sort((a, b) => a[0] - b[0]);
                    for (const [slideNum, content] of sortedSlides) {
                        slides.push(content);
                        slideText += `\n\nSlide ${slideNum}:\n${content}`;
                    }
                    if (sizeLimitExceeded) {
                        slideText += SIZE_LIMIT_WARNING;
                    }
                    resolve({
                        text: slideText.trim() || "[No text content found in PowerPoint]",
                        metadata: {
                            format: 'PowerPoint Presentation',
                            extractedBy: 'yauzl',
                            slides: slides.length,
                            size: buffer.length,
                            note: "Extracted text content from PowerPoint slides"
                        }
                    });
                };
                const fail = (error) => {
                    if (settled)
                        return;
                    settled = true;
                    reject(error);
                };
                zipfile.on("error", fail);
                zipfile.on("entry", (entry) => {
                    // Look for slide XML files
                    if (!sizeLimitExceeded && entry.fileName.includes("ppt/slides/slide") && entry.fileName.endsWith(".xml")) {
                        const slideMatch = entry.fileName.match(/slide(\d+)\.xml/);
                        const slideNumber = slideMatch ? parseInt(slideMatch[1]) : slides.length + 1;
                        zipfile.openReadStream(entry, (err, readStream) => {
                            if (err) {
                                fail(err);
                                return;
                            }
                            // Buffers are kept and decoded once: decoding chunk by chunk would corrupt any
                            // multi-byte UTF-8 sequence that straddles a chunk boundary.
                            const chunks = [];
                            readStream.on('error', fail);
                            readStream.on('data', (chunk) => {
                                // Count while streaming so an oversized entry is never fully buffered.
                                totalExtracted += chunk.length;
                                if (totalExtracted > limit) {
                                    sizeLimitExceeded = true;
                                    readStream.destroy();
                                    zipfile.close();
                                    finish();
                                    return;
                                }
                                chunks.push(chunk);
                            });
                            readStream.on('end', () => {
                                if (sizeLimitExceeded)
                                    return;
                                const safeContent = sanitizeXml(Buffer.concat(chunks).toString('utf8'));
                                // Extract text from XML
                                const textMatches = safeContent.match(/<a:t[^>]*>([^<]*)<\/a:t>/g);
                                if (textMatches) {
                                    const slideContent = textMatches
                                        .map(match => match.replace(/<a:t[^>]*>([^<]*)<\/a:t>/, '$1'))
                                        .filter(text => text.trim())
                                        .join(' ');
                                    if (slideContent) {
                                        slideContents.set(slideNumber, slideContent);
                                    }
                                }
                                zipfile.readEntry();
                            });
                        });
                    }
                    else {
                        zipfile.readEntry();
                    }
                });
                zipfile.on("end", finish);
                zipfile.readEntry();
            });
        });
    }
    /**
     * Parse Word (.docx) files by extracting text from document XML
     */
    static async parseWord(buffer) {
        return new Promise((resolve, reject) => {
            yauzl.fromBuffer(buffer, { lazyEntries: true }, (err, zipfile) => {
                if (err) {
                    resolve({
                        text: "[Word document content - unable to extract]",
                        metadata: {
                            format: 'docx',
                            note: "Word document file could not be parsed",
                            size: buffer.length
                        }
                    });
                    return;
                }
                let documentText = '';
                let totalExtracted = 0;
                let sizeLimitExceeded = false;
                const limit = maxZipExtractedSize();
                let settled = false;
                const finish = () => {
                    if (settled)
                        return;
                    settled = true;
                    if (sizeLimitExceeded) {
                        documentText += SIZE_LIMIT_WARNING;
                    }
                    resolve({
                        text: documentText.trim() || "[No text content found in Word document]",
                        metadata: {
                            format: 'docx',
                            extractedBy: 'yauzl',
                            size: buffer.length,
                            note: "Extracted text content from Word document"
                        }
                    });
                };
                const fail = (error) => {
                    if (settled)
                        return;
                    settled = true;
                    reject(error);
                };
                zipfile.on("error", fail);
                zipfile.on("entry", (entry) => {
                    // Look for the main document XML
                    if (entry.fileName === "word/document.xml") {
                        zipfile.openReadStream(entry, (err, readStream) => {
                            if (err) {
                                fail(err);
                                return;
                            }
                            // Buffers are kept and decoded once: decoding chunk by chunk would corrupt any
                            // multi-byte UTF-8 sequence that straddles a chunk boundary.
                            const chunks = [];
                            readStream.on('error', fail);
                            readStream.on('data', (chunk) => {
                                // Count while streaming so an oversized entry is never fully buffered.
                                totalExtracted += chunk.length;
                                if (totalExtracted > limit) {
                                    sizeLimitExceeded = true;
                                    readStream.destroy();
                                    zipfile.close();
                                    finish();
                                    return;
                                }
                                chunks.push(chunk);
                            });
                            readStream.on('end', () => {
                                if (sizeLimitExceeded)
                                    return;
                                const safeContent = sanitizeXml(Buffer.concat(chunks).toString('utf8'));
                                // Split on paragraph tags to preserve paragraph breaks
                                const paragraphs = safeContent.split(/<w:p[\s>]/);
                                const paragraphTexts = [];
                                for (const paragraph of paragraphs) {
                                    // Extract text from <w:t> tags within each paragraph
                                    const textMatches = paragraph.match(/<w:t[^>]*>([^<]*)<\/w:t>/g);
                                    if (textMatches) {
                                        const paragraphContent = textMatches
                                            .map((match) => match.replace(/<w:t[^>]*>([^<]*)<\/w:t>/, '$1'))
                                            .join('');
                                        if (paragraphContent.trim()) {
                                            paragraphTexts.push(paragraphContent);
                                        }
                                    }
                                }
                                documentText = paragraphTexts.join('\n');
                                zipfile.readEntry();
                            });
                        });
                    }
                    else {
                        zipfile.readEntry();
                    }
                });
                zipfile.on("end", finish);
                zipfile.readEntry();
            });
        });
    }
    /**
     * Parse plain text files
     */
    static parseText(buffer, extension) {
        const text = buffer.toString('utf8');
        return {
            text: text || '[Empty file]',
            metadata: {
                format: `Text File (${extension.toUpperCase()})`,
                encoding: 'utf8',
                size: buffer.length,
                lines: text.split('\n').length,
                characters: text.length
            }
        };
    }
    /**
     * Parse HTML files
     */
    static parseHTML(buffer) {
        try {
            const html = buffer.toString('utf8');
            const root = parseHtml(html);
            // Remove script and style tags
            root.querySelectorAll('script, style, noscript').forEach(el => el.remove());
            // Extract text content
            const text = root.text.replace(/\s+/g, ' ').trim();
            // Extract metadata
            const title = root.querySelector('title')?.text || '';
            const metaTags = {};
            root.querySelectorAll('meta').forEach(meta => {
                const name = meta.getAttribute('name') || meta.getAttribute('property');
                const content = meta.getAttribute('content');
                if (name && content) {
                    metaTags[name] = content;
                }
            });
            return {
                text: text || '[No text content in HTML]',
                metadata: {
                    format: 'HTML Document',
                    extractedBy: 'node-html-parser',
                    title: title,
                    description: metaTags['description'],
                    keywords: metaTags['keywords'],
                    author: metaTags['author'],
                    metaTags: Object.keys(metaTags).length > 0 ? metaTags : undefined,
                    hasImages: root.querySelectorAll('img').length,
                    hasLinks: root.querySelectorAll('a').length,
                    size: buffer.length
                }
            };
        }
        catch (error) {
            throw new Error(`HTML parsing failed: ${error.message}`);
        }
    }
    /**
     * Parse RTF files (basic extraction)
     */
    static parseRTF(buffer) {
        try {
            const rtfContent = buffer.toString('utf8');
            // Basic RTF text extraction (removes control codes)
            let text = rtfContent
                .replace(/\\par\s*/g, '\n') // Convert paragraphs to newlines
                .replace(/\\tab\s*/g, '\t') // Convert tabs
                .replace(/\\'([0-9a-f]{2})/gi, (match, hex) => String.fromCharCode(parseInt(hex, 16))) // Hex chars
                .replace(/\\[a-z]+\d*\s*/gi, '') // Remove other control words
                .replace(/[{}]/g, '') // Remove braces
                .trim();
            return {
                text: text || '[No text content found in RTF]',
                metadata: {
                    format: 'Rich Text Format',
                    size: buffer.length,
                    note: "Basic RTF parsing - formatting information removed"
                }
            };
        }
        catch (error) {
            throw new Error(`RTF parsing failed: ${error.message}`);
        }
    }
    /**
     * Extract text from binary files (fallback)
     */
    static extractTextFromBinary(buffer) {
        // Try to extract any ASCII text from binary files
        const text = buffer.toString('utf8', 0, Math.min(buffer.length, 10000))
            .replace(/[^\x20-\x7E\n\r\t]/g, '') // Keep only printable ASCII
            .trim();
        return {
            text: text || '[Binary file - no extractable text]',
            metadata: {
                format: 'Binary File',
                size: buffer.length,
                note: 'Attempted to extract readable text from binary file'
            }
        };
    }
}
