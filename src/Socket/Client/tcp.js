import { EventEmitter } from 'events';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const nodeNet = require('node:net');

import { AbstractSocketClient } from './types.js';

// Simple TCP adapter mirroring WaMobileTcpSocket from zapo-js, adapted to Baileys.
export class TcpSocketClient extends AbstractSocketClient {
    constructor(url, config) {
        super(url, config);
        this.socket = null;
        this.readyState = 0; // CONNECTING
        this.closedCode = 1000;
        this.closedReason = '';
        this.closedClean = true;
        this.forceCloseTimer = null;
        this.proxyResponse = Buffer.alloc(0);
        this.tunnelReady = true;
    }

    get isOpen() {
        return this.socket && this.readyState === 1; // OPEN
    }
    get isClosed() {
        return this.socket === null || this.readyState === 3; // CLOSED
    }
    get isClosing() {
        return this.readyState === 2; // CLOSING
    }
    get isConnecting() {
        return this.readyState === 0;
    }

    _parseUrl() {
        let work = String(this.url);
        if (work.startsWith('tcp://')) work = work.slice('tcp://'.length);
        const q = work.indexOf('?');
        if (q >= 0) work = work.slice(0, q);
        const slash = work.indexOf('/');
        if (slash >= 0) work = work.slice(0, slash);
        const colon = work.lastIndexOf(':');
        const host = colon === -1 ? work : work.slice(0, colon);
        const port = colon === -1 ? 443 : Number(work.slice(colon + 1));
        return { host, port };
    }

    connect() {
        if (this.socket) return;
        const { host, port } = this._parseUrl();
        const agent = this.config?.agent;
        let proxy = null;
        if (agent && typeof agent === 'object') {
            // support http-proxy-agent-like
            try {
                if (agent.proxy) proxy = agent.proxy;
            } catch { }
        }
        // Baileys passes agent directly; support object with hostname/port
        if (!proxy && agent && (agent.hostname || agent.host) && agent.port) {
            proxy = agent;
        }

        const targetHost = host;
        const targetPort = port;

        if (proxy) {
            const ph = proxy.hostname || proxy.host;
            const pp = proxy.port;
            this.socket = nodeNet.connect({ host: ph, port: pp });
        } else {
            this.socket = nodeNet.connect({ host: targetHost, port: targetPort });
        }

        let tunnelReady = !proxy;
        let proxyBuf = Buffer.alloc(0);

        this.socket.on('connect', () => {
            if (this.readyState !== 0) return;
            if (proxy) {
                const authority = `${targetHost}:${targetPort}`;
                const lines = [
                    `CONNECT ${authority} HTTP/1.1`,
                    `Host: ${authority}`,
                    'Proxy-Connection: Keep-Alive'
                ];
                if (proxy.authorization) lines.push(`Proxy-Authorization: ${proxy.authorization}`);
                this.socket.write(lines.join('\r\n') + '\r\n\r\n');
                return;
            }
            this._markOpen();
        });

        this.socket.on('data', (chunk) => {
            if (!tunnelReady && proxy) {
                proxyBuf = Buffer.concat([proxyBuf, chunk]);
                const headerEnd = this._findHeaderEnd(proxyBuf);
                if (headerEnd === -1) {
                    if (proxyBuf.length > 65536) {
                        this.socket.destroy(new Error('proxy headers too large'));
                    }
                    return;
                }
                const statusLine = proxyBuf.slice(0, headerEnd).toString('utf8').split('\r\n')[0];
                if (!/^HTTP\/1\.[01] 2\d\d(?:\s|$)/.test(statusLine)) {
                    this.socket.destroy(new Error(`proxy CONNECT failed (${statusLine})`));
                    return;
                }
                const remaining = proxyBuf.slice(headerEnd + 4);
                proxyBuf = Buffer.alloc(0);
                tunnelReady = true;
                this._markOpen();
                if (remaining.length > 0) this.emit('message', remaining);
                return;
            }
            this.emit('message', Buffer.from(chunk));
        });

        this.socket.on('error', (err) => {
            this.closedClean = false;
            this.closedReason = err?.message || String(err);
            this.emit('error', err);
        });

        this.socket.on('close', (hadError) => {
            this.readyState = 3;
            if (this.forceCloseTimer) {
                clearTimeout(this.forceCloseTimer);
                this.forceCloseTimer = null;
            }
            if (hadError) this.closedClean = false;
            this.emit('close', this.closedCode, this.closedReason, this.closedClean);
        });
    }

    _markOpen() {
        if (this.readyState !== 0) return;
        this.readyState = 1;
        this.emit('open');
    }

    _findHeaderEnd(buf) {
        for (let i = 3; i < buf.length; i++) {
            if (buf[i - 3] === 13 && buf[i - 2] === 10 && buf[i - 1] === 13 && buf[i] === 10) return i - 3;
        }
        return -1;
    }

    async close() {
        if (this.readyState === 3) return;
        this.readyState = 2;
        this.socket?.end();
        this.forceCloseTimer = setTimeout(() => {
            this.forceCloseTimer = null;
            if (this.readyState !== 3) this.socket?.destroy();
        }, 5000);
        if (this.forceCloseTimer && typeof this.forceCloseTimer.unref === 'function') this.forceCloseTimer.unref();
    }

    send(data, cb) {
        if (this.readyState !== 1) {
            if (typeof cb === 'function') cb(new Error('socket not open'));
            return false;
        }
        let bytes;
        if (typeof data === 'string') bytes = Buffer.from(data, 'utf8');
        else if (data instanceof Uint8Array) bytes = Buffer.from(data);
        else if (data instanceof ArrayBuffer) bytes = Buffer.from(data);
        else bytes = Buffer.from(data);
        this.socket.write(bytes, (err) => {
            if (typeof cb === 'function') cb(err);
        });
        return true;
    }
}

export * from './tcp.js';
