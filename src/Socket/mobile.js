import { randomBytes } from 'crypto';

import { proto } from '../../WAProto/index.js';
import { S_WHATSAPP_NET } from '../WABinary/index.js';
import { getBinaryNodeChild, getAllBinaryNodeChildren, getBinaryNodeChildren } from '../WABinary/index.js';
import {
    parseCompanionQr,
    buildSignedCompanionIdentity,
    buildSignedKeyIndexList,
    preparePrimaryHello,
    completePrimaryHandshake,
    derivePemKey,
    buildHistorySyncBootstrapMessage
} from '../Utils/mobile-companion-crypto.js';
import {
    buildPairDeviceIq,
    buildKeyIndexListPublishIq,
    buildRemoveCompanionDeviceIq,
    buildRemoveAllCompanionDevicesIq,
    buildPrimaryHelloIq
} from './mobile-builders.js';

const PAIR_DEVICE_TIMEOUT_MS = 32000;
const KEY_INDEX_TIMEOUT_MS = 32000;
const REMOVE_DEVICE_TIMEOUT_MS = 32000;
const PRIMARY_HELLO_TIMEOUT_MS = 120000;
const LINK_CODE_FINISH_TIMEOUT_MS = 120000;
const PEM_TTL_SECONDS = 5 * 24 * 60 * 60;

const toRawPubKey = (pub) => {
    const b = Buffer.from(pub);
    return b.length === 33 ? b.slice(1) : b;
};

const getNodeTextContent = (node) => {
    if (!node) return null;
    if (typeof node.content === 'string') return node.content;
    if (Buffer.isBuffer(node.content)) return node.content.toString('utf8');
    if (Array.isArray(node.content)) return node.content.map(getNodeTextContent).filter(Boolean).join('');
    return null;
};

const getNodeBytesContent = (node) => {
    if (!node) return null;
    if (Buffer.isBuffer(node.content)) return new Uint8Array(node.content);
    if (node.content instanceof Uint8Array) return node.content;
    return null;
};

const findNodeChild = (parent, tag) => {
    if (!parent) return undefined;
    const children = Array.isArray(parent.content) ? parent.content : (parent.content ? [parent.content] : []);
    return children.find((c) => c && c.tag === tag);
};

export const makeMobileCoordinator = (sock, config) => {
    const logger = sock.logger || console;
    const ev = sock.ev;
    const query = (node, timeout) => sock.query(node, timeout);
    const authState = sock.authState;
    const persistence = config?.companionHost?.persistence;

    let epoch = null;
    let pendingCompanionHello = null;
    let pendingFinish = null;
    const accountKeyIndexes = new Set([0]);

    const isMobilePrimary = () => (typeof config.isMobilePrimary === 'function' ? config.isMobilePrimary() : !!authState?.creds?.deviceInfo);

    const requirePrimaryIdentityKeyPair = () => {
        if (!isMobilePrimary()) throw new Error('client.mobile requires a mobile-primary session');
        const creds = authState.creds;
        if (!creds?.signedIdentityKey) throw new Error('companion-host requires signedIdentityKey');
        return creds.signedIdentityKey;
    };

    const ensureEpoch = async () => {
        if (epoch) return epoch;
        if (persistence) {
            try {
                const loaded = await persistence.load();
                if (loaded) { epoch = loaded; return epoch; }
            } catch (e) { logger.warn?.({ e }, 'companion epoch load failed'); }
        }
        epoch = { rawId: Math.floor(Math.random() * 0x7fffffff) + 1, currentKeyIndex: 0, companions: [] };
        if (persistence) {
            try { await persistence.save(epoch); } catch (e) { logger.warn?.({ e }, 'companion epoch save failed'); }
        }
        return epoch;
    };

    const persist = async (state) => {
        if (persistence) {
            try { await persistence.save(state); } catch (e) { logger.warn?.({ e }, 'companion persist failed'); }
        }
    };

    const validKeyIndexes = (ep) => {
        const indexes = new Set([0, ...accountKeyIndexes]);
        for (const c of (ep.companions || [])) indexes.add(c.keyIndex);
        return [...indexes].sort((a, b) => a - b);
    };

    const nextKeyIndex = (ep) => Math.max(ep.currentKeyIndex || 0, ...validKeyIndexes(ep)) + 1;

    const emit = (event, payload) => {
        try { ev.emit(event, payload); } catch (e) { logger.warn?.({ e }, 'emit failed'); }
    };

    const buildClientPairingProps = () => ({
        isChatDbLidMigrated: true,
        isSyncdPureLidSession: true,
        isSyncdSnapshotRecoveryEnabled: true
    });

    const handleIncomingNotification = (node) => {
        try {
            if (node?.attrs?.type === 'account_sync') {
                const devices = findNodeChild(node, 'devices');
                if (devices) {
                    const indexes = new Set([0]);
                    for (const child of getBinaryNodeChildren(devices)) {
                        if (child.tag !== 'device') continue;
                        const rawIndex = child.attrs?.['key-index'];
                        const parsed = rawIndex ? parseInt(rawIndex, 10) : NaN;
                        if (Number.isInteger(parsed) && parsed >= 0) indexes.add(parsed);
                    }
                    accountKeyIndexes.clear();
                    for (const i of indexes) accountKeyIndexes.add(i);
                }
            }
            const linkCode = findNodeChild(node, 'link_code_companion_reg');
            if (linkCode) {
                const stage = linkCode.attrs?.stage;
                if (stage === 'companion_hello') {
                    const ref = getNodeTextContent(findNodeChild(linkCode, 'link_code_pairing_ref'));
                    const wrapped = getNodeBytesContent(findNodeChild(linkCode, 'link_code_pairing_wrapped_companion_ephemeral_pub'));
                    const authKey = getNodeBytesContent(findNodeChild(linkCode, 'companion_server_auth_key_pub'));
                    if (ref && wrapped && authKey) {
                        pendingCompanionHello = { ref, wrappedCompanionEphemeralPub: wrapped, companionServerAuthKeyPub: authKey };
                    }
                } else if (stage === 'companion_finish') {
                    const ref = getNodeTextContent(findNodeChild(linkCode, 'link_code_pairing_ref'));
                    const wrappedKeyBundle = getNodeBytesContent(findNodeChild(linkCode, 'link_code_pairing_wrapped_key_bundle'));
                    const companionIdentityPub = getNodeBytesContent(findNodeChild(linkCode, 'companion_identity_public'));
                    if (ref && wrappedKeyBundle && companionIdentityPub && pendingFinish?.ref === ref) {
                        pendingFinish.resolve({ companionIdentityPub, wrappedKeyBundle });
                        pendingFinish = null;
                    }
                }
            }
        } catch (e) { logger.warn?.({ e }, 'handleIncomingNotification failed'); }
        return false;
    };

    const completeLink = async (input) => {
        const accountIdentityKeyPair = requirePrimaryIdentityKeyPair();
        const ep = await ensureEpoch();
        const keyIndex = nextKeyIndex(ep);
        const validIndexes = [...validKeyIndexes(ep), keyIndex].sort((a, b) => a - b);
        const timestampSeconds = Math.floor(Date.now() / 1000);
        const signed = await buildSignedCompanionIdentity({
            accountIdentityKeyPair,
            companionIdentityPublicKey: input.companionIdentityPublicKey,
            advSecretKey: input.advSecretKey,
            rawId: ep.rawId,
            keyIndex,
            timestampSeconds,
            validIndexes
        });
        const iq = buildPairDeviceIq({
            ref: input.ref,
            companionNoisePublicKey: input.companionNoisePublicKey,
            deviceIdentityBytes: signed.deviceIdentityBytes,
            keyIndexListBytes: signed.keyIndexListBytes,
            keyIndexListTimestampSeconds: timestampSeconds,
            clientProps: buildClientPairingProps(),
            pem: config?.companionHost?.includePem ? {
                aesGcmKeyBytes: derivePemKey(input.advSecretKey, input.companionNoisePublicKey),
                ttlSeconds: PEM_TTL_SECONDS
            } : undefined
        });
        const result = await query(iq, PAIR_DEVICE_TIMEOUT_MS);
        // assert no error
        const wrapper = Array.isArray(result?.content) ? result.content[0] : result?.content;
        const deviceNode = findNodeChild(result, 'device') || (wrapper ? findNodeChild(wrapper, 'device') : undefined);
        const deviceJid = deviceNode?.attrs?.jid;
        if (!deviceJid) throw new Error('pair-device result missing <device jid>');
        epoch = {
            rawId: ep.rawId,
            currentKeyIndex: keyIndex,
            companions: [...(ep.companions || []), {
                deviceJid,
                keyIndex,
                companionIdentityPublicKey: input.companionIdentityPublicKey,
                addedAtSeconds: timestampSeconds
            }]
        };
        await persist(epoch);
        emit('companion_host_linked', { deviceJid, keyIndex });
        return { deviceJid, keyIndex };
    };

    const sendHistorySyncBootstrap = async (companionDeviceJid, options = {}) => {
        requirePrimaryIdentityKeyPair();
        const { message, payloadBytes } = await buildHistorySyncBootstrapMessage({
            phoneNumberToLidMappings: options.phoneNumberToLidMappings
        });
        await sock.relayMessage(companionDeviceJid, proto.WebMessageInfo.fromObject({ message: { protocolMessage: message } }), {});
        logger.info?.('companion-host history sync bootstrap sent', { deviceJid: companionDeviceJid, payloadBytes });
    };

    const provisionLinkedCompanion = (deviceJid) => {
        void (async () => {
            let lastError = null;
            for (let attempt = 1; attempt <= 8; attempt++) {
                if (attempt > 1) await new Promise((r) => setTimeout(r, 1500));
                try {
                    await sendHistorySyncBootstrap(deviceJid);
                    logger.info?.('companion provisioned', { deviceJid, attempt });
                    return;
                } catch (error) {
                    lastError = error;
                    logger.debug?.({ deviceJid, attempt, message: error?.message }, 'companion provisioning attempt failed');
                }
            }
            if (lastError) emit('companion_host_error', lastError);
        })();
    };

    const mobile = {
        isMobilePrimary,
        async linkCompanion(qr) {
            try {
                const parsed = parseCompanionQr(qr);
                const accountIdentityKeyPair = requirePrimaryIdentityKeyPair();
                const ep = await ensureEpoch();
                // Need build signed identity; advSecret from qr
                const keyIndex = nextKeyIndex(ep);
                // We'll delegate to completeLink-like flow without provisioning
                const validIndexes = [...validKeyIndexes(ep), keyIndex].sort((a, b) => a - b);
                const timestampSeconds = Math.floor(Date.now() / 1000);
                const signed = await buildSignedCompanionIdentity({
                    accountIdentityKeyPair,
                    companionIdentityPublicKey: parsed.identityPublicKey,
                    advSecretKey: parsed.advSecretKey,
                    rawId: ep.rawId,
                    keyIndex,
                    timestampSeconds,
                    validIndexes
                });
                const iq = buildPairDeviceIq({
                    ref: parsed.ref,
                    companionNoisePublicKey: parsed.noisePublicKey,
                    deviceIdentityBytes: signed.deviceIdentityBytes,
                    keyIndexListBytes: signed.keyIndexListBytes,
                    keyIndexListTimestampSeconds: timestampSeconds,
                    clientProps: buildClientPairingProps(),
                    pem: config?.companionHost?.includePem ? {
                        aesGcmKeyBytes: derivePemKey(parsed.advSecretKey, parsed.noisePublicKey),
                        ttlSeconds: PEM_TTL_SECONDS
                    } : undefined
                });
                const result = await query(iq, PAIR_DEVICE_TIMEOUT_MS);
                const wrapper = Array.isArray(result?.content) ? result.content[0] : result?.content;
                const deviceNode = findNodeChild(result, 'device') || (wrapper ? findNodeChild(wrapper, 'device') : undefined);
                const deviceJid = deviceNode?.attrs?.jid;
                if (!deviceJid) throw new Error('pair-device result missing <device jid>');
                epoch = {
                    rawId: ep.rawId,
                    currentKeyIndex: keyIndex,
                    companions: [...(ep.companions || []), {
                        deviceJid,
                        keyIndex,
                        companionIdentityPublicKey: parsed.identityPublicKey,
                        addedAtSeconds: timestampSeconds
                    }]
                };
                await persist(epoch);
                emit('companion_host_linked', { deviceJid, keyIndex });
                provisionLinkedCompanion(deviceJid);
                return { deviceJid, keyIndex };
            } catch (error) {
                emit('companion_host_error', error);
                throw error;
            }
        },
        async linkCompanionByCode(pairingCode) {
            try {
                const accountIdentityKeyPair = requirePrimaryIdentityKeyPair();
                const hello = pendingCompanionHello;
                if (!hello) throw new Error('no pending companion; a companion must request a pairing code for this account first');
                const prepared = await preparePrimaryHello({
                    pairingCode: String(pairingCode).replace(/[^0-9A-Za-z]/g, '').toUpperCase(),
                    wrappedCompanionEphemeralPub: hello.wrappedCompanionEphemeralPub
                });
                let finishResolve, finishReject;
                const finishPromise = new Promise((resolve, reject) => { finishResolve = resolve; finishReject = reject; });
                pendingFinish = { ref: hello.ref, resolve: finishResolve };
                const timeout = setTimeout(() => {
                    if (pendingFinish?.ref === hello.ref) {
                        pendingFinish = null;
                        finishReject(new Error('link-code companion_finish timed out'));
                    }
                }, LINK_CODE_FINISH_TIMEOUT_MS);
                let finish;
                try {
                    const helloResult = await query(buildPrimaryHelloIq({
                        ref: hello.ref,
                        wrappedPrimaryEphemeralPub: prepared.wrappedPrimaryEphemeralPub,
                        primaryIdentityPub: toRawPubKey(accountIdentityKeyPair.pubKey)
                    }), PRIMARY_HELLO_TIMEOUT_MS);
                    finish = await finishPromise;
                } finally {
                    clearTimeout(timeout);
                    if (pendingFinish?.ref === hello.ref) pendingFinish = null;
                }
                const advSecretKey = await completePrimaryHandshake({
                    sharedEphemeral: prepared.sharedEphemeral,
                    wrappedKeyBundle: finish.wrappedKeyBundle,
                    companionIdentityPub: finish.companionIdentityPub,
                    primaryIdentityKeyPair: accountIdentityKeyPair
                });
                pendingCompanionHello = null;
                // reuse linkCompanion completeLink logic by calling linkCompanion? Instead inline pair-device
                const ep = await ensureEpoch();
                const keyIndex = nextKeyIndex(ep);
                const validIndexes = [...validKeyIndexes(ep), keyIndex].sort((a, b) => a - b);
                const timestampSeconds = Math.floor(Date.now() / 1000);
                const signed = await buildSignedCompanionIdentity({
                    accountIdentityKeyPair,
                    companionIdentityPublicKey: toRawPubKey(finish.companionIdentityPub),
                    advSecretKey,
                    rawId: ep.rawId,
                    keyIndex,
                    timestampSeconds,
                    validIndexes
                });
                const iq = buildPairDeviceIq({
                    ref: hello.ref,
                    companionNoisePublicKey: hello.companionServerAuthKeyPub,
                    deviceIdentityBytes: signed.deviceIdentityBytes,
                    keyIndexListBytes: signed.keyIndexListBytes,
                    keyIndexListTimestampSeconds: timestampSeconds,
                    clientProps: buildClientPairingProps()
                });
                const result = await query(iq, PAIR_DEVICE_TIMEOUT_MS);
                const wrapper = Array.isArray(result?.content) ? result.content[0] : result?.content;
                const deviceNode = findNodeChild(result, 'device') || (wrapper ? findNodeChild(wrapper, 'device') : undefined);
                const deviceJid = deviceNode?.attrs?.jid;
                if (!deviceJid) throw new Error('pair-device result missing <device jid>');
                epoch = {
                    rawId: ep.rawId,
                    currentKeyIndex: keyIndex,
                    companions: [...(ep.companions || []), {
                        deviceJid,
                        keyIndex,
                        companionIdentityPublicKey: toRawPubKey(finish.companionIdentityPub),
                        addedAtSeconds: timestampSeconds
                    }]
                };
                await persist(epoch);
                emit('companion_host_linked', { deviceJid, keyIndex });
                provisionLinkedCompanion(deviceJid);
                return { deviceJid, keyIndex };
            } catch (error) {
                emit('companion_host_error', error);
                throw error;
            }
        },
        async revokeCompanion(deviceJid, reason = 'user_initiated') {
            requirePrimaryIdentityKeyPair();
            const ep = await ensureEpoch();
            if (!(ep.companions || []).some((c) => c.deviceJid === deviceJid)) {
                throw new Error(`companion ${deviceJid} is not tracked by this primary`);
            }
            await query(buildRemoveCompanionDeviceIq({ deviceJid, reason }), REMOVE_DEVICE_TIMEOUT_MS);
            epoch = {
                rawId: ep.rawId,
                currentKeyIndex: ep.currentKeyIndex,
                companions: (ep.companions || []).filter((c) => c.deviceJid !== deviceJid)
            };
            await persist(epoch);
            emit('companion_host_revoked', { deviceJid });
            try { await mobile.publishKeyIndexList(); } catch (e) { logger.warn?.({ e }, 'republish failed'); }
        },
        async revokeAllCompanions(reason = 'user_initiated', options = {}) {
            requirePrimaryIdentityKeyPair();
            const ep = await ensureEpoch();
            await query(buildRemoveAllCompanionDevicesIq({ reason, excludeHostedCompanion: options.excludeHostedCompanion }), REMOVE_DEVICE_TIMEOUT_MS);
            if (!options.excludeHostedCompanion) {
                epoch = { rawId: ep.rawId, currentKeyIndex: ep.currentKeyIndex, companions: [] };
                await persist(epoch);
            }
            emit('companion_host_revoked', { deviceJid: 'all' });
        },
        async listCompanions() {
            const ep = await ensureEpoch();
            return ep.companions || [];
        },
        async reconcileCompanions() {
            return [];
        },
        async publishKeyIndexList() {
            const accountIdentityKeyPair = requirePrimaryIdentityKeyPair();
            const ep = await ensureEpoch();
            const timestampSeconds = Math.floor(Date.now() / 1000);
            const validIndexes = validKeyIndexes(ep);
            const currentIndex = validIndexes[validIndexes.length - 1] || 0;
            const keyIndexListBytes = await buildSignedKeyIndexList({
                accountIdentityKeyPair,
                rawId: ep.rawId,
                currentIndex,
                timestampSeconds,
                validIndexes
            });
            await query(buildKeyIndexListPublishIq({ keyIndexListBytes, timestampSeconds }), KEY_INDEX_TIMEOUT_MS);
        },
        sendHistorySyncBootstrap,
        handleIncomingNotification: handleIncomingNotification
    };

    return mobile;
};
