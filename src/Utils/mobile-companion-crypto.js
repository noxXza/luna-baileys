import { pbkdf2Sync, randomBytes } from 'crypto';
import { hkdfSync } from 'crypto';
import { promisify } from 'util';
import { deflate } from 'zlib';
const deflateAsync = promisify(deflate);

import { Curve, aesEncryptCTR, aesDecryptCTR, hmacSign } from './crypto.js';
import { proto } from '../../WAProto/index.js';

const EMPTY = Buffer.alloc(0);
const PEM_HKDF_INFO = Buffer.from('Canonical Ent Companion Nonce Encrypt');
const PBKDF2_ITERATIONS = 131072;
const PAIRING_AES_KEY_BYTES = 32;
const ADV_PREFIX_ACCOUNT_SIGNATURE = Buffer.from([6, 0]);
const ADV_PREFIX_ACCOUNT_KEY_INDEX = Buffer.from([6, 2]);

const toRawPubKey = (pub) => {
    const b = Buffer.from(pub);
    return b.length === 33 ? b.slice(1) : b;
};

const decodeBase64Url = (input, label) => {
    let s = String(input).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    try {
        return Buffer.from(s, 'base64');
    } catch (e) {
        throw new Error(`${label}: invalid base64url`);
    }
};

export const parseCompanionQr = (qr) => {
    const parts = String(qr).split(',');
    if (parts.length < 5) throw new Error(`companion qr must have at least 5 parts, got ${parts.length}`);
    const platform = parts[parts.length - 1];
    const advSecretB64 = parts[parts.length - 2];
    const identityPubB64 = parts[parts.length - 3];
    const noisePubB64 = parts[parts.length - 4];
    const ref = parts.slice(0, parts.length - 4).join(',');
    return {
        ref,
        noisePublicKey: decodeBase64Url(noisePubB64, 'noisePublicKey'),
        identityPublicKey: decodeBase64Url(identityPubB64, 'identityPublicKey'),
        advSecretKey: decodeBase64Url(advSecretB64, 'advSecretKey'),
        platform
    };
};

export const buildSignedKeyIndexList = async (input) => {
    const details = proto.ADVKeyIndexList.encode({
        rawId: input.rawId,
        timestamp: input.timestampSeconds,
        currentIndex: input.currentIndex,
        validIndexes: [...input.validIndexes]
    }).finish();
    const accountSignature = await signKeyIndexList(details, input.accountIdentityKeyPair);
    return proto.ADVSignedKeyIndexList.encode({ details, accountSignature }).finish();
};

export const signKeyIndexList = async (keyIndexListDetails, accountIdentityKeyPair, isHosted = false) => {
    const prefix = isHosted ? Buffer.from([6, 7]) : ADV_PREFIX_ACCOUNT_KEY_INDEX;
    const message = Buffer.concat([prefix, Buffer.from(keyIndexListDetails)]);
    return Curve.sign(accountIdentityKeyPair.private, message);
};

export const generateDeviceIdentityAccountSignature = async (details, companionIdentityPublicKey, accountIdentityKeyPair, isHosted = false) => {
    const prefix = isHosted ? Buffer.from([6, 5]) : ADV_PREFIX_ACCOUNT_SIGNATURE;
    const message = Buffer.concat([prefix, Buffer.from(details), toRawPubKey(companionIdentityPublicKey)]);
    return Curve.sign(accountIdentityKeyPair.private, message);
};

export const computeAdvIdentityHmac = (secretKey, details) => {
    return hmacSign(Buffer.from(details), Buffer.from(secretKey));
};

export const buildSignedCompanionIdentity = async (input) => {
    const accountSignatureKey = toRawPubKey(input.accountIdentityKeyPair.pubKey);
    const details = proto.ADVDeviceIdentity.encode({
        rawId: input.rawId,
        timestamp: input.timestampSeconds,
        keyIndex: input.keyIndex
    }).finish();
    const accountSignature = await generateDeviceIdentityAccountSignature(
        details,
        input.companionIdentityPublicKey,
        input.accountIdentityKeyPair
    );
    const signedIdentity = proto.ADVSignedDeviceIdentity.encode({
        details,
        accountSignatureKey,
        accountSignature
    }).finish();
    const hmac = computeAdvIdentityHmac(input.advSecretKey, signedIdentity);
    const deviceIdentityBytes = proto.ADVSignedDeviceIdentityHMAC.encode({
        details: signedIdentity,
        hmac
    }).finish();
    const keyIndexListBytes = await buildSignedKeyIndexList({
        accountIdentityKeyPair: input.accountIdentityKeyPair,
        rawId: input.rawId,
        currentIndex: input.keyIndex,
        timestampSeconds: input.timestampSeconds,
        validIndexes: input.validIndexes
    });
    return { deviceIdentityBytes, keyIndexListBytes };
};

export const derivePemKey = (advSecretKey, companionNoisePublicKey) => {
    return Buffer.from(hkdfSync('sha256', Buffer.from(advSecretKey), Buffer.from(companionNoisePublicKey), PEM_HKDF_INFO, 32));
};

export const preparePrimaryHello = async (args) => {
    if (args.wrappedCompanionEphemeralPub.length < 48) {
        throw new Error(`wrapped companion ephemeral pub too short`);
    }
    const codeBytes = Buffer.from(args.pairingCode, 'utf8');
    const salt = args.wrappedCompanionEphemeralPub.subarray(0, 32);
    const counter = args.wrappedCompanionEphemeralPub.subarray(32, 48);
    const companionCipherKey = pbkdf2Sync(codeBytes, Buffer.from(salt), PBKDF2_ITERATIONS, PAIRING_AES_KEY_BYTES, 'sha256');
    const companionEphemeralPub = aesDecryptCTR(
        args.wrappedCompanionEphemeralPub.subarray(48),
        companionCipherKey,
        counter
    );

    const primaryEphemeralKeyPair = Curve.generateKeyPair();
    const salt2 = randomBytes(32);
    const counter2 = randomBytes(16);
    const primaryCipherKey = pbkdf2Sync(codeBytes, salt2, PBKDF2_ITERATIONS, PAIRING_AES_KEY_BYTES, 'sha256');
    const encrypted = aesEncryptCTR(primaryEphemeralKeyPair.public, primaryCipherKey, counter2);
    const sharedEphemeral = Curve.sharedKey(primaryEphemeralKeyPair.private, companionEphemeralPub);

    return {
        primaryEphemeralKeyPair,
        wrappedPrimaryEphemeralPub: Buffer.concat([salt2, counter2, encrypted]),
        sharedEphemeral
    };
};

export const buildHistorySyncBootstrapMessage = async (input = {}) => {
    const historySync = {
        syncType: proto.HistorySync.HistorySyncType.INITIAL_BOOTSTRAP,
        chunkOrder: 0,
        progress: 100,
        conversations: input.conversations ? [...input.conversations] : [],
        pushnames: input.pushnames ? [...input.pushnames] : [],
        phoneNumberToLidMappings: (input.phoneNumberToLidMappings || []).map((m) => ({ pnJid: m.pnJid, lidJid: m.lidJid })),
        ...(input.companionMetaNonce !== undefined ? { companionMetaNonce: input.companionMetaNonce } : {})
    };
    const serialized = proto.HistorySync.encode(historySync).finish();
    const compressed = await deflateAsync(serialized, { level: 1 });
    const payload = new Uint8Array(compressed);
    const message = {
        type: proto.Message.ProtocolMessage.Type.HISTORY_SYNC_NOTIFICATION,
        historySyncNotification: {
            syncType: proto.Message.HistorySyncType.INITIAL_BOOTSTRAP,
            chunkOrder: 0,
            progress: 100,
            initialHistBootstrapInlinePayload: payload
        }
    };
    return { message, payloadBytes: payload.byteLength };
};

export const completePrimaryHandshake = async (args) => {
    const info = Buffer.from('link_code_pairing_key_bundle_encryption_key');
    const key = Buffer.from(hkdfSync('sha256', Buffer.from(args.sharedEphemeral), args.wrappedKeyBundle.subarray(0, 32), info, 32));
    const plaintextBundle = aesDecryptGCM(
        args.wrappedKeyBundle.subarray(44),
        key,
        args.wrappedKeyBundle.subarray(32, 44),
        Buffer.alloc(0)
    );
    const bundleCompanionIdentity = plaintextBundle.subarray(0, 32);
    const bundlePrimaryIdentity = plaintextBundle.subarray(32, 64);
    const bundleSecret = plaintextBundle.subarray(64);

    const rawCompanionIdentity = toRawPubKey(args.companionIdentityPub);
    const rawPrimaryIdentity = toRawPubKey(args.primaryIdentityKeyPair.pubKey);
    if (Buffer.compare(Buffer.from(bundlePrimaryIdentity), rawPrimaryIdentity) !== 0) {
        throw new Error('link-code bundle primary identity mismatch');
    }
    if (Buffer.compare(Buffer.from(bundleCompanionIdentity), rawCompanionIdentity) !== 0) {
        throw new Error('link-code bundle companion identity mismatch');
    }

    const sharedIdentity = Curve.sharedKey(args.primaryIdentityKeyPair.private, rawCompanionIdentity);
    const advSecret = Buffer.from(hkdfSync('sha256', Buffer.concat([Buffer.from(args.sharedEphemeral), Buffer.from(sharedIdentity), Buffer.from(bundleSecret)]), EMPTY, Buffer.from('adv_secret'), 32));
    // Wait zapo uses concatBytes([sharedEphemeral, sharedIdentity, bundleSecret]) as ikm, salt null, info ADV_SECRET. Need exact info string. Baileys messages-recv uses 'adv_secret'. Good.
    return advSecret;
};
