import { proto } from '../../WAProto/index.js';
import { S_WHATSAPP_NET } from '../WABinary/index.js';

const buildIqNode = (type, to, xmlns, content) => ({
    tag: 'iq',
    attrs: { to: to || S_WHATSAPP_NET, type, xmlns },
    content
});

export const buildPairDeviceIq = (input) => {
    const children = [
        { tag: 'ref', attrs: {}, content: input.ref },
        { tag: 'pub-key', attrs: {}, content: input.companionNoisePublicKey },
        { tag: 'device-identity', attrs: {}, content: input.deviceIdentityBytes },
        { tag: 'key-index-list', attrs: { ts: String(input.keyIndexListTimestampSeconds) }, content: input.keyIndexListBytes }
    ];
    if (input.clientProps) {
        children.push({
            tag: 'client-props',
            attrs: {},
            content: proto.ClientPairingProps.encode({
                isChatDbLidMigrated: input.clientProps.isChatDbLidMigrated,
                isSyncdPureLidSession: input.clientProps.isSyncdPureLidSession,
                isSyncdSnapshotRecoveryEnabled: input.clientProps.isSyncdSnapshotRecoveryEnabled
            }).finish()
        });
    }
    if (input.pem) {
        children.push({
            tag: 'pem',
            attrs: { version: '1', algorithm: 'rsa2048' },
            content: [
                { tag: 'pem', attrs: {}, content: input.pem.aesGcmKeyBytes },
                { tag: 'ttl', attrs: { ts_s: String(input.pem.ttlSeconds) } },
                { tag: 'key_id', attrs: {}, content: '1' }
            ]
        });
    }
    return buildIqNode('set', S_WHATSAPP_NET, 'md', [
        { tag: 'pair-device', attrs: {}, content: children }
    ]);
};

export const buildKeyIndexListPublishIq = (input) => buildIqNode('set', S_WHATSAPP_NET, 'md', [
    { tag: 'key-index-list', attrs: { ts: String(input.timestampSeconds) }, content: input.keyIndexListBytes }
]);

export const buildRemoveCompanionDeviceIq = (input) => buildIqNode('set', S_WHATSAPP_NET, 'md', [
    { tag: 'remove-companion-device', attrs: { jid: input.deviceJid, reason: input.reason } }
]);

export const buildRemoveAllCompanionDevicesIq = (input) => {
    const attrs = { all: 'true', reason: input.reason };
    if (input.excludeHostedCompanion) attrs.exclude_hosted_companion = 'true';
    return buildIqNode('set', S_WHATSAPP_NET, 'md', [
        { tag: 'remove-companion-device', attrs }
    ]);
};

export const buildPrimaryHelloIq = (input) => buildIqNode('set', S_WHATSAPP_NET, 'md', [
    {
        tag: 'link_code_companion_reg',
        attrs: { stage: 'primary_hello' },
        content: [
            { tag: 'link_code_pairing_wrapped_primary_ephemeral_pub', attrs: {}, content: input.wrappedPrimaryEphemeralPub },
            { tag: 'primary_identity_pub', attrs: {}, content: input.primaryIdentityPub },
            { tag: 'link_code_pairing_ref', attrs: {}, content: input.ref }
        ]
    }
]);


