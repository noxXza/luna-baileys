import { Boom } from '@hapi/boom';
import { createHash, randomUUID } from 'crypto';
import { proto } from '../../WAProto/index.js';
import { KEY_BUNDLE_TYPE, WA_ADV_ACCOUNT_SIG_PREFIX, WA_ADV_DEVICE_SIG_PREFIX, WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX } from '../Defaults/index.js';
import { getBinaryNodeChild, jidDecode, S_WHATSAPP_NET } from '../WABinary/index.js';
import { Curve, hmacSign } from './crypto.js';
import { encodeBigEndian } from './generics.js';
import { createSignalIdentity } from './signal.js';
const getUserAgent = (config) => {
    return {
        appVersion: {
            primary: config.version[0],
            secondary: config.version[1],
            tertiary: config.version[2]
        },
        platform: config.browser[1].toLocaleLowerCase().includes('android')
            ? proto.ClientPayload.UserAgent.Platform.ANDROID
            : proto.ClientPayload.UserAgent.Platform.WEB,
        releaseChannel: proto.ClientPayload.UserAgent.ReleaseChannel.RELEASE,
        osVersion: '0.1',
        device: 'Desktop',
        osBuildNumber: '0.1',
        localeLanguageIso6391: 'en',
        mnc: '000',
        mcc: '000',
        localeCountryIso31661Alpha2: config.countryCode
    };
};
const PLATFORM_MAP = {
    'Mac OS': proto.ClientPayload.WebInfo.WebSubPlatform.DARWIN,
    Windows: proto.ClientPayload.WebInfo.WebSubPlatform.WIN32
};
const getWebInfo = (config) => {
    let webSubPlatform = proto.ClientPayload.WebInfo.WebSubPlatform.WEB_BROWSER;
    if (config.syncFullHistory &&
        PLATFORM_MAP[config.browser[0]] &&
        config.browser[1] === 'Desktop') {
        webSubPlatform = PLATFORM_MAP[config.browser[0]];
    }
    return { webSubPlatform };
};
const getClientPayload = (config) => {
    const payload = {
        connectType: proto.ClientPayload.ConnectType.WIFI_UNKNOWN,
        connectReason: proto.ClientPayload.ConnectReason.USER_ACTIVATED,
        userAgent: getUserAgent(config)
    };
    if (!config.browser[1].toLocaleLowerCase().includes('android')) {
        payload.webInfo = getWebInfo(config);
    }
    if (config.pushName) {
        payload.pushName = config.pushName;
    }
    return payload;
};
const buildMobileLoginPayload = (userJid, config, deviceInfo) => {
    if (!deviceInfo) {
        throw new Boom('mobile login requires deviceInfo', { statusCode: 400 });
    }
    const { user, device } = jidDecode(userJid);
    const username = +user;
    if (!Number.isSafeInteger(username) || username <= 0) {
        throw new Boom('mobile login requires a valid numeric username', { statusCode: 400 });
    }
    const parseAppVersion = (version) => {
        const parts = String(version || '').split('.');
        const at = (i) => {
            const n = Number(parts[i]);
            return Number.isFinite(n) ? n : undefined;
        };
        return { primary: at(0) ?? 2, secondary: at(1) ?? 0, tertiary: at(2) ?? 0, quaternary: at(3) };
    };
    const version = parseAppVersion(deviceInfo.appVersion);
    const isIos = deviceInfo.os === 'ios';
    const platform = isIos
        ? (deviceInfo.business ? proto.ClientPayload.UserAgent.Platform.SMB_IOS : proto.ClientPayload.UserAgent.Platform.IOS)
        : (deviceInfo.business ? proto.ClientPayload.UserAgent.Platform.SMB_ANDROID : proto.ClientPayload.UserAgent.Platform.ANDROID);
    const distributionChannelMap = {
        website: proto.ClientPayload.UserAgent.DistributionChannel.WEBSITE,
        testflight: proto.ClientPayload.UserAgent.DistributionChannel.TESTFLIGHT,
        internal: proto.ClientPayload.UserAgent.DistributionChannel.INTERNAL,
        appstore: proto.ClientPayload.UserAgent.DistributionChannel.APPSTORE
    };
    const userAgent = {
        platform,
        releaseChannel: proto.ClientPayload.UserAgent.ReleaseChannel.RELEASE,
        appVersion: version,
        osVersion: deviceInfo.osVersion,
        manufacturer: deviceInfo.manufacturer,
        device: deviceInfo.device,
        osBuildNumber: deviceInfo.osBuildNumber,
        phoneId: deviceInfo.phoneId || randomUUID(),
        localeLanguageIso6391: deviceInfo.localeLanguageIso6391 || 'en',
        localeCountryIso31661Alpha2: deviceInfo.localeCountryIso31661Alpha2 || 'US',
        deviceType: proto.ClientPayload.UserAgent.DeviceType.PHONE,
        deviceModelType: deviceInfo.deviceModelType
    };
    if (isIos) {
        userAgent.distributionChannel = distributionChannelMap[deviceInfo.distributionChannel || 'appstore'] || distributionChannelMap.appstore;
    } else {
        userAgent.mcc = deviceInfo.mcc || '000';
        userAgent.mnc = deviceInfo.mnc || '000';
        userAgent.deviceBoard = deviceInfo.deviceBoard;
    }
    const payload = {
        passive: config.mobileTransport?.passive === true || deviceInfo.passive === true,
        pull: true,
        product: proto.ClientPayload.Product.WHATSAPP,
        connectType: proto.ClientPayload.ConnectType.CELLULAR_UNKNOWN,
        connectReason: proto.ClientPayload.ConnectReason.USER_ACTIVATED,
        userAgent,
        username,
        device: device || 0,
        lidDbMigrated: false,
        pushName: config.mobileTransport?.pushName || config.pushName
    };
    if (config.mobileTransport?.yearClass) payload.yearClass = config.mobileTransport.yearClass;
    if (config.mobileTransport?.memClass) payload.memClass = config.mobileTransport.memClass;
    return proto.ClientPayload.fromObject(payload);
};

export const generateLoginNode = (userJid, config, deviceInfo) => {
    if (deviceInfo || config?.mobileDeviceInfo || config?.mobileTransport?.deviceInfo) {
        const di = deviceInfo || config?.mobileDeviceInfo || config?.mobileTransport?.deviceInfo;
        return buildMobileLoginPayload(userJid, { ...config, mobileTransport: config?.mobileTransport }, di);
    }
    const { user, device } = jidDecode(userJid);
    const payload = {
        ...getClientPayload(config),
        passive: true,
        pull: true,
        username: +user,
        device: device,

        lidDbMigrated: false
    };
    return proto.ClientPayload.fromObject(payload);
};
const getPlatformType = (platform) => {
    const platformType = platform.toUpperCase();
    if (platformType === 'ANDROID') {
        return proto.DeviceProps.PlatformType.ANDROID_PHONE;
    }
    return (proto.DeviceProps.PlatformType[platformType] ||
        proto.DeviceProps.PlatformType.CHROME);
};
export const generateRegistrationNode = ({ registrationId, signedPreKey, signedIdentityKey }, config) => {

    const appVersionBuf = createHash('md5')
        .update(config.version.join('.'))
        .digest();
    const companion = {
        os: config.browser[0],
        platformType: getPlatformType(config.browser[1]),
        requireFullSync: config.syncFullHistory,
        historySyncConfig: {
            storageQuotaMb: 10240,
            inlineInitialPayloadInE2EeMsg: true,
            recentSyncDaysLimit: undefined,
            supportCallLogHistory: false,
            supportBotUserAgentChatHistory: true,
            supportCagReactionsAndPolls: true,
            supportBizHostedMsg: true,
            supportRecentSyncChunkMessageCountTuning: true,
            supportHostedGroupMsg: true,
            supportFbidBotChatHistory: true,
            supportAddOnHistorySyncMigration: undefined,
            supportMessageAssociation: true,
            supportGroupHistory: false,
            onDemandReady: undefined,
            supportGuestChat: undefined
        },
        version: {
            primary: 10,
            secondary: 15,
            tertiary: 7
        }
    };
    const companionProto = proto.DeviceProps.encode(companion).finish();
    const registerPayload = {
        ...getClientPayload(config),
        passive: false,
        pull: false,
        devicePairingData: {
            buildHash: appVersionBuf,
            deviceProps: companionProto,
            eRegid: encodeBigEndian(registrationId),
            eKeytype: KEY_BUNDLE_TYPE,
            eIdent: signedIdentityKey.public,
            eSkeyId: encodeBigEndian(signedPreKey.keyId, 3),
            eSkeyVal: signedPreKey.keyPair.public,
            eSkeySig: signedPreKey.signature
        }
    };
    return proto.ClientPayload.fromObject(registerPayload);
};
export const configureSuccessfulPairing = (stanza, { advSecretKey, signedIdentityKey, signalIdentities }) => {
    const msgId = stanza.attrs.id;
    const pairSuccessNode = getBinaryNodeChild(stanza, 'pair-success');
    const deviceIdentityNode = getBinaryNodeChild(pairSuccessNode, 'device-identity');
    const platformNode = getBinaryNodeChild(pairSuccessNode, 'platform');
    const deviceNode = getBinaryNodeChild(pairSuccessNode, 'device');
    const businessNode = getBinaryNodeChild(pairSuccessNode, 'biz');
    if (!deviceIdentityNode || !deviceNode) {
        throw new Boom('Missing device-identity or device in pair success node', { data: stanza });
    }
    const bizName = businessNode?.attrs.name;
    const jid = deviceNode.attrs.jid;
    const lid = deviceNode.attrs.lid;
    const { details, hmac, accountType } = proto.ADVSignedDeviceIdentityHMAC.decode(deviceIdentityNode.content);
    let hmacPrefix = Buffer.from([]);
    if (accountType !== undefined && accountType === proto.ADVEncryptionType.HOSTED) {
        hmacPrefix = WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX;
    }
    const advSign = hmacSign(Buffer.concat([hmacPrefix, details]), Buffer.from(advSecretKey, 'base64'));
    if (Buffer.compare(hmac, advSign) !== 0) {
        throw new Boom('Invalid account signature');
    }
    const account = proto.ADVSignedDeviceIdentity.decode(details);
    const { accountSignatureKey, accountSignature, details: deviceDetails } = account;
    const deviceIdentity = proto.ADVDeviceIdentity.decode(deviceDetails);
    const accountSignaturePrefix = deviceIdentity.deviceType === proto.ADVEncryptionType.HOSTED
        ? WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX
        : WA_ADV_ACCOUNT_SIG_PREFIX;
    const accountMsg = Buffer.concat([accountSignaturePrefix, deviceDetails, signedIdentityKey.public]);
    if (!Curve.verify(accountSignatureKey, accountMsg, accountSignature)) {
        throw new Boom('Failed to verify account signature');
    }
    const deviceMsg = Buffer.concat([
        WA_ADV_DEVICE_SIG_PREFIX,
        deviceDetails,
        signedIdentityKey.public,
        accountSignatureKey
    ]);
    account.deviceSignature = Curve.sign(signedIdentityKey.private, deviceMsg);
    const identity = createSignalIdentity(lid, accountSignatureKey);
    const accountEnc = encodeSignedDeviceIdentity(account, false);
    const reply = {
        tag: 'iq',
        attrs: {
            to: S_WHATSAPP_NET,
            type: 'result',
            id: msgId
        },
        content: [
            {
                tag: 'pair-device-sign',
                attrs: {},
                content: [
                    {
                        tag: 'device-identity',
                        attrs: { 'key-index': deviceIdentity.keyIndex.toString() },
                        content: accountEnc
                    }
                ]
            }
        ]
    };
    const authUpdate = {
        account,
        me: { id: jid, name: bizName, lid },
        signalIdentities: [...(signalIdentities || []), identity],
        platform: platformNode?.attrs.name
    };
    return {
        creds: authUpdate,
        reply
    };
};
export const encodeSignedDeviceIdentity = (account, includeSignatureKey) => {
    account = { ...account };

    if (!includeSignatureKey || !account.accountSignatureKey?.length) {
        account.accountSignatureKey = null;
    }
    return proto.ADVSignedDeviceIdentity.encode(account).finish();
};
