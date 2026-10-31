import { S_WHATSAPP_NET } from '../WABinary/index.js';
import { getBinaryNodeChild, getBinaryNodeChildren } from '../WABinary/index.js';

const WA_EMAIL_XMLNS = 'urn:xmpp:whatsapp:account';
const WA_EMAIL_TAGS = {
    EMAIL: 'email',
    EMAIL_ADDRESS: 'email_address',
    VERIFY_EMAIL: 'verify_email',
    CONFIRM_EMAIL: 'confirm_email',
    CONTEXT: 'context',
    CODE: 'code',
    LG: 'lg',
    LC: 'lc',
    AUTO_VERIFY: 'auto_verify',
    CONFIRMED: 'confirmed'
};
const WA_EMAIL_LIMITS = {
    EMAIL_MAX_LENGTH: 320,
    CODE_LENGTH: 6,
    LOCALE_MIN_LENGTH: 2,
    LOCALE_MAX_LENGTH: 3
};

const getText = (node) => {
    if (!node) return null;
    if (typeof node.content === 'string') return node.content;
    if (Buffer.isBuffer(node.content)) return node.content.toString('utf8');
    if (Array.isArray(node.content)) {
        return node.content.map(getText).filter(Boolean).join('');
    }
    return null;
};

const parseEmailStatus = (result) => {
    const emailNode = getBinaryNodeChild(result, WA_EMAIL_TAGS.EMAIL);
    if (!emailNode) return { email: null, verified: false, confirmed: false };
    const verifiedAttr = emailNode.attrs?.verified;
    const addressNode = getBinaryNodeChild(emailNode, WA_EMAIL_TAGS.EMAIL_ADDRESS);
    const confirmedNode = getBinaryNodeChild(emailNode, WA_EMAIL_TAGS.CONFIRMED);
    return {
        email: addressNode ? (getText(addressNode) ?? null) : null,
        verified: verifiedAttr === 'true',
        confirmed: confirmedNode ? getText(confirmedNode) === 'true' : false
    };
};

const parseVerifyCodeResult = (result) => {
    const emailNode = getBinaryNodeChild(result, WA_EMAIL_TAGS.EMAIL);
    if (!emailNode) return { verified: false, autoVerifyFailed: false, email: null };
    const doVerify = emailNode.attrs?.do_verify;
    const autoVerifyNode = getBinaryNodeChild(emailNode, WA_EMAIL_TAGS.AUTO_VERIFY);
    const addressNode = getBinaryNodeChild(emailNode, WA_EMAIL_TAGS.EMAIL_ADDRESS);
    return {
        verified: doVerify === 'true',
        autoVerifyFailed: autoVerifyNode ? getText(autoVerifyNode) === 'fail' : false,
        email: addressNode ? (getText(addressNode) ?? null) : null
    };
};

export const makeEmailCoordinator = (query, isMobilePrimaryFn) => {
    const ensureMobile = () => {
        if (typeof isMobilePrimaryFn === 'function' && !isMobilePrimaryFn()) {
            throw new Error('email binding is mobile-only');
        }
    };
    return {
        getStatus: async () => {
            ensureMobile();
            const result = await query({
                tag: 'iq',
                attrs: { to: S_WHATSAPP_NET, type: 'get', xmlns: WA_EMAIL_XMLNS },
                content: [{ tag: WA_EMAIL_TAGS.EMAIL, attrs: {} }]
            });
            return parseEmailStatus(result);
        },
        setEmail: async (email, context) => {
            ensureMobile();
            if (!email || email.length === 0 || email.length > WA_EMAIL_LIMITS.EMAIL_MAX_LENGTH) {
                throw new Error(`email length must be between 1 and ${WA_EMAIL_LIMITS.EMAIL_MAX_LENGTH} chars`);
            }
            const emailChildren = [];
            if (context !== undefined) emailChildren.push({ tag: WA_EMAIL_TAGS.CONTEXT, attrs: {}, content: context });
            emailChildren.push({ tag: WA_EMAIL_TAGS.EMAIL_ADDRESS, attrs: {}, content: email });
            const result = await query({
                tag: 'iq',
                attrs: { to: S_WHATSAPP_NET, type: 'set', xmlns: WA_EMAIL_XMLNS },
                content: [{ tag: WA_EMAIL_TAGS.EMAIL, attrs: {}, content: emailChildren }]
            });
            return parseEmailStatus(result);
        },
        requestVerificationCode: async (input) => {
            ensureMobile();
            const { languageCode, localeCode } = input || {};
            if (!languageCode || languageCode.length < WA_EMAIL_LIMITS.LOCALE_MIN_LENGTH || languageCode.length > WA_EMAIL_LIMITS.LOCALE_MAX_LENGTH) {
                throw new Error(`languageCode must be between ${WA_EMAIL_LIMITS.LOCALE_MIN_LENGTH} and ${WA_EMAIL_LIMITS.LOCALE_MAX_LENGTH} chars`);
            }
            if (!localeCode || localeCode.length < WA_EMAIL_LIMITS.LOCALE_MIN_LENGTH || localeCode.length > WA_EMAIL_LIMITS.LOCALE_MAX_LENGTH) {
                throw new Error(`localeCode must be between ${WA_EMAIL_LIMITS.LOCALE_MIN_LENGTH} and ${WA_EMAIL_LIMITS.LOCALE_MAX_LENGTH} chars`);
            }
            const result = await query({
                tag: 'iq',
                attrs: { to: S_WHATSAPP_NET, type: 'set', xmlns: WA_EMAIL_XMLNS },
                content: [{
                    tag: WA_EMAIL_TAGS.VERIFY_EMAIL,
                    attrs: {},
                    content: [
                        { tag: WA_EMAIL_TAGS.LG, attrs: {}, content: languageCode },
                        { tag: WA_EMAIL_TAGS.LC, attrs: {}, content: localeCode }
                    ]
                }]
            });
            return result;
        },
        verifyCode: async (code) => {
            ensureMobile();
            if (!code || code.length !== WA_EMAIL_LIMITS.CODE_LENGTH) {
                throw new Error(`verification code must be exactly ${WA_EMAIL_LIMITS.CODE_LENGTH} chars`);
            }
            const result = await query({
                tag: 'iq',
                attrs: { to: S_WHATSAPP_NET, type: 'set', xmlns: WA_EMAIL_XMLNS },
                content: [{
                    tag: WA_EMAIL_TAGS.VERIFY_EMAIL,
                    attrs: {},
                    content: [{ tag: WA_EMAIL_TAGS.CODE, attrs: {}, content: code }]
                }]
            });
            return parseVerifyCodeResult(result);
        },
        confirm: async (context) => {
            ensureMobile();
            const children = context !== undefined ? [{ tag: WA_EMAIL_TAGS.CONTEXT, attrs: {}, content: context }] : undefined;
            const node = {
                tag: 'iq',
                attrs: { to: S_WHATSAPP_NET, type: 'set', xmlns: WA_EMAIL_XMLNS },
                content: [{
                    tag: WA_EMAIL_TAGS.CONFIRM_EMAIL,
                    attrs: {},
                    ...(children !== undefined ? { content: children } : {})
                }]
            };
            await query(node);
        }
    };
};