
import { Request, Response } from "express";
import axios from "axios";
import logger from "../utils/logger";
import { constants, randomBytes, publicEncrypt, createCipheriv } from 'crypto';
import { pack } from 'python-struct';
import * as OTPAuth from "otpauth";

async function pwd_key_fetch() {
    try {
        const config = {
            method: 'get',
            url: 'https://graph.facebook.com/pwd_key_fetch?app_version=412474635&fb_api_caller_class=FBPasswordEncryptionKeyFetchRequest&fb_api_req_friendly_name=FBPasswordEncryptionKeyFetchRequest:networkRequest&flow=controller_initialization&format=json&locale=vi_VN&pretty=0&sdk=ios&sdk_version=3&version=2',
            headers: {
                'x-fb-privacy-context': '0xf0000000b659eb4a',
                'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/17H35 [FBAN/FBIOS;FBAV/390.1.0.38.101;FBBV/412474635;FBDV/iPhone10,2;FBMD/iPhone;FBSN/iOS;FBSV/13.7;FBSS/3;FBID/phone;FBLC/vi_VN;FBOP/5;FBRV/0]',
                'x-fb-connection-type': 'wifi.CTRadioAccessTechnologyLTE',
                'x-fb-sim-hni': '45202',
                'authorization': 'OAuth 6628568379|c1e620fa708a1d5696fb991c1bde5662',
                'x-tigon-is-retry': 'False',
                'x-fb-friendly-name': 'FBPasswordEncryptionKeyFetchRequest:networkRequest',
                'x-fb-http-engine': 'Liger',
                'x-fb-client-ip': 'True',
                'x-fb-server-cluster': 'True'
            }
        };
        const response = await axios(config);
        return response.data;
    } catch (error) {
        logger.error(error);
        return false;
    }
}

function encrypt(password: string, pubkey: string, keyId: number): string {

    //Key and IV for AES encryption
    const randomKey = randomBytes(32);
    const randomIV = randomBytes(12);

    // Encrypt AES key with Facebook's RSA public key
    const publicKey = {
        key: pubkey,
        padding: constants.RSA_PKCS1_PADDING
    }
    const encrypted_rand_key = publicEncrypt(publicKey, randomKey);

    //Encrypt payload with AES-256
    const cipher_aes = createCipheriv('aes-256-gcm', randomKey, randomIV);
    const current_time = Math.round(Date.now() / 1000).toString();

    //Add the current time to the additional authenticated data (AAD) section
    cipher_aes.setAAD(Buffer.from(current_time, 'utf8'));
    const bufferPass = cipher_aes.update(password);
    const encrypted_passwd = Buffer.concat([bufferPass, cipher_aes.final()]);
    const auth_tag = cipher_aes.getAuthTag();
    const encode = Buffer.concat([
        //1 is presumably the version
        Buffer.from([1, keyId]),
        randomIV,
        //Length of the encrypted AES key as a little-endian 16-bit int
        pack('<h', encrypted_rand_key.length),
        encrypted_rand_key,
        auth_tag,
        encrypted_passwd,
    ]).toString('base64');
    return `#PWD_WILDE:2:${current_time}:${encode}`;
}

function truncateTo(str: string, digits: number) {
    if (str.length <= digits) {
        return str;
    }
    return str.slice(-digits);
}

export async function encryptPassword(req: Request, res: Response) {
    try {
        const pwdKeyFetch = await pwd_key_fetch();
        if (pwdKeyFetch) {
            const { public_key, key_id } = pwdKeyFetch;
            const pwd = encrypt(req.body.text, public_key, key_id);
            return res.send({
                status: 'success',
                data: pwd
            });
        }
        return res.send({
            status: 'error',
            data: null
        });
    } catch (e: any) {
        logger.error(e);
        return res.status(409).send(e.message);
    }
}
