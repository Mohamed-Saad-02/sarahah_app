import CryptoJS from "crypto-js";

interface EncryptionType {
  value: string;
  secretKey: string;
}

const DefaultValueEncryption = { value: "", secretKey: "" };

export const Encryption = ({
  value,
  secretKey,
}: EncryptionType = DefaultValueEncryption): string => {
  return CryptoJS.AES.encrypt(JSON.stringify(value), secretKey).toString();
};

interface DecryptionType {
  cipher: string;
  secretKey: string;
}

const DefaultValueDecryption = { cipher: "", secretKey: "" };
export const Decryption = ({
  cipher,
  secretKey,
}: DecryptionType = DefaultValueDecryption) => {
  return CryptoJS.AES.decrypt(cipher, secretKey)
    .toString(CryptoJS.enc.Utf8)
    .replace(/"/g, "");
};
