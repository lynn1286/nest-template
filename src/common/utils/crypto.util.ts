import * as crypto from 'crypto';

/**
 * @description: 加盐
 * @param {string} input
 * @param {string} salt
 * @return {*}
 */
export default (input: string, salt: string) => {
  return crypto.pbkdf2Sync(input, salt, 1000, 64, 'sha256').toString('hex');
};
