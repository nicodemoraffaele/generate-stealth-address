const stealth_version_byte = 0x32;
const crypto = require('crypto');
const bs58 = require('bs58');

module.exports = class StealthAddress {
  constructor(scanPriv, scanPub, spendPriv, spendPub) {
    this.scanPub = scanPub;
    this.spendPub = spendPub;
    this.scanPriv = scanPriv;
    this.spendPriv = spendPriv;
    this.options = 0;
  }

  encode() {
    const address = new Buffer.from([
      stealth_version_byte,
      this.options,
      ...this.scanPub,
      1, // size of public keys
      ...this.spendPub,
      0, // size of signatures
      0, // ??
    ]);

    const result = Buffer.concat([address, this.generateChecksum(address)]);
    return bs58.encode(result);
  }

  generateChecksum(data) {
    return crypto
      .createHash('sha256')
      .update(
        crypto
          .createHash('sha256')
          .update(data)
          .digest()
      )
      .digest()
      .slice(0, 4);
  }

  validateChecksum(modules) {
    const buffered = new Buffer.from(modules);
    const checksumModule = buffered.slice(
      buffered.byteLength - 4,
      buffered.byteLength
    );

    const informationModules = buffered.slice(0, buffered.byteLength - 4);
    const informationChecksum = this.generateChecksum(informationModules);
    return {
      valid: Buffer.compare(informationChecksum, checksumModule) === 0,
      checksum: informationChecksum.toString('hex'),
    };
  }

  isStealth(bs58address) {
    const modules = bs58.decode(bs58address);
    let checks = this.validateChecksum(modules);
    if (!checks.valid) {
      return {
        valid: false,
      };
    }

    if (modules.length < 1 + 1 + 33 + 1 + 33 + 1 + 1 + 4) {
      return {
        valid: false,
      };
    }

    checks = { ...checks, length: modules.length };

    if (modules[0] !== stealth_version_byte) {
      return {
        valid: false,
      };
    }

    checks = {
      ...checks,
      stealthVersion: `0x${modules[0].toString('16')}`,
    };

    return checks;
  }

  toJsonPrivate() {
    return JSON.stringify(
      {
        scanPub: this.scanPub.toString('hex'),
        spendPub: this.spendPub.toString('hex'),
        scanPriv: this.scanPriv.toString('hex'),
        spendPriv: this.spendPriv.toString('hex'),
        options: this.options,
        address: this.encode(),
        isStealth: this.isStealth(this.encode()),
      },
      null,
      2
    );
  }

  toJson() {
    return JSON.stringify(
      {
        scanPub: this.scanPub.toString('hex'),
        spendPub: this.spendPub.toString('hex'),
        scanPriv: 'hidden',
        spendPriv: 'hidden',
        options: this.options,
        address: this.encode(),
        isStealth: this.isStealth(this.encode()),
      },
      null,
      2
    );
  }
};