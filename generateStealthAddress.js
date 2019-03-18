const { randomBytes } = require('crypto');
const secp256k1 = require('secp256k1');
const SxAddress = require('./stealthAddress');

// generates a private key from a secure/random source
const generatePrivateKey = () => {
  // generate privKey
  let privKey;
  do {
    privKey = randomBytes(32);
    // check if the seed is within the secp256k1 range
  } while (!secp256k1.privateKeyVerify(privKey));

  return privKey;
};

// generate a public key based on the current seeds
const generatePublicKey = privKey => {
  // get the public key in a compressed format
  return secp256k1.publicKeyCreate(privKey);
};

const scanPriv = generatePrivateKey();
const spendPriv = generatePrivateKey();
// pass all the data into the stealth address class
const address = new SxAddress(
  scanPriv,
  generatePublicKey(scanPriv),
  spendPriv,
  generatePublicKey(spendPriv)
);

console.log(address.toJson());