// EXPECT-NONE
// FIXTURE: public by design. Juice Shop's Web3 pages hold contract and wallet
// ADDRESSES - published on a blockchain, the opposite of a secret - and a map
// of Solidity compiler FILE NAMES. Twenty were reported as credentials.
export const BeeTokenAddress = '0x36435796Ca9be2bf150CE0dECc2D8Fab5C4d6E13';
export const nftAddress = '0x41427790c94E7a592B17ad694eD9c06A02bb9C39';
export const payments = [{ name: 'Bitcoin', address: '1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' }];
export const compilers: Record<string, string> = {
  '0.8.21': 'soljson-v0.8.21+commit.d9974bed.js',
  '0.8.9': 'soljson-v0.8.9+commit.e5eed63a.js',
};
export const hmacKey = process.env.HMAC_KEY;
