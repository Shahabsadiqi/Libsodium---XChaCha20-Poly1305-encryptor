// cli.js
const readline = require('readline');
const path = require('path');
const FileEncryptor = require('./encryptor.js');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const encryptor = new FileEncryptor();

function ask(question) {
  return new Promise(resolve => rl.question(question, resolve));
}

async function run() {
  console.log("Simple File Encryption Tool (XChaCha20-Poly1305)\n");

  const mode = await ask("Encrypt or Decrypt? (e/d): ");
  const filePath = await ask("File path: ");
  const password = await ask("Password: ");
  const absPath = path.resolve(filePath);
  const outputExt = mode === 'e' ? '.encrypted' : '.decrypted';
  const outputPath = absPath + outputExt;

  encryptor.on('progress', (p) => {
    process.stdout.clearLine(0);
    process.stdout.cursorTo(0);
    process.stdout.write(`Progress: ${p}%`);
  });

  try {
    if (mode === 'e') {
      await encryptor.encrypt(absPath, outputPath, password);
      console.log("\nEncrypted →", outputPath);
    } else {
      await encryptor.decrypt(absPath, outputPath, password);
      console.log("\nDecrypted →", outputPath);
    }
  } catch (err) {
    console.error("\nError:", err.message);
  } finally {
    rl.close();
  }
}

run();
