const fs = require('fs');

// Minimal 32x32 PNG (1-pixel blue square encoded in base64)
const png32 = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAARElEQVRYR+3OsQ0AIAwEwe/9l4YJQCLdHdiJSCQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD4ewALuAABCdB+5wAAAABJRU5ErkJggg==', 'base64');
const png128 = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAASklEQVR42u3BAQ0AAADCoPdPbQ43oAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8G8HQAACDQP/eQAAAABJRU5ErkJggg==', 'base64');
const png256 = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAYAAABccqhmAAAALklEQVR42u3BAQ0AAADCoPdPbQ43oAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8G8HQAACDQP/eQAAAABJRU5ErkJggg==', 'base64');

// Minimal ICO file (just header + one 32x32 PNG entry)
const icoHeader = Buffer.alloc(6);
icoHeader.writeUInt16LE(0, 0);  // Reserved
icoHeader.writeUInt16LE(1, 2);  // Type (1 = ICO)
icoHeader.writeUInt16LE(1, 4);  // Number of images

const icoEntry = Buffer.alloc(16);
icoEntry.writeUInt8(32, 0);     // Width
icoEntry.writeUInt8(32, 1);     // Height
icoEntry.writeUInt8(0, 2);       // Color palette
icoEntry.writeUInt8(0, 3);       // Reserved
icoEntry.writeUInt16LE(1, 4);    // Color planes
icoEntry.writeUInt16LE(32, 6);   // Bits per pixel
icoEntry.writeUInt32LE(png32.length, 8);  // Size of image data
icoEntry.writeUInt32LE(22, 12);  // Offset to image data (6 + 16)

const ico = Buffer.concat([icoHeader, icoEntry, png32]);

fs.writeFileSync('icons/32x32.png', png32);
fs.writeFileSync('icons/128x128.png', png128);
fs.writeFileSync('icons/128x128@2x.png', png256);
fs.writeFileSync('icons/icon.ico', ico);
fs.writeFileSync('icons/icon.icns', png256);

console.log('Icons generated');
