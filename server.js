const http = require("http");
const path = require("path");
const { readFileSync, read } = require("fs");
const WS_MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const crypto = require("crypto");
const { error } = require("console");
const { throws } = require("assert");
const { StringDecoder } = require("string_decoder");
const { stringify } = require("querystring");
const port = 9000;

const FIRST_BIT = 128
const SEVEN_BITS_INT = 125; 
const SIXTEEN_BITS_INT = 126; 
const SIXTY_BITS_INT = 127;
const MASK_KEYS_BYTES_LENGTH = 4; 
const OPCODE_TEXT = 0x01 //1 bit in binary 1 
const MAXIMUM_SIXTEENBITS_INTEGER = 2 ** 16 //[0,65536]
const arrayMsg = []


const server = http
  .createServer((req, res) => {
    if (req.url === "/") {
      const html = readFileSync(path.resolve(__dirname, "index.html"), "utf8");
      res.statusCode = 200;
      res.write(html);
    }
    res.end();
  })
  .listen(port, () => {
    console.log(`server is running on ${port}`);
  });

//error handling to keep the server on

["uncaughtException", "unhandledRejection"].forEach((event) => {
  process.on(event, (err) => {
    console.error(
      `something bad happened! event: ${event}, msg: ${err.stack || err}`
    );
  });
});

//upgrade protocol to websocket
server.on("upgrade", onSocketUpgrade);

function onSocketUpgrade(req, socket, head) {
  const {"sec-websocket-key": websocketClientKey} = req.headers 
  const headers = prepareHandShakeHeaders(websocketClientKey)
  socket.write(headers)
  socket.on('readable',()=>onSoketReable(socket))

  console.log(socket)
}

function sendMessage(message,socket) { 
  const dataFrameBuffer = prepareMessage(message)
  socket.write(dataFrameBuffer)
}
function prepareMessage(message) { 
  const msg = Buffer.from(message)
  const messageLength = msg.length

  let dataFrameBuffer; 


  //0x80 === 128 in binary 
  //0x + Math.abs(128).toString(16) === 128 (10000000)
  //OPCODE_TEXT: 00000001
  const firstByte = 0x80 | OPCODE_TEXT //single frame + text 
  //if messageLength less than 7 bits that is the size of the message lenght
  console.log(messageLength)
  if (messageLength <= SEVEN_BITS_INT) { 
    const bytes = [firstByte] 
    dataFrameBuffer = Buffer.from(bytes.concat(messageLength))
  }
  else if (messageLength <= MAXIMUM_SIXTEENBITS_INTEGER) { 
    let offsetFourBytes = 4; 
     const target = Buffer.allocUnsafe(offsetFourBytes)
     target[0] = firstByte 
     target[1] = SIXTEEN_BITS_INT | 0x0 //just to know the mask
     target.writeUint16BE(messageLength,2) //the next two bytes is the size of content 
     dataFrameBuffer = target
  }
  else { 
    throw new Error("message is too long"); 
  }
  const totalLenght = dataFrameBuffer.byteLength + messageLength; 
  const dataResponse = concat([dataFrameBuffer,msg],totalLenght)
  return dataResponse
}
function concat(bufferList,totalLength) { 
  let target = Buffer.allocUnsafe(totalLength)
  let offset = 0;
  for (const buffer of bufferList) { 
    target.set(buffer,offset) 
    offset += buffer.length
  } 
  return target
}

function onSoketReable(socket){ 
  //read the first byte - FIN,REVERSE CODES ,OPCODE ...
  socket.read(1)
 
  //read the second byte - payload length
  const [markerAndPayloadLength] = socket.read(1) 
  //first bit is always 1 from client-to-server
  //substract 128 or '10000000'
  const  lengthIndicatorInBits = markerAndPayloadLength - FIRST_BIT 
  // console.log(`${lengthIndicatorInBits} = ${markerAndPayloadLength} - ${FIRST_BIT}`) 
  let messageLength = 0 


  if (lengthIndicatorInBits <= SEVEN_BITS_INT) { 
    messageLength = lengthIndicatorInBits 
  }
  //read the next two bytes to get actual length
  else if (lengthIndicatorInBits == SIXTEEN_BITS_INT) { 
    //unsigned, big-endian 16 bit integer [0-65k] - 2 ** 16
    messageLength = socket.read(2).readUint16BE(0)
  }
  else {
    throw new Error("your message is too long!")
  }
  
  const maskKey = socket.read(MASK_KEYS_BYTES_LENGTH)
  const encoded = socket.read(messageLength)
  const received = unmask(encoded,maskKey)
  
  const dataReceived = JSON.stringify(received)
  arrayMsg.push(dataReceived)
    // console.log(String.fromCharCode(...decoded))
  sendMessage(JSON.stringify(arrayMsg),socket)
}

function unmask(encodedBuffer,maskKey)
{ 
  //masking key has only 4 bytes
  //encode: each byte in payload will be XOR with corresponding byte in masking key (return first index when payload higher)
  //=>Decode: each byte in payload decoded will be XOR with masking key to get first content 

  const toBinary = (t)=> t.toString(2).padStart(8,"0")

  let decoded = Uint8Array.from(encodedBuffer, (elt, i) =>{ 
    const decode = elt ^ maskKey[i % MASK_KEYS_BYTES_LENGTH]
    // const logger = {
    //   unmaskingCalc : `${toBinary(elt)} ^ ${toBinary(maskKey[i%MASK_KEYS_BYTES_LENGTH])} = ${toBinary(decode)}` , 
    //   charFromBinary:  `buffer: ${decode} to Binary: ${toBinary(decode)} to charater: ${(String.fromCharCode(parseInt(toBinary(decode),2)))} and String.fromCharCode: ${String.fromCharCode(decode)}`
    // }
    // console.log(logger)
     return decode
  }); // Perform an XOR on the mask

  

  return new TextDecoder().decode(decoded)
}

function prepareHandShakeHeaders($id) {
  const headers = [
    "HTTP/1.1 101 Switching Protocols",
    "Upgrade: websocket",
    "Connection: Upgrade",
    `Sec-WebSocket-Accept: ${createSocketAccept($id)}`,
    ""
  ].map(item => 
      item.concat('\r\n')
    ).join('')
   return headers
}
/* 
 To get it, 
 1. concatenate the client's Sec-WebSocket-Key and the string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" together (it's a "magic string"), 
 2. take the SHA-1 hash of the result, 
 3. and return the base64 encoding of that hash.
*/
function createSocketAccept($id) {
  const sha1 = crypto.createHash("sha1");
  sha1.update($id + WS_MAGIC_STRING);
  return sha1.digest("base64");
}
