import { safeuint8array } from "../../src/dep.ts";

const decoder = new TextDecoder();
const encoder = new TextEncoder();

const SMTP_SERVER = "smtp.gmail.com"//"localhost";//"smtp-mail.outlook.com"; //"testtls.com";//
const SMTP_PORT = 587;  //443;// For TLS

const conn = await Deno.connect({ hostname: SMTP_SERVER, port: SMTP_PORT, tcp: 'tcp' });
performance.mark("start")
const response = await sendCommand(conn, `EHLO mail.example.com\r\n`, 600, 250);
performance.mark("end")
console.log(response)
const time = performance.measure("total send and response", "start", "end")
console.log(`time : ${time.duration}`)
//const response = await send_response(conn, `EHLO smtp.gmail.com\r\n`);
//const response2 = await send_response(conn, `EHLO smtp.gmail.com\r\n`);
/* const response = await send_response_0(conn, `EHLO smtp.gmail.com\r\n`);
const response2 = await send_response_0(conn, `EHLO smtp.gmail.com\r\n`); */
conn.close()
debugger;




async function send_response(conn, command) {
   await sendCommand(conn, command)
   const reader = conn.readable.getReader();// FIXME

   const { value, done } = await reader.read();
   const response = decoder.decode(value, { stream: true });
   reader.releaseLock();
   return response;
}

async function send_response_0(conn, command) {
   await sendCommand(conn, command)
   const buffer = new Uint8Array(8192)
   const bytesRead = await conn.read(buffer);
   const response = decoder.decode(buffer, { stream: true });
   return response;
}

// Function to send a command to the server
async function sendCommand(conn, command, buffer, timeout) {
   await conn.write(encoder.encode(command));
   const byte = await readStream(conn, buffer, timeout);
   return decoder.decode(byte)
}

async function readByte(reader, bufferSize, timeout) {
   const buffer = new Uint8Array(bufferSize);
   let result = [];
   while (true) {
      try {
         // Set a timeout to prevent infinite waiting
         const { done, value } = await Promise.race([
            reader.read(buffer),
            new Promise((_resolve, reject) =>
               setTimeout(() => reject(new Error("Read timeout")), timeout)
            ),
         ]);
         if (value) result.push(value);
         if (done) break;
      } 
      catch(error){
         break;
      }
   }
   return safeuint8array(...result);
}
async function readStream_0(conn, bufferSize = 8192, timeout = 1000) {
   const reader = conn.readable.getReader(/* { mode: "byob" } */);
   const buffer = new Uint8Array(bufferSize);
   let result = [];
   while (true) {
      try {
         // Set a timeout to prevent infinite waiting
         const { done, value } = await Promise.race([
            reader.read(buffer),
            new Promise((_resolve, reject) =>
               setTimeout(() => reject(new Error("Read timeout")), timeout)
            ),
         ]);
         if (value) result.push(value);
         if (done) break;
      } 
      catch(error){
         break;
      }
   }
   return safeuint8array(...result);
}

async function readStream(conn, bufferSize = 8192, timeout = 1000) {
   const reader = conn.readable.getReader(/* { mode: "byob" } */);
   let bytesReceived = 0;
   let result = [];

   while (true) {
      //performance.mark('start')
      // Reset buffer (BYOB expects reusing the same buffer)
      const buffer = new Uint8Array(bufferSize);
      try {
         // Set a timeout to prevent infinite waiting
         const { done, value } = await Promise.race([
            reader.read(buffer),
            new Promise((_, reject) =>
               setTimeout(() => reject(new Error("Read timeout")), timeout)
            ),
         ]);

         if (done) {
            console.log(`readStream() complete. Total bytes: ${bytesReceived}`);
            break;
         }

         if (value) {
            //bytesReceived += value.byteLength;
            console.log(`Read ${value.byteLength} bytes (${bytesReceived} total):`, value);
            result.push(value)//(value.slice(0, value.byteLength)); // Copy valid portion
            performance.mark('end');
            const timelapse = performance.measure('start', 'end');
            console.log(timelapse.duration)
            //return value
         }
      } catch (err) {
         console.error("Read error:", err.message);
         //performance.mark('end');
         //const timelapse = performance.measure('start', 'end');
         //console.log(timelapse.duration)
         break; // Exit the loop on timeout or error
      }
   }

   return safeuint8array(...result);
}