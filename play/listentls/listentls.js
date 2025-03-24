// openssl s_server -cert cert.pem -key key.pem -accept 587 -tls1_3
// openssl s_client -starttls smtp -connect smtp.gmail.com:587
import * as path from "jsr:@std/path"

const currentPath = import.meta.dirname;

export const server = Deno.listenTls({
   hostname: "localhost", // Listen on all network interfaces
   port: 587, // Change to your preferred TLS port
   cert:  Deno.readTextFileSync(path.join(currentPath, "./cert.pem")), // Your SSL certificate
   key:  Deno.readTextFileSync(path.join(currentPath, "./key.pem")),   // Your SSL private key
});

console.log(`TLS Server running on port 587...`);

for await (const conn of server) {
   handleClient(conn);
}

async function handleClient(conn) {
   const decoder = new TextDecoder();
   const encoder = new TextEncoder();

   try {
      //await conn.write(encoder.encode("Welcome to the TLS Server!\r\n"));

      for await (const data of conn.readable) {
         const message = decoder.decode(data);
         console.log("Received:", message);

         if (message.trim().toLowerCase() === "hello") {
            await conn.write(encoder.encode("Hello, client!\r\n"));
         } else {
            await conn.write(encoder.encode("You said: " + message));
         }
      }
   } catch (error) {
      console.error("Connection error:", error);
   } finally {
      conn.close();
   }
}