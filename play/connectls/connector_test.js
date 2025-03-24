import { connect } from "./connector.js";

const SMTP_SERVER = "smtp.gmail.com"//"localhost";//"smtp-mail.outlook.com"; //"testtls.com";//
const SMTP_PORT = 587;  //443;// For TLS

const Smtp_servers = [
   "smtp.gmail.com",
   `smtp-mail.outlook.com`,
   `smtp.mail.yahoo.com`,
   `smtp.mail.me.com`,
   `smtp.aol.com`,
   `smtp.zoho.com`,
   `smtp.yandex.com`,
   `mail.gmx.com`,
   `smtp.mail.com`,
   `smtp.fastmail.com`
]

let dConn, response

for (const smtp of Smtp_servers) {
   dConn = await connect({ port: SMTP_PORT, hostname: smtp });
   response = await dConn.readDecode();
   console.log("Smtp Greeting: \r\n" + response);
   response = await dConn.sendCommand(`EHLO mail.example.com\r\n`);
   console.log("EHLO mail.example.com\r\n" + response);
}

dConn.close();