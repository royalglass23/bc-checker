import http from 'node:http';
import { requestListener } from './src/server.mjs';

const port = Number(process.env.PORT || 3000);
http.createServer(requestListener).listen(port, () => {
  console.log(`BC Checker listening on ${port}`);
});
