import http from 'node:http';
import handler from './handler.mjs';
http.createServer(handler).listen(Number(process.env.PORT)||3001,'127.0.0.1',()=>console.log('Beveiligd dashboard: http://127.0.0.1:3001'));
