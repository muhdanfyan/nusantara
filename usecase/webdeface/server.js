const http = require('http');
const fs = require('fs');

const server = http.createServer((req, res) => {
  fs.readFile('index.html', (err, data) => {
    if (err) {
      res.statusCode = 500;
      res.end(`Error getting the file: ${err}.`);
    } else {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'text/html');
      res.end(data);
    }
  });
});

const port = 3000;
// IP injected at runtime via environment variable or fallback to 0.0.0.0
const IP = process.env.SERVER_IP || '0.0.0.0';
server.listen(port, '0.0.0.0', () => {
  console.log(`Server running at http://${IP}:${port}/`);
});