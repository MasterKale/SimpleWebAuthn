const path = require('path');
const express = require('express');

const app = express();
const port = 3000;

app.use(express.static('./public/'));

app.listen(port, () => {
  console.log(`🚀 Server ready at http://localhost:${port}`);
});
