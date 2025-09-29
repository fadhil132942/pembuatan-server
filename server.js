const express = require('express');
const app = express();
const port = 3000;

// Middleware untuk membaca JSON
app.use(express.json());

// Root route
app.get('/', (req, res) => {
  res.send(`Congratulations! Your Express server is running on port ${port}`);
});

// Dummy GET
app.get('/dummy-get', (req, res) => {
  res.json({ message: 'This is a dummy GET API' });
});

// Dummy POST
app.post('/dummy-post', (req, res) => {
  const body = req.body;
  console.log('Received body:', body);
  res.json({
    message: 'This is a dummy POST API',
    youSent: body
  });
});

// Dummy DELETE
app.delete('/dummy-delete/:id', (req, res) => {
  const { id } = req.params;
  res.json({ message: `Item with id ${id} has been deleted (dummy).` });
});

// Jalankan server
app.listen(port, () => {
  console.log(`Example app listening on port ${port}!`);
});
