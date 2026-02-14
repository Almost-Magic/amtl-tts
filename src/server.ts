import { createApp } from './app.js';

const PORT = process.env.PORT ?? 5015;

const app = createApp();

app.listen(PORT, () => {
  console.log(`Digital Sentinel listening on port ${PORT}`);
});
