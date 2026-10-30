import axios from 'axios';

const client = axios.create({ baseURL: 'https://example.com/api' });

export async function getUser(id) {
  const { data } = await client.get(`/users/${id}`);
  return data;
}

export async function lazyPing() {
  const { default: http } = await import('axios');
  return http.head('https://example.com');
}
