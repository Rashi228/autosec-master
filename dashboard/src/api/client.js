import axios from 'axios';

const BASE_URL = 'http://127.0.0.1:7860';

const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 5000,
});

export const getSystemState = async () => {
  const response = await apiClient.get('/v1/state');
  return response.data;
};

export const resetEnvironment = async (taskId, mode = 'war_room') => {
  const response = await apiClient.post('/v1/reset', { task_id: taskId, mode });
  return response.data;
};

export const stepEnvironment = async (action) => {
  const response = await apiClient.post('/v1/step', { action });
  return response.data;
};

export default apiClient;
