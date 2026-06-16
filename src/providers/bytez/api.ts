import { ProviderAPIConfig } from '../types';
import { version } from '../../../package.json';

const BytezInferenceAPI: ProviderAPIConfig = {
  getBaseURL: () => 'https://api.bytez.com',
  headers: async ({ providerOptions }) => {
    const { apiKey } = providerOptions;

    const headers: Record<string, string> = {};

    headers['Authorization'] = `Key ${apiKey}`;
    headers['user-agent'] = `portkey/${version}`;

    return headers;
  },
  getEndpoint: ({ gatewayRequestBodyJSON }) => {
    const { model } = gatewayRequestBodyJSON;
    const bytezVersion = (gatewayRequestBodyJSON as { version?: number }).version ?? 2;
    return `/models/v${bytezVersion}/${model}`;
  },
};

export default BytezInferenceAPI;
