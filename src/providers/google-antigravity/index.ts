import { ProviderConfigs } from '../types';
import GoogleAntigravityApiConfig from './api';
import {
  GoogleAntigravityChatCompleteConfig,
  GoogleAntigravityChatCompleteResponseTransform,
  GoogleAntigravityChatCompleteStreamChunkTransform,
} from './chatComplete';

/**
 * Antigravity — Gemini models served through Google's Code Assist backend.
 *
 * Chat completions only. The backend exposes no embeddings method, and
 * declaring one that 404s upstream would be worse than not offering it.
 */
const GoogleAntigravityConfig: ProviderConfigs = {
  api: GoogleAntigravityApiConfig,
  chatComplete: GoogleAntigravityChatCompleteConfig,
  responseTransforms: {
    chatComplete: GoogleAntigravityChatCompleteResponseTransform,
    'stream-chatComplete': GoogleAntigravityChatCompleteStreamChunkTransform,
  },
};

export default GoogleAntigravityConfig;
